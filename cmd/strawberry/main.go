package main

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/network/peer"
)

type Validator struct {
	Index   uint
	PubKeys crypto.ValidatorKey
}

func createValidatorData(info []FullValidatorInfo) (safrole.ValidatorsData, error) {
	if len(info) < common.NumberOfValidators {
		return safrole.ValidatorsData{}, fmt.Errorf("invalid number of validators: %d", len(info))
	}
	validators := make([]Validator, common.NumberOfValidators)
	for i := uint(0); i < common.NumberOfValidators; i++ {
		addr, err := info[i].getUDPAddr()
		if err != nil {
			return safrole.ValidatorsData{}, fmt.Errorf("error getting UDP address: %w", err)
		}
		encoded, err := encodeToBytes(addr)
		if err != nil {
			return safrole.ValidatorsData{}, fmt.Errorf("error encoding UDP address: %w", err)
		}
		validators[i] = Validator{
			Index: i,
			PubKeys: crypto.ValidatorKey{
				Bandersnatch: crypto.BandersnatchPublicKey(info[i].BandersnatchPublicKey),
				Ed25519:      info[i].Ed25519PublicKey,
				Bls:          crypto.BlsKey(info[i].BlsKey),
				Metadata:     sliceToMetadataKey(encoded),
			},
		}
	}
	var data safrole.ValidatorsData
	for i, v := range validators {
		data[i] = &v.PubKeys
	}
	return data, nil
}

func sliceToMetadataKey(bytes []byte) crypto.MetadataKey {
	arr := [crypto.MetadataSize]byte{}
	copy(arr[:], bytes)
	return crypto.MetadataKey(arr)
}

func convertToValidatorKeys(fullInfo []FullValidatorInfo) ([]validator.ValidatorKeys, error) {
	validators := make([]validator.ValidatorKeys, len(fullInfo))
	for i, info := range fullInfo {
		validatorKeys, err := info.ToValidatorKeys()
		if err != nil {
			return nil, fmt.Errorf("error converting validator %d: %w", i, err)
		}
		validators[i] = validatorKeys
	}
	return validators, nil
}
func (f *FullValidatorInfo) getUDPAddr() (*net.UDPAddr, error) {
	// Remove square brackets if present for IPv6
	address := f.Address

	ip := net.ParseIP(address)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", f.Address)
	}

	return &net.UDPAddr{
		IP:   ip,
		Port: f.Port,
	}, nil
}
func toUDPAddrFromParts(address string, port int) (*net.UDPAddr, error) {
	// Parse IP address
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", address)
	}

	return &net.UDPAddr{
		IP:   ip,
		Port: port,
	}, nil
}

func encodeToBytes(addr *net.UDPAddr) ([]byte, error) {
	if len(addr.IP) != net.IPv6len {
		return nil, fmt.Errorf("not an IPv6 address")
	}

	result := make([]byte, 18)
	copy(result[:16], addr.IP)
	binary.LittleEndian.PutUint16(result[16:], uint16(addr.Port))
	return result, nil
}

type FullValidatorInfo struct {
	Index                  uint   `json:"index"`
	Address                string `json:"address"` // IPv6 address without brackets
	Port                   int    `json:"port"`
	Ed25519PublicKey       []byte `json:"ed25519_public_key"`
	Ed25519PrivateKey      []byte `json:"ed25519_private_key"`
	BandersnatchPublicKey  []byte `json:"bandersnatch_public_key"`
	BandersnatchPrivateKey []byte `json:"bandersnatch_private_key"`
	BlsKey                 []byte `json:"bls_key"`
}

func (f *FullValidatorInfo) ToValidatorKeys() (validator.ValidatorKeys, error) {
	if len(f.Ed25519PrivateKey) != ed25519.PrivateKeySize {
		return validator.ValidatorKeys{}, fmt.Errorf("invalid Ed25519 private key size")
	}
	if len(f.Ed25519PublicKey) != ed25519.PublicKeySize {
		return validator.ValidatorKeys{}, fmt.Errorf("invalid Ed25519 public key size")
	}

	var banderPrv crypto.BandersnatchPrivateKey
	var banderPub crypto.BandersnatchPublicKey
	var blsKey crypto.BlsKey

	copy(banderPrv[:], f.BandersnatchPrivateKey)
	copy(banderPub[:], f.BandersnatchPublicKey)
	copy(blsKey[:], f.BlsKey)

	return validator.ValidatorKeys{
		EdPrv:     ed25519.PrivateKey(f.Ed25519PrivateKey),
		EdPub:     ed25519.PublicKey(f.Ed25519PublicKey),
		BanderPrv: banderPrv,
		BanderPub: banderPub,
		Bls:       blsKey,
	}, nil
}

func loadFullValidatorInfos(filename string) ([]FullValidatorInfo, error) {
	jsonData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	var validators []FullValidatorInfo
	if err := json.Unmarshal(jsonData, &validators); err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON: %w", err)
	}

	return validators, nil
}

func main() {
	ctx := context.Background()
	index := flag.String("index", "", "Validator Index")
	flag.Parse()
	validatorIndex, err := strconv.Atoi(*index)
	if err != nil {
		log.Fatalf("Invalid validator index: %v", err)
	}
	fullInfos, err := loadFullValidatorInfos("full_info.json")
	if err != nil {
		log.Fatalf("Failed to load validator info: %v", err)
	}

	keys, err := convertToValidatorKeys(fullInfos)
	if err != nil {
		log.Fatalf("Failed to convert validator keys: %v", err)
	}

	// This will try to create common.NumberOfValidators number of validators
	// It will error if the number of validators in fullInfos is less than common.NumberOfValidators
	validatorsData, err := createValidatorData(fullInfos)
	if err != nil {
		log.Fatalf("Failed to create validator data: %v", err)
	}
	state := validator.ValidatorState{
		CurrentValidators:  validatorsData,
		ArchivedValidators: validatorsData,
		QueuedValidators:   validatorsData,
	}
	epochKeys, err := safrole.SelectFallbackKeys(crypto.Hash{}, validatorsData)
	if err != nil {
		log.Fatalf("Failed to select fallback keys: %v", err)
	}
	// Create the node
	listenAddr, err := toUDPAddrFromParts(fullInfos[validatorIndex].Address, fullInfos[validatorIndex].Port)

	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	node, err := peer.NewNode(ctx, listenAddr.AddrPort().String(), keys[validatorIndex], state, uint16(validatorIndex))
	if err != nil {
		log.Fatalf("Failed to create node: %v", err)
	}
	node.ValidatorManager.GridMapper = validator.NewGridMapper(state)
	// Start the node
	if err := node.Start(); err != nil {
		log.Fatalf("Failed to start node: %v", err)
	}
	// connectDemo(node, validatorsData)
	if err := node.ConnectToNeighbours(); err != nil {
		log.Fatalf("Failed to connect to neighbours: %v", err)
	}

	go node.RunBlockProduction(epochKeys)

	// Block forever
	select {}
}
