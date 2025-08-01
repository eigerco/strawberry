package main

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safrole"
	chainState "github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/logger"
	"github.com/eigerco/strawberry/pkg/network/node"
)

type FullValidatorInfo struct {
	Index      uint   `json:"index"`
	IP         string `json:"address"`
	Port       int    `json:"port"`
	Ed25519Pub string `json:"ed25519_public_key"`
	Ed25519Prv string `json:"ed25519_private_key"`
}

func (f FullValidatorInfo) ToJson() ([]byte, error) {
	pub, prv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	prvStr := hex.EncodeToString(prv)
	pubStr := hex.EncodeToString(pub)
	f.Ed25519Prv = prvStr
	f.Ed25519Pub = pubStr
	return json.MarshalIndent(f, "", "	")
}

func loadFullValidatorInfos(filename string) ([]FullValidatorInfo, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	var validators []FullValidatorInfo
	if err := json.NewDecoder(f).Decode(&validators); err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON: %w", err)
	}

	return validators, nil
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

func (f FullValidatorInfo) ToMetadata() ([]byte, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(f.IP, strconv.Itoa(f.Port)))
	if err != nil {
		return nil, err
	}
	addrBytes, err := encodeToBytes(addr)
	if err != nil {
		return nil, err
	}

	// Create a 128-byte array filled with zeros
	result := make([]byte, 128)
	// Copy the address bytes into the start of the array
	copy(result, addrBytes)

	return result, nil
}

// main starts a blockchain node.
// go run main.go -index 0
func main() {
	ctx := context.Background()
	index := flag.String("index", "", "Validator Configuration Index")
	flag.Parse()

	log := logger.NewConsoleLogger(logger.Options{Debug: true})
	if *index == "" {
		log.Fatal().Str("missing commandline flag", "-index").Msg("validator configuration index is required")
	}

	vs, err := loadFullValidatorInfos("test_validators.json")
	if err != nil {
		log.Fatal().Err(err).Msgf("loading validator configuration failed")
	}

	i, err := strconv.Atoi(*index)
	if err != nil {
		log.Fatal().Err(err).Msgf("index parameter conversion failed")
	}

	if i < 0 || i >= len(vs) {
		log.Fatal().Int("index", i).Msgf("validator configuration index out of bounds")
	}
	address := vs[i].IP
	port := vs[i].Port
	udpAddress, err := net.ResolveUDPAddr("udp", net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		log.Fatal().Str("address", address).Int("port", port).Err(err).Msgf("address resolve failed")
	}

	log.Info().Msgf("listening on: %v", address)
	prv, err := hex.DecodeString(vs[i].Ed25519Prv)
	if err != nil {
		log.Fatal().Err(err).Msg("own private key decode failed")
	}
	pub, err := hex.DecodeString(vs[i].Ed25519Pub)
	if err != nil {
		log.Fatal().Err(err).Msg("own public key decode failed")
	}

	privateKey := ed25519.PrivateKey(prv)
	publicKey := ed25519.PublicKey(pub)
	vkeys := validator.ValidatorKeys{
		EdPrv: privateKey,
		EdPub: publicKey,
	}
	validatorsData := safrole.ValidatorsData{}

	for i, k := range vs {
		pub, err := hex.DecodeString(k.Ed25519Pub)
		if err != nil {
			log.Fatal().Int("index", i).Err(err).Msg("validator public key decode failed")
		}

		meta, err := k.ToMetadata()
		if err != nil {
			log.Fatal().Int("index", i).Err(err).Msg("validator metadata decode failed")
		}

		vk := crypto.ValidatorKey{
			Ed25519:  ed25519.PublicKey(pub),
			Metadata: crypto.MetadataKey(meta),
		}
		validatorsData[i] = vk
	}

	vstate := validator.ValidatorState{
		CurrentValidators:  validatorsData,
		ArchivedValidators: validatorsData,
		QueuedValidators:   validatorsData,
	}

	state := chainState.State{
		ValidatorState: vstate,
	}

	node, err := node.NewNode(ctx, udpAddress, vkeys, state, uint16(i))
	if err != nil {
		log.Fatal().Err(err).Msg("node creation failed")
	}
	err = node.Start()
	if err != nil {
		log.Fatal().Err(err).Msg("node start failed")
	}
	select {}
}
