package main

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/network/peer"
	"log"
	"net"
	"os"
	"strconv"
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
		panic(err)
	}
	prvStr := hex.EncodeToString(prv)
	pubStr := hex.EncodeToString(pub)
	f.Ed25519Prv = prvStr
	f.Ed25519Pub = pubStr
	jsonData, err := json.MarshalIndent(f, "", "	")
	if err != nil {
		return nil, err
	}

	return jsonData, nil
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
	index := flag.String("index", "", "Validator Index")
	flag.Parse()

	if *index == "" {
		log.Fatal("listen address is required")
	}
	vs, err := loadFullValidatorInfos("test_validators.json")
	if err != nil {
		panic(err)
	}
	i, err := strconv.Atoi(*index)
	if err != nil {
		panic(err)
	}
	address := vs[i].IP
	port := vs[i].Port
	udpAddress, err := net.ResolveUDPAddr("udp", net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		panic(err)
	}
	fmt.Printf("listening on: %v\n", address)
	prv, err := hex.DecodeString(vs[i].Ed25519Prv)
	if err != nil {
		panic(err)
	}
	pub, err := hex.DecodeString(vs[i].Ed25519Pub)
	if err != nil {
		panic(err)
	}
	privateKey := ed25519.PrivateKey(prv)
	publicKey := ed25519.PublicKey(pub)
	vk := validator.ValidatorKeys{
		EdPrv: privateKey,
		EdPub: publicKey,
	}
	validatorsData := safrole.ValidatorsData{}
	for i, k := range vs {
		pub, err := hex.DecodeString(k.Ed25519Pub)
		if err != nil {
			panic(err)
		}
		meta, err := k.ToMetadata()
		if err != nil {
			panic(err)
		}
		vk := crypto.ValidatorKey{
			Ed25519:  ed25519.PublicKey(pub),
			Metadata: crypto.MetadataKey(meta),
		}
		validatorsData[i] = &vk
	}

	vstate := validator.ValidatorState{
		CurrentValidators:  validatorsData,
		ArchivedValidators: validatorsData,
		QueuedValidators:   validatorsData,
	}

	node, err := peer.NewNode(ctx, udpAddress, vk, vstate, uint16(i))
	if err != nil {
		panic(err)
	}
	err = node.Start()
	if err != nil {
		panic(err)
	}
	select {}
}
