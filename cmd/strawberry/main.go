package main

import (
	"context"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safrole"
	chainState "github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/log"
	"github.com/eigerco/strawberry/pkg/network/node"
)

type FullValidatorInfo struct {
	Index      uint   `json:"index"`
	IP         string `json:"address"`
	Port       int    `json:"port"`
	Ed25519Pub string `json:"ed25519_public_key"`
	Ed25519Prv string `json:"ed25519_private_key"`
}

type AppConfig struct {
	LogLevel       string `json:"loglevel"`
	ValidatorIndex int    `json:"validatorIndex"`
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

func loadConfig(filename string) (*AppConfig, error) {
	appConfig := AppConfig{}

	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("config file open failed: %v", err)
	}

	if err := json.NewDecoder(f).Decode(&appConfig); err != nil {
		return nil, fmt.Errorf("umarshalling application config failed: %v", err)
	}

	return &appConfig, nil
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

	appConfig, err := loadConfig("appconfig.json")
	if err != nil {
		panic("application config load failed:" + err.Error())
	}

	loglevel, err := log.ParseLogLevel(appConfig.LogLevel)
	if err != nil {
		panic("log level parsing failed: " + err.Error())
	}

	opts := log.Options{LogLevel: loglevel}
	log.Init(opts)

	maxuint16 := int(^uint16(0))
	if appConfig.ValidatorIndex < 0 && appConfig.ValidatorIndex > maxuint16 {
		log.Internal.Fatal().
			Msgf("validator index %d out of bounds 0-%d", appConfig.ValidatorIndex, maxuint16)
	}

	index := uint16(appConfig.ValidatorIndex)

	vs, err := loadFullValidatorInfos("test_validators.json")
	if err != nil {
		log.Internal.Fatal().
			Err(err).
			Msg("loading validator configuration failed")
	}

	if int(index) >= len(vs) {
		log.Internal.Fatal().
			Uint16("index", index).
			Msg("validator configuration index out of bounds")
	}
	address := vs[index].IP
	port := vs[index].Port
	udpAddress, err := net.ResolveUDPAddr("udp", net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		log.Internal.Fatal().
			Str("address", address).
			Int("port", port).
			Err(err).
			Msg("address resolve failed")
	}

	log.Internal.Info().
		Msgf("listening on: %v", address)

	prv, err := hex.DecodeString(vs[index].Ed25519Prv)
	if err != nil {
		log.Internal.Fatal().
			Err(err).
			Msg("own private key decode failed")
	}
	pub, err := hex.DecodeString(vs[index].Ed25519Pub)
	if err != nil {
		log.Internal.Fatal().
			Err(err).
			Msg("own public key decode failed")
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
			log.Internal.Fatal().
				Int("index", i).
				Err(err).
				Msg("validator public key decode failed")
		}

		meta, err := k.ToMetadata()
		if err != nil {
			log.Internal.Fatal().
				Int("index", i).
				Err(err).
				Msg("validator metadata decode failed")
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

	node, err := node.NewNode(ctx, udpAddress, vkeys, state, index)
	if err != nil {
		log.Internal.Fatal().
			Err(err).
			Msg("node creation failed")
	}
	err = node.Start()
	if err != nil {
		log.Internal.Fatal().
			Err(err).
			Msg("node start failed")
	}
	select {}
}
