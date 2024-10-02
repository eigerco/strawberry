package state

import (
	"encoding/binary"
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestGenerateStateKey verifies that the state key generation works as expected.
func TestGenerateStateKey(t *testing.T) {
	// Test with i and serviceId
	i := uint8(1)
	serviceId := block.ServiceId(100)

	// Generate the state key
	stateKey := generateStateKey(i, serviceId)

	// Verify the length is 32 bytes
	assert.Equal(t, 32, len(stateKey))

	// Verify that the first byte matches i
	assert.Equal(t, i, stateKey[0])

	// Optionally, verify that the encoded serviceId is in the key
	expectedEncodedServiceId := make([]byte, 4)
	binary.BigEndian.PutUint32(expectedEncodedServiceId, uint32(serviceId))
	assert.Equal(t, expectedEncodedServiceId, stateKey[1:5])
}

// TestGenerateStateKeyInterleaved verifies that the interleaving function works as expected.
func TestGenerateStateKeyInterleaved(t *testing.T) {
	serviceId := block.ServiceId(1234)
	hash := crypto.Hash{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Generate the interleaved state key
	stateKey := generateStateKeyInterleaved(serviceId, hash)

	// Verify the length is 32 bytes
	assert.Equal(t, 32, len(stateKey))

	// Verify that the first 8 bytes are interleaved between serviceId and hash
	assert.Equal(t, stateKey[0], byte(serviceId>>24))
	assert.Equal(t, stateKey[1], hash[0])
	assert.Equal(t, stateKey[2], byte(serviceId>>16))
	assert.Equal(t, stateKey[3], hash[1])
}

// TestCalculateFootprintSize checks if the footprint size calculation is correct.
func TestCalculateFootprintSize(t *testing.T) {
	storage := map[crypto.Hash][]byte{
		{0x01}: {0x01, 0x02, 0x03},
	}
	preimageMeta := map[PreImageMetaKey]PreimageHistoricalTimeslots{
		{Hash: crypto.Hash{0x02}, Length: 32}: {},
	}

	// Calculate footprint size
	footprintSize := calculateFootprintSize(storage, preimageMeta)

	// Verify the calculation
	expectedSize := uint64(81+32) + uint64(32+3)
	assert.Equal(t, expectedSize, footprintSize)
}

// TestCombineEncoded verifies that combining multiple encoded fields works as expected.
func TestCombineEncoded(t *testing.T) {
	field1 := []byte{0x01, 0x02}
	field2 := []byte{0x03, 0x04}

	// Combine the fields
	combined := combineEncoded(field1, field2)

	// Verify the combined result
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, combined)
}

// TestBitwiseNotExceptFirst4Bytes checks that the bitwise NOT is applied correctly except the first 4 bytes.
func TestBitwiseNotExceptFirst4Bytes(t *testing.T) {
	// Example input hash
	inputHash := crypto.Hash{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Apply the bitwise NOT except the first 4 bytes
	result := bitwiseNotExceptFirst4Bytes(inputHash)

	// Verify that the first 4 bytes are unchanged
	assert.Equal(t, inputHash[0:4], result[0:4])

	// Verify that the rest of the bytes are bitwise NOT applied
	for i := 4; i < len(result); i++ {
		assert.Equal(t, ^inputHash[i], result[i])
	}
}
