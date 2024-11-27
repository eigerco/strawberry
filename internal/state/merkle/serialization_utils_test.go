package state

import (
	"encoding/binary"
	"fmt"
	"math"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/stretchr/testify/assert"
)

// TestGenerateStateKey verifies that the state key generation works as expected.
func TestGenerateStateKey(t *testing.T) {
	tests := []struct {
		name      string
		i         uint8
		serviceId block.ServiceId
	}{
		{
			name:      "basic case",
			i:         1,
			serviceId: 100,
		},
		{
			name:      "max values",
			i:         255,
			serviceId: block.ServiceId(math.MaxUint32),
		},
		{
			name:      "zero values",
			i:         0,
			serviceId: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate the state key
			stateKey := generateStateKey(tt.i, tt.serviceId)

			// Convert serviceId to bytes for verification
			serviceIdBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(serviceIdBytes, uint32(tt.serviceId))

			// Verify length is 32 bytes
			assert.Equal(t, 32, len(stateKey), "key length should be 32 bytes")

			// Verify first byte is i
			assert.Equal(t, tt.i, stateKey[0], "first byte should be i")

			// Verify the interleaved pattern:
			// [i, n0, 0, n1, 0, n2, 0, n3, 0, 0, ...]
			assert.Equal(t, serviceIdBytes[0], stateKey[1], "n0 should be at position 1")
			assert.Equal(t, byte(0), stateKey[2], "zero should be at position 2")
			assert.Equal(t, serviceIdBytes[1], stateKey[3], "n1 should be at position 3")
			assert.Equal(t, byte(0), stateKey[4], "zero should be at position 4")
			assert.Equal(t, serviceIdBytes[2], stateKey[5], "n2 should be at position 5")
			assert.Equal(t, byte(0), stateKey[6], "zero should be at position 6")
			assert.Equal(t, serviceIdBytes[3], stateKey[7], "n3 should be at position 7")
			assert.Equal(t, byte(0), stateKey[8], "zero should be at position 8")

			// Verify remaining bytes are zero
			for i := 9; i < 32; i++ {
				assert.Equal(t, byte(0), stateKey[i],
					fmt.Sprintf("byte at position %d should be zero", i))
			}
		})
	}
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
	preimageMeta := map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
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
