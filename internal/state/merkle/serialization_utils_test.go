package state

import (
	"fmt"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/require"
	"math"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/stretchr/testify/assert"
)

// TestGenerateStateKeyInterleavedBasic verifies that the state key generation works as expected.
func TestGenerateStateKeyInterleavedBasic(t *testing.T) {
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
			stateKey, err := generateStateKeyInterleavedBasic(tt.i, tt.serviceId)
			require.NoError(t, err)

			// Get encoded service ID for verification
			encodedServiceId, err := jam.Marshal(tt.serviceId)
			require.NoError(t, err)

			// Verify length is 32 bytes
			assert.Equal(t, 32, len(stateKey), "key length should be 32 bytes")

			// Verify first byte is i
			assert.Equal(t, tt.i, stateKey[0], "first byte should be i")

			// Verify the interleaved pattern:
			// [i, s0, 0, s1, 0, s2, 0, s3, 0, 0, ...]
			assert.Equal(t, encodedServiceId[0], stateKey[1], "s0 should be at position 1")
			assert.Equal(t, byte(0), stateKey[2], "zero should be at position 2")
			assert.Equal(t, encodedServiceId[1], stateKey[3], "s1 should be at position 3")
			assert.Equal(t, byte(0), stateKey[4], "zero should be at position 4")
			assert.Equal(t, encodedServiceId[2], stateKey[5], "s2 should be at position 5")
			assert.Equal(t, byte(0), stateKey[6], "zero should be at position 6")
			assert.Equal(t, encodedServiceId[3], stateKey[7], "s3 should be at position 7")
			assert.Equal(t, byte(0), stateKey[8], "zero should be at position 8")

			// Verify remaining bytes are zero
			for i := 9; i < 32; i++ {
				assert.Equal(t, byte(0), stateKey[i],
					fmt.Sprintf("byte at position %d should be zero", i))
			}

			// Verify we can extract the service ID back
			extractedServiceId, err := extractServiceIdFromKey(crypto.Hash(stateKey))
			require.NoError(t, err)
			assert.Equal(t, tt.serviceId, extractedServiceId)
		})
	}
}

// TestGenerateStateKeyInterleaved verifies that the interleaving function works as expected.
func TestGenerateStateKeyInterleaved(t *testing.T) {
	serviceId := block.ServiceId(1234)
	hash := crypto.Hash{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Get encoded service ID for verification
	encodedServiceId, err := jam.Marshal(serviceId)
	require.NoError(t, err)

	// Generate the interleaved state key
	stateKey, err := generateStateKeyInterleaved(serviceId, hash)
	require.NoError(t, err)

	// Verify the length is 32 bytes
	assert.Equal(t, 32, len(stateKey))

	// Verify that the first 8 bytes are interleaved between serviceId and hash
	assert.Equal(t, encodedServiceId[0], stateKey[0])
	assert.Equal(t, hash[0], stateKey[1])
	assert.Equal(t, encodedServiceId[1], stateKey[2])
	assert.Equal(t, hash[1], stateKey[3])
	assert.Equal(t, encodedServiceId[2], stateKey[4])
	assert.Equal(t, hash[2], stateKey[5])
	assert.Equal(t, encodedServiceId[3], stateKey[6])
	assert.Equal(t, hash[3], stateKey[7])

	// Verify that remaining bytes from hash are copied correctly
	rest := stateKey[8:]
	for i := 0; i < len(rest); i++ {
		if i < len(hash)-4 {
			assert.Equal(t, hash[i+4], rest[i], "hash byte mismatch at position %d", i)
		} else {
			assert.Equal(t, byte(0), rest[i], "should be zero at position %d", i)
		}
	}
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
