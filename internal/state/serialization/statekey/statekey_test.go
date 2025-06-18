package statekey

import (
	"fmt"
	"math"
	"testing"

	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/stretchr/testify/assert"
)

// TestNewService verifies that the state key generation works as expected for services.
func TestNewService(t *testing.T) {
	tests := []struct {
		name      string
		serviceId block.ServiceId
	}{
		{
			name:      "basic case",
			serviceId: 100,
		},
		{
			name:      "max values",
			serviceId: block.ServiceId(math.MaxUint32),
		},
		{
			name:      "zero values",
			serviceId: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate the state key
			stateKey, err := NewService(tt.serviceId)
			require.NoError(t, err)

			// Get encoded service ID for verification
			encodedServiceId, err := jam.Marshal(tt.serviceId)
			require.NoError(t, err)

			// Verify first byte is 255
			assert.Equal(t, uint8(255), stateKey[0], "first byte should be 255")

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
			for i := 9; i < 31; i++ {
				assert.Equal(t, byte(0), stateKey[i],
					fmt.Sprintf("byte at position %d should be zero", i))
			}

			// Verify we can extract the service ID back
			_, extractedServiceId, err := stateKey.ExtractChapterServiceID()
			require.NoError(t, err)
			assert.Equal(t, tt.serviceId, extractedServiceId)
		})
	}
}

// TestNewServiceDict verifies that the interleaving function works as expected.
func TestNewServiceDict(t *testing.T) {
	serviceId := block.ServiceId(1234)
	hashComponent := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Get encoded service ID for verification
	encodedServiceId, err := jam.Marshal(serviceId)
	require.NoError(t, err)

	// Generate the interleaved state key
	stateKey, err := NewServiceDict(serviceId, hashComponent)
	require.NoError(t, err)

	// Verify that the first 8 bytes are interleaved between serviceId and the hash of the hash component
	hash := crypto.HashData(hashComponent)
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
