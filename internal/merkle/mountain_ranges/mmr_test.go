package mountain_ranges

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func mockHashData(data []byte) crypto.Hash {
	var h crypto.Hash
	copy(h[:], data)
	return h
}

func TestMMR(t *testing.T) {
	tests := []struct {
		name          string
		toAppend      [][]byte
		expectedPeaks []*crypto.Hash
	}{
		{
			name:          "empty",
			toAppend:      [][]byte{},
			expectedPeaks: make([]*crypto.Hash, 0), // Initialize properly
		},
		{
			name:     "single_item",
			toAppend: [][]byte{[]byte("1")},
			expectedPeaks: func() []*crypto.Hash {
				h := mockHashData([]byte("1"))
				return []*crypto.Hash{&h}
			}(),
		},
		{
			name:     "two_items",
			toAppend: [][]byte{[]byte("1"), []byte("2")},
			expectedPeaks: func() []*crypto.Hash {
				h1 := mockHashData([]byte("1"))
				h2 := mockHashData([]byte("2"))
				combined := append(h1[:], h2[:]...)
				hash := mockHashData(combined)
				return []*crypto.Hash{
					nil,
					&hash,
				}
			}(),
		},
		{
			name:     "three_items",
			toAppend: [][]byte{[]byte("1"), []byte("2"), []byte("3")},
			expectedPeaks: func() []*crypto.Hash {
				h1 := mockHashData([]byte("1"))
				h2 := mockHashData([]byte("2"))
				combined := append(h1[:], h2[:]...)
				h12 := mockHashData(combined)
				h3 := mockHashData([]byte("3"))
				return []*crypto.Hash{&h3, &h12}
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mmr := New()
			peaks := make([]*crypto.Hash, 0)

			for _, item := range tc.toAppend {
				hash := mockHashData(item)
				peaks = mmr.Append(peaks, hash, mockHashData)
			}

			// Compare slices length
			assert.Equal(t, len(tc.expectedPeaks), len(peaks))

			// Compare individual hash values
			for i := range peaks {
				if tc.expectedPeaks[i] == nil {
					assert.Nil(t, peaks[i])
				} else {
					assert.Equal(t, *tc.expectedPeaks[i], *peaks[i])
				}
			}

			encoded, err := mmr.Encode(peaks)
			require.NoError(t, err)
			assert.NotNil(t, encoded)
		})
	}
}
