package mountain_ranges

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree/testutils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMMR(t *testing.T) {
	tests := []struct {
		name          string
		toAppend      [][]byte
		expectedPeaks []*crypto.Hash
	}{
		{
			name:          "empty",
			toAppend:      [][]byte{},
			expectedPeaks: []*crypto.Hash{},
		},
		{
			name:     "single_item",
			toAppend: [][]byte{[]byte("1")},
			expectedPeaks: func() []*crypto.Hash {
				h := testutils.MockHashData([]byte("1"))
				return []*crypto.Hash{&h}
			}(),
		},
		{
			name: "two_items",
			toAppend: [][]byte{
				[]byte("1"),
				[]byte("2"),
			},
			expectedPeaks: func() []*crypto.Hash {
				h1 := testutils.MockHashData([]byte("1"))
				h2 := testutils.MockHashData([]byte("2"))
				combined := append(h1[:], h2[:]...)
				hash := testutils.MockHashData(combined)
				return []*crypto.Hash{
					nil,
					&hash,
				}
			}(),
		},
		{
			name: "three_items",
			toAppend: [][]byte{
				[]byte("1"),
				[]byte("2"),
				[]byte("3"),
			},
			expectedPeaks: func() []*crypto.Hash {
				h1 := testutils.MockHashData([]byte("1"))
				h2 := testutils.MockHashData([]byte("2"))
				combined := append(h1[:], h2[:]...)
				h12 := testutils.MockHashData(combined)
				h3 := testutils.MockHashData([]byte("3"))
				return []*crypto.Hash{
					&h3,
					&h12,
				}
			}(),
		},
		{
			name: "four_items",
			toAppend: [][]byte{
				[]byte("1"),
				[]byte("2"),
				[]byte("3"),
				[]byte("4"),
			},
			expectedPeaks: func() []*crypto.Hash {
				h1 := testutils.MockHashData([]byte("1"))
				h2 := testutils.MockHashData([]byte("2"))
				combined12 := append(h1[:], h2[:]...)
				h12 := testutils.MockHashData(combined12)
				h3 := testutils.MockHashData([]byte("3"))
				h4 := testutils.MockHashData([]byte("4"))
				combined34 := append(h3[:], h4[:]...)
				h34 := testutils.MockHashData(combined34)
				combined := append(h12[:], h34[:]...)
				hash := testutils.MockHashData(combined)
				return []*crypto.Hash{
					nil,
					nil,
					&hash,
				}
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mmr := New()

			// Append all items
			for _, item := range tc.toAppend {
				err := mmr.Append(item, testutils.MockHashData)
				assert.NoError(t, err)
			}

			// Check peaks
			assert.Equal(t, tc.expectedPeaks, mmr.GetPeaks())
		})
	}
}

func TestEncode(t *testing.T) {
	tests := []struct {
		name     string
		toAppend [][]byte
	}{
		{
			name:     "empty",
			toAppend: [][]byte{},
		},
		{
			name: "multiple_items",
			toAppend: [][]byte{
				[]byte("1"),
				[]byte("2"),
				[]byte("3"),
				[]byte("4"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mmr := New()

			for _, item := range tc.toAppend {
				err := mmr.Append(item, testutils.MockHashData)
				assert.NoError(t, err)
			}

			encoded, err := mmr.Encode()

			assert.NoError(t, err)
			assert.NotNil(t, encoded)
		})
	}
}

func TestAppendIdempotent(t *testing.T) {
	mmr1 := New()
	mmr2 := New()

	items := [][]byte{[]byte("1"), []byte("2"), []byte("3")}

	// Append to first MMR in sequence
	for _, item := range items {
		err := mmr1.Append(item, testutils.MockHashData)
		assert.NoError(t, err)
	}

	// Append same items to second MMR
	for _, item := range items {
		err := mmr2.Append(item, testutils.MockHashData)
		assert.NoError(t, err)
	}

	// Both should have identical peaks
	assert.Equal(t, mmr1.GetPeaks(), mmr2.GetPeaks())

	// Both should encode to same value
	encoded1, err := mmr1.Encode()
	assert.NoError(t, err)
	encoded2, err := mmr2.Encode()
	assert.NoError(t, err)
	assert.Equal(t, encoded1, encoded2)
}
