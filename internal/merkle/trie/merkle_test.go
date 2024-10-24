package trie

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestBit tests the bit utility function.
func TestBit(t *testing.T) {
	byteSeq := []byte{0xA2} // 10100010 in binary

	// Test individual bits
	assert.Equal(t, true, bit(byteSeq, 0), "The first bit should be 1.")
	assert.Equal(t, false, bit(byteSeq, 1), "The second bit should be 0.")
	assert.Equal(t, true, bit(byteSeq, 2), "The third bit should be 1.")
	assert.Equal(t, false, bit(byteSeq, 3), "The fourth bit should be 0.")
	assert.Equal(t, false, bit(byteSeq, 4), "The fifth bit should be 0.")
	assert.Equal(t, false, bit(byteSeq, 5), "The sixth bit should be 0.")
	assert.Equal(t, true, bit(byteSeq, 6), "The seventh bit should be 1.")
	assert.Equal(t, false, bit(byteSeq, 7), "The eighth bit should be 0.")
}
