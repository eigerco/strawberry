//go:build integration

package integration_test

import (
	"encoding/hex"
	"encoding/json"
	"github.com/eigerco/strawberry/internal/merkle/trie"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

// Merklize test struct for parsing JSON
type MerkleTestVector struct {
	Input  map[string]string `json:"input"`
	Output string            `json:"output"`
}

// Helper function to load the JSON file and unmarshal it into the test vector structs
func loadMerkleTestVectors(t *testing.T, filename string) []MerkleTestVector {
	file, err := os.ReadFile(filename)
	require.NoError(t, err)

	var vectors []MerkleTestVector
	err = json.Unmarshal(file, &vectors)
	require.NoError(t, err)

	return vectors
}

// Test function to verify Merklize implementation against the vectors loaded from the JSON file
func TestMerkleTreeFromJSON(t *testing.T) {
	// Load test vectors from the JSON file
	testVectors := loadMerkleTestVectors(t, "vectors/trie/trie.json")

	for _, vector := range testVectors {
		// Prepare the input for the Merklize function
		var kvs [][2][]byte
		for k, v := range vector.Input {
			kvs = append(kvs, [2][]byte{hexToBytes(t, k), hexToBytes(t, v)})
		}

		// Calculate the merkle root
		result, err := trie.Merklize(kvs, 0, nil)
		require.NoError(t, err)

		// Check if the calculated output matches the expected output
		expected := hexToBytes(t, vector.Output)
		require.Equal(t, expected, result[:], "Merklize root mismatch for input %v", vector.Input)
	}
}

// Helper function to convert a hex string to byte slice
func hexToBytes(t *testing.T, hexStr string) []byte {
	bytes, err := hex.DecodeString(hexStr)
	require.NoError(t, err)
	return bytes
}
