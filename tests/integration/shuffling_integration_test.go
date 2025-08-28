//go:build integration

package integration

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
)

type ShufflingTestCase struct {
	Input          uint32
	Entropy        string
	ExpectedOutput []uint32 `json:"output"`
}

func TestShuffleVectors(t *testing.T) {
	filePath := "vectors/shuffling/shuffle_tests.json"
	fileData, err := os.ReadFile(filePath)
	require.NoError(t, err)

	var testCases []ShufflingTestCase
	err = json.Unmarshal(fileData, &testCases)
	require.NoError(t, err)

	for idx, testCase := range testCases {
		t.Run(
			fmt.Sprintf("Test case %d: Input=%d", idx+1, testCase.Input),
			func(t *testing.T) {
				entropyBytes, err := hex.DecodeString(testCase.Entropy)
				require.NoError(t, err)

				ss := make([]uint32, testCase.Input)
				for i := uint32(0); i < testCase.Input; i++ {
					ss[i] = i
				}

				shuffledSequence, err := common.DeterministicShuffle(ss, crypto.Hash(entropyBytes))
				require.NoError(t, err)

				assert.Equal(t, testCase.ExpectedOutput, shuffledSequence)
			},
		)
	}
}
