package integration

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestCase struct {
	Input          uint32
	Entropy        string
	ExpectedOutput []uint32 `json:"output"`
}

func TestShuffleVectors(t *testing.T) {
	filePath := "vectors/shuffling/shuffle_tests.json"
	fileData, err := os.ReadFile(filePath)
	require.NoError(t, err)

	var testCases []TestCase
	s := serialization.NewSerializer(&codec.JSONCodec{})
	err = s.Decode(fileData, &testCases)
	require.NoError(t, err)

	for idx, testCase := range testCases {
		t.Run(
			fmt.Sprintf("Test case %d: Input=%d", idx+1, testCase.Input),
			func(t *testing.T) {
				entropyBytes, err := hex.DecodeString(testCase.Entropy)
				require.NoError(t, err)

				shuffledSequence, err := common.DeterministicShuffle(testCase.Input, crypto.Hash(entropyBytes))
				require.NoError(t, err)

				assert.Equal(t, testCase.ExpectedOutput, shuffledSequence)
			},
		)
	}
}
