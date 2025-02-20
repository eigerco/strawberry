//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/stretchr/testify/require"
)

// JSON structures for authorization test vectors
type AuthInput struct {
	Slot  int          `json:"slot"`
	Auths []CoreAuthor `json:"auths"`
}

type CoreAuthor struct {
	Core     int    `json:"core"`
	AuthHash string `json:"auth_hash"`
}

type AuthData struct {
	Input     AuthInput  `json:"input"`
	PreState  AuthState  `json:"pre_state"`
	Output    AuthOutput `json:"output"`
	PostState AuthState  `json:"post_state"`
}

type AuthOutput struct {
	Ok  interface{} `json:"ok"`
	Err string      `json:"err"`
}

type AuthState struct {
	AuthPools  [][]string `json:"auth_pools"`
	AuthQueues [][]string `json:"auth_queues"`
}

func readAuthJSONFile(filename string) (*AuthData, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var data AuthData
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return &data, nil
}

func mapAuthState(s AuthState) state.State {
	var authPools state.CoreAuthorizersPool

	// Map each pool
	for i, pool := range s.AuthPools {
		if i >= int(common.TotalNumberOfCores) {
			break
		}
		authPools[i] = make([]crypto.Hash, len(pool))
		for j, hash := range pool {
			authPools[i][j] = crypto.Hash(crypto.StringToHex(hash))
		}
	}

	// Map each queue
	authQueues := state.PendingAuthorizersQueues{}
	for coreIndex, auths := range s.AuthQueues {
		// Ensure we don't exceed the size of authQueues
		if coreIndex >= len(authQueues) {
			break
		}
		// Iterate over all hashes in the JSON slice and assign them to the queue
		for i, hashStr := range auths {
			authQueues[uint16(coreIndex)][i] = crypto.Hash(crypto.StringToHex(hashStr))
		}
	}

	return state.State{
		CoreAuthorizersPool:      authPools,
		PendingAuthorizersQueues: authQueues,
	}
}

func TestAuthorizations(t *testing.T) {
	files, err := os.ReadDir("vectors/authorizations/tiny")
	require.NoError(t, err, "failed to read authorizations directory")

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
			filePath := fmt.Sprintf("vectors/authorizations/tiny/%s", file.Name())
			data, err := readAuthJSONFile(filePath)
			require.NoError(t, err, "failed to read JSON file: %s", filePath)

			// Map pre-state
			preState := mapAuthState(data.PreState)

			// Create block header
			header := block.Header{
				TimeSlotIndex: jamtime.Timeslot(data.Input.Slot),
			}

			// Map authorizations to guarantees for the block
			guarantees := mapGuarantees(data)

			// Process authorizations
			newAuthPools := statetransition.CalculateNewCoreAuthorizations(
				header,
				guarantees,
				preState.PendingAuthorizersQueues,
				preState.CoreAuthorizersPool,
			)

			// Map expected post-state
			expectedPostState := mapAuthState(data.PostState)

			// Verify authorization pools
			require.Equal(t, len(expectedPostState.CoreAuthorizersPool), len(newAuthPools),
				"Mismatch in CoreAuthorizersPool length")

			for i := range expectedPostState.CoreAuthorizersPool {
				expected := expectedPostState.CoreAuthorizersPool[i]
				actual := newAuthPools[i]

				require.ElementsMatch(t, expected, actual,
					"Mismatch in CoreAuthorizersPool[%d]", i)
			}

			for i := range expectedPostState.PendingAuthorizersQueues {
				expected := preState.PendingAuthorizersQueues[i]
				actual := expectedPostState.PendingAuthorizersQueues[i]

				require.ElementsMatch(t, expected, actual,
					"Mismatch in CoreAuthorizersPool[%d]", i)
			}

			// If error expected, verify it
			if data.Output.Err != "" {
				require.Error(t, err)
				require.EqualError(t, err, strings.ReplaceAll(data.Output.Err, "_", " "))
				return
			}
			require.NoError(t, err)
		})
	}
}

func mapGuarantees(data *AuthData) block.GuaranteesExtrinsic {
	guarantees := block.GuaranteesExtrinsic{}
	for _, auth := range data.Input.Auths {
		guarantee := block.Guarantee{
			WorkReport: block.WorkReport{
				CoreIndex:      uint16(auth.Core),
				AuthorizerHash: crypto.Hash(crypto.StringToHex(auth.AuthHash)),
				// Other fields left at zero values since not used in test vectors
			},
			Timeslot: jamtime.Timeslot(data.Input.Slot),
			// Test vectors don't require specific credentials
			Credentials: []block.CredentialSignature{},
		}
		guarantees.Guarantees = append(guarantees.Guarantees, guarantee)
	}
	return guarantees
}
