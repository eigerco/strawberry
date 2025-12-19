//go:build tiny && conformance

package conformance

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/guaranteeing"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// Trace represents a block trace with pre and post state for testing
type Trace struct {
	PreState  StateWithRoot
	Block     block.Block
	PostState StateWithRoot
}

// StateWithRoot represents state with its merkle root
type StateWithRoot struct {
	StateRoot crypto.Hash
	KeyValues []statekey.KeyValue
}

// Genesis represents the genesis block with header and state
type GenesisTrace struct {
	Header block.Header
	State  StateWithRoot
}

// TestAncestryFeature tests ancestry storage and validation with 6 cases:
// 1. FeatureNone: ancestry NOT stored, ImportBlock succeeds (no validation)
// 2. FeatureFork: ancestry NOT stored, ImportBlock succeeds (no validation)
// 3. FeatureAncestry: ancestry stored, ImportBlock succeeds
// 4. FeatureAncestry + delete: ancestry stored then deleted, ImportBlock fails
// 5. FeatureAncestryAndFork: ancestry stored, ImportBlock succeeds
// 6. FeatureAncestryAndFork + delete: ancestry stored then deleted, ImportBlock fails
func TestAncestryFeature(t *testing.T) {
	tests := []struct {
		name                     string
		features                 Features
		deleteAncestryFromDB     bool
		expectBlockImportSuccess bool
		expectAncestryStored     bool
	}{{
		name:                     "ancestry disabled - import succeeds without validation",
		features:                 FeatureNone,
		deleteAncestryFromDB:     false,
		expectBlockImportSuccess: true,
		expectAncestryStored:     false,
	},
		{
			name:                     "ancestry disabled - ancestry not stored in DB",
			features:                 FeatureFork,
			deleteAncestryFromDB:     false,
			expectBlockImportSuccess: true,
			expectAncestryStored:     false,
		},
		{
			name:                     "ancestry enabled and stored - import succeeds",
			features:                 FeatureAncestry,
			deleteAncestryFromDB:     false,
			expectBlockImportSuccess: true,
			expectAncestryStored:     true,
		},
		{
			name:                     "ancestry enabled but deleted - import fails",
			features:                 FeatureAncestry,
			deleteAncestryFromDB:     true,
			expectBlockImportSuccess: false,
			expectAncestryStored:     true,
		},

		{
			name:                     "ancestryAndFork enabled and stored - import succeeds",
			features:                 FeatureAncestryAndFork,
			deleteAncestryFromDB:     false,
			expectBlockImportSuccess: true,
			expectAncestryStored:     true,
		},
		{
			name:                     "ancestryAndFork enabled but deleted - import fails",
			features:                 FeatureAncestryAndFork,
			deleteAncestryFromDB:     true,
			expectBlockImportSuccess: false,
			expectAncestryStored:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset guaranteeing.Ancestry before each test
			guaranteeing.Ancestry = false

			socketPath := fmt.Sprintf("/tmp/test_socket_ancestry_%s", tt.name)

			kvStore, err := pebble.NewKVStore()
			require.NoError(t, err)
			t.Cleanup(func() {
				if err := kvStore.Close(); err != nil {
					t.Log("db close error:", err)
				}
			})

			chain := store.NewChain(kvStore)
			trieStore := store.NewTrie(chain)

			appName := []byte("Strawberry")
			appVersion := Version{0, 0, 2}
			jamVersion := Version{0, 7, 2}

			go func() {
				n := NewNode(socketPath, chain, trieStore, appName, appVersion, jamVersion, tt.features)
				if err := n.Start(); err != nil {
					t.Logf("failed to start Node: %v", err)
				}
				t.Cleanup(func() {
					if err := n.Stop(); err != nil {
						t.Logf("failed to stop Node: %v", err)
					}
				})
			}()

			time.Sleep(1 * time.Second)

			conn, err := net.Dial("unix", socketPath)
			require.NoError(t, err)
			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Logf("failed to close connection: %v", err)
				}
			})

			ctx := context.Background()

			// Handshake
			requestMsg := NewMessage(PeerInfo{
				Name:       []byte("test client"),
				AppVersion: Version{1, 0, 0},
				JamVersion: Version{0, 7, 2},
			})
			msgBytes, err := jam.Marshal(requestMsg)
			require.NoError(t, err)
			err = handlers.WriteMessageWithContext(ctx, conn, msgBytes)
			require.NoError(t, err)
			_, err = handlers.ReadMessageWithContext(ctx, conn)
			require.NoError(t, err)

			// Load genesis and trace
			genesisData, err := os.ReadFile("../../tests/integration/traces/fuzzy_light/genesis.bin")
			require.NoError(t, err)
			var genesis GenesisTrace
			err = jam.Unmarshal(genesisData, &genesis)
			require.NoError(t, err)

			traceData, err := os.ReadFile("../../tests/integration/traces/fuzzy_light/00000001.bin")
			require.NoError(t, err)
			var trace Trace
			err = jam.Unmarshal(traceData, &trace)
			require.NoError(t, err)

			// Get the lookup_anchor from the trace block's guarantee
			require.NotEmpty(t, trace.Block.Extrinsic.EG.Guarantees, "trace block should have guarantees")
			lookupAnchorHash := trace.Block.Extrinsic.EG.Guarantees[0].WorkReport.RefinementContext.LookupAnchor.HeaderHash
			lookupAnchorSlot := trace.Block.Extrinsic.EG.Guarantees[0].WorkReport.RefinementContext.LookupAnchor.Timeslot

			// Create a random test hash to verify ancestry storage behavior
			// (separate from lookup_anchor which may match genesis)
			testAncestryHash := testutils.RandomHash(t)
			testAncestrySlot := uint32(99)

			// Initialize with ancestry: both the lookup_anchor (for block import) and a test hash (to verify storage)
			requestMsg = NewMessage(Initialize{
				Header: genesis.Header,
				State:  State{StateItems: genesis.State.KeyValues},
				Ancestry: Ancestry{Items: []AncestryItem{
					{Slot: uint32(lookupAnchorSlot), Hash: lookupAnchorHash},
					{Slot: testAncestrySlot, Hash: testAncestryHash},
				}},
			})

			msgBytes, err = jam.Marshal(requestMsg)
			require.NoError(t, err)
			err = handlers.WriteMessageWithContext(ctx, conn, msgBytes)
			require.NoError(t, err)

			bb, err := handlers.ReadMessageWithContext(ctx, conn)
			require.NoError(t, err)

			respMsg := &Message{}
			err = jam.Unmarshal(bb.Content, respMsg)
			require.NoError(t, err)

			_, isStateRoot := respMsg.Get().(StateRoot)
			require.True(t, isStateRoot, "expected StateRoot after Initialize, got %T: %+v", respMsg.Get(), respMsg.Get())

			// Verify ancestry storage behavior using the random test hash
			// (not the lookup_anchor which may be stored as genesis header)
			_, err = chain.GetHeader(testAncestryHash)
			if tt.expectAncestryStored {
				require.NoError(t, err, "test ancestry hash should be stored in database")
			} else {
				require.Error(t, err, "test ancestry hash should NOT be stored in database")
			}

			// Delete lookup_anchor from DB to test failure case (missing ancestry)
			if tt.deleteAncestryFromDB && tt.expectAncestryStored {
				headerKey := append([]byte{0x01}, lookupAnchorHash[:]...)
				err = kvStore.Delete(headerKey)
				require.NoError(t, err)
			}

			// Import block
			requestMsg = NewMessage(ImportBlock{
				Block: trace.Block,
			})
			msgBytes, err = jam.Marshal(requestMsg)
			require.NoError(t, err)
			err = handlers.WriteMessageWithContext(ctx, conn, msgBytes)
			require.NoError(t, err)

			bb, err = handlers.ReadMessageWithContext(ctx, conn)
			require.NoError(t, err)

			respMsg = &Message{}
			err = jam.Unmarshal(bb.Content, respMsg)
			require.NoError(t, err)

			// Verify import result
			if tt.expectBlockImportSuccess {
				stateRootResp, isStateRoot := respMsg.Get().(StateRoot)
				require.True(t, isStateRoot, "expected StateRoot after ImportBlock, got %T: %+v", respMsg.Get(), respMsg.Get())
				assert.Equal(t, trace.PostState.StateRoot, stateRootResp.StateRootHash, "state root should match trace post-state")
			} else {
				errorResp, isError := respMsg.Get().(Error)
				require.True(t, isError, "expected Error when ancestry is missing, got %T: %+v", respMsg.Get(), respMsg.Get())
				assert.Contains(t, string(errorResp.Message), "no record of header found")
			}
		})
	}
}
