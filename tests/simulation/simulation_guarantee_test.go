//go:build integration

// Genesis state, block and keys adapted from: https://github.com/jam-duna/jamtestnet
package simulation

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/testutils"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
	"github.com/eigerco/strawberry/pkg/db/pebble"
)

func TestSimulateGuarantee(t *testing.T) {
	data, err := os.ReadFile("keys.json")
	require.NoError(t, err)

	// Genesis validator keys
	var keys []ValidatorKeys
	err = json.Unmarshal(data, &keys)
	require.NoError(t, err)

	// Genesis state
	data, err = os.ReadFile("genesis-state-guarantee-tiny.json")
	require.NoError(t, err)
	var currentState *state.State
	restoredState := jsonutils.RestoreStateSnapshot(data)
	currentState = &restoredState

	// Gensesis block
	data, err = os.ReadFile("block-with-guarantee-tiny.json")
	require.NoError(t, err)
	var genesisSimBlock Block
	err = json.Unmarshal(data, &genesisSimBlock)
	currentBlock := toGuaranteeBlock(t, genesisSimBlock)
	require.NoError(t, err)

	// Trie DB for merklization
	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		require.NoError(t, err, "failed to close db")
	}()
	trieDB := store.NewTrie(db)
	require.NoError(t, err)

	chainDB := store.NewChain(db)
	require.NoError(t, err)

	currentTimeslot := jamtime.Timeslot(12)
	slotLeaderKey := crypto.BandersnatchPrivateKey{}
	slotLeaderName := ""

	// Find the slot leader
	found := false
	for _, k := range keys {
		key := crypto.BandersnatchPrivateKey(testutils.MustFromHex(t, k.BandersnatchPrivate))
		ok, err := isSlotLeader(currentTimeslot, currentState, key)
		require.NoError(t, err)
		if ok {
			slotLeaderKey = key
			slotLeaderName = k.Name
			found = true
			break
		}
	}
	require.True(t, found, "slot leader not found")

	require.NotEqual(t, slotLeaderKey, crypto.BandersnatchPrivateKey{})
	t.Logf("slot leader: %s", slotLeaderName)

	headerHash, err := currentBlock.Header.Hash()
	require.NoError(t, err)

	ticketAttempts := map[string]int{}
	for _, k := range keys {
		ticketAttempts[k.Name] = 0
	}

	// Submit tickets if possible
	ticketProofs := submitTickets(t, keys, currentState, currentTimeslot, ticketAttempts)

	newBlock, err := produceBlock(
		currentTimeslot,
		headerHash,
		currentState,
		trieDB,
		slotLeaderKey,
		ticketProofs,
		block.Extrinsic{
			EG: currentBlock.Extrinsic.EG,
		},
	)
	require.NoError(t, err)

	t.Logf("block prior state root: %v", hex.EncodeToString(newBlock.Header.PriorStateRoot[:]))
	t.Logf("block parent hash: %v", hex.EncodeToString(newBlock.Header.ParentHash[:]))

	// Update state
	err = statetransition.UpdateState(
		currentState,
		newBlock,
		chainDB,
	)

	require.NoError(t, err)
}

type Block struct {
	Header    Header
	Extrinsic Extrinsic `json:"extrinsic"`
}

type Extrinsic struct {
	Guarantees []Guarantees `json:"guarantees"`
}

type Guarantees struct {
	Report     WorkReport       `json:"report"`
	Slot       jamtime.Timeslot `json:"slot"`
	Signatures []struct {
		ValidatorIndex uint16 `json:"validator_index"`
		Signature      string `json:"signature"`
	} `json:"signatures"`
}

type WorkReport struct {
	PackageSpec struct {
		Hash         string `json:"hash"`
		Length       uint32 `json:"length"`
		ErasureRoot  string `json:"erasure_root"`
		ExportsRoot  string `json:"exports_root"`
		ExportsCount uint16 `json:"exports_count"`
	} `json:"package_spec"`
	Context           RefinementContext `json:"context"`
	CoreIndex         uint16            `json:"core_index"`
	AuthorizerHash    string            `json:"authorizer_hash"`
	AuthOutput        string            `json:"auth_output"`
	SegmentRootLookup []interface{}     `json:"segment_root_lookup"`
	Results           []WorkResult      `json:"results"`
	AuthGasUsed       uint              `json:"auth_gas_used"`
}

type RefinementContext struct {
	Anchor           string           `json:"anchor"`
	StateRoot        string           `json:"state_root"`
	BeefyRoot        string           `json:"beefy_root"`
	LookupAnchor     string           `json:"lookup_anchor"`
	LookupAnchorSlot jamtime.Timeslot `json:"lookup_anchor_slot"`
	Prerequisites    []crypto.Hash    `json:"prerequisites"`
}

type WorkResult struct {
	ServiceId     block.ServiceId `json:"service_id"`
	CodeHash      string          `json:"code_hash"`
	PayloadHash   string          `json:"payload_hash"`
	AccumulateGas uint64          `json:"accumulate_gas"`
	Result        Result          `json:"result"`
	RefineLoad    struct {
		GasUsed        uint `json:"gas_used"`
		Imports        uint `json:"imports"`
		ExtrinsicCount uint `json:"extrinsic_count"`
		ExtrinsicSize  uint `json:"extrinsic_size"`
		Exports        uint `json:"exports"`
	} `json:"refine_load"`
}

type Result struct {
	Ok    *string         `json:"ok"`
	Panic json.RawMessage `json:"panic"`
}

func toGuaranteeBlock(t *testing.T, simBlock Block) block.Block {
	b := block.Block{
		Header: block.Header{
			ParentHash:       crypto.Hash(testutils.MustFromHex(t, simBlock.Header.Parent)),
			PriorStateRoot:   crypto.Hash(testutils.MustFromHex(t, simBlock.Header.ParentStateRoot)),
			ExtrinsicHash:    crypto.Hash(testutils.MustFromHex(t, simBlock.Header.ExtrinsicHash)),
			TimeSlotIndex:    jamtime.Timeslot(simBlock.Header.Slot),
			BlockAuthorIndex: uint16(simBlock.Header.AuthorIndex),
		},
		Extrinsic: block.Extrinsic{
			EG: block.GuaranteesExtrinsic{Guarantees: mapGuaranteeBlock(t, simBlock.Extrinsic.Guarantees)},
		},
	}

	if simBlock.Header.EpochMark != nil {
		epochMark := &block.EpochMarker{
			Entropy:        crypto.Hash(testutils.MustFromHex(t, simBlock.Header.EpochMark.Entropy)),
			TicketsEntropy: crypto.Hash(testutils.MustFromHex(t, simBlock.Header.EpochMark.TicketsEntropy)),
		}

		for i, v := range simBlock.Header.EpochMark.Validators {
			epochMark.Keys[i].Bandersnatch = crypto.BandersnatchPublicKey(testutils.MustFromHex(t, v))
		}

		b.Header.EpochMarker = epochMark
	}

	return b
}

func mapGuaranteeBlock(t *testing.T, simGuarantee []Guarantees) []block.Guarantee {
	var guarantees []block.Guarantee
	for _, g := range simGuarantee {
		var guarantee block.Guarantee

		var results []block.WorkResult
		for _, r := range g.Report.Results {
			var result block.WorkResult
			result.ServiceId = r.ServiceId
			result.ServiceHashCode = crypto.Hash(testutils.MustFromHex(t, r.CodeHash))
			result.PayloadHash = crypto.Hash(testutils.MustFromHex(t, r.PayloadHash))
			result.GasPrioritizationRatio = r.AccumulateGas

			if r.Result.Ok != nil {
				result.Output.SetValue(testutils.MustFromHex(t, *r.Result.Ok))
			}

			if r.Result.Panic != nil {
				result.Output.SetValue(block.UnexpectedTermination)
			}

			result.GasUsed = r.RefineLoad.GasUsed
			result.ImportsCount = r.RefineLoad.Imports
			result.ExtrinsicCount = r.RefineLoad.ExtrinsicCount
			result.ExtrinsicSize = r.RefineLoad.ExtrinsicSize
			result.ExportsCount = r.RefineLoad.ExtrinsicCount

			results = append(results, result)
		}

		guarantee.WorkReport = block.WorkReport{
			WorkPackageSpecification: block.WorkPackageSpecification{
				WorkPackageHash:           crypto.Hash(testutils.MustFromHex(t, g.Report.PackageSpec.Hash)),
				AuditableWorkBundleLength: g.Report.PackageSpec.Length,
				ErasureRoot:               crypto.Hash(testutils.MustFromHex(t, g.Report.PackageSpec.ErasureRoot)),
				SegmentRoot:               crypto.Hash(testutils.MustFromHex(t, g.Report.PackageSpec.ExportsRoot)),
				SegmentCount:              g.Report.PackageSpec.ExportsCount,
			},
			RefinementContext: block.RefinementContext{
				Anchor: block.RefinementContextAnchor{
					HeaderHash:         crypto.Hash(testutils.MustFromHex(t, g.Report.Context.Anchor)),
					PosteriorStateRoot: crypto.Hash(testutils.MustFromHex(t, g.Report.Context.StateRoot)),
					PosteriorBeefyRoot: crypto.Hash(testutils.MustFromHex(t, g.Report.Context.BeefyRoot)),
				},
				LookupAnchor: block.RefinementContextLookupAnchor{
					HeaderHash: crypto.Hash(testutils.MustFromHex(t, g.Report.Context.LookupAnchor)),
					Timeslot:   g.Report.Context.LookupAnchorSlot,
				},
			},
			CoreIndex:      g.Report.CoreIndex,
			AuthorizerHash: crypto.Hash(testutils.MustFromHex(t, g.Report.AuthorizerHash)),
			Output:         testutils.MustFromHex(t, g.Report.AuthOutput),
			WorkResults:    results,
			AuthGasUsed:    g.Report.AuthGasUsed,
		}

		guarantee.Timeslot = g.Slot

		var signatures []block.CredentialSignature
		for _, sig := range g.Signatures {
			var signature block.CredentialSignature
			signature.ValidatorIndex = sig.ValidatorIndex
			signature.Signature = crypto.Ed25519Signature(testutils.MustFromHex(t, sig.Signature))

			signatures = append(signatures, signature)
			guarantee.Credentials = append(guarantee.Credentials, signature)
		}
		guarantees = append(guarantees, guarantee)
	}

	return guarantees
}
