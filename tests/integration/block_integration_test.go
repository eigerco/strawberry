//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

var toWorkResultErrorMap = map[string]block.WorkResultError{
	"out-of-gas":    block.OutOfGas,
	"panic":         block.UnexpectedTermination,
	"bad-code":      block.CodeNotAvailable,
	"code-oversize": block.CodeTooLarge,
}

func TestDecodeBlockWithJamCodec(t *testing.T) {
	b, err := os.ReadFile("vectors/codec/block.bin")
	require.NoError(t, err)

	var unmarshaled block.Block
	err = jam.Unmarshal(b, &unmarshaled)
	require.NoError(t, err)

	expected := unmarsalExpectedBlock(t)

	// Header fields
	require.Equal(t, expected.Header.Parent, toHex(unmarshaled.Header.ParentHash))
	require.Equal(t, expected.Header.ParentStateRoot, toHex(unmarshaled.Header.PriorStateRoot))
	require.Equal(t, expected.Header.ExtrinsicHash, toHex(unmarshaled.Header.ExtrinsicHash))
	require.Equal(t, expected.Header.Slot, unmarshaled.Header.TimeSlotIndex)

	require.Equal(t, expected.Header.EpochMark.Entropy, toHex(unmarshaled.Header.EpochMarker.Entropy))
	require.Equal(t, expected.Header.EpochMark.TicketsEntropy, toHex(unmarshaled.Header.EpochMarker.TicketsEntropy))

	for i := range expected.Header.EpochMark.Validators {
		require.Equal(t, expected.Header.EpochMark.Validators[i], toHex(unmarshaled.Header.EpochMarker.Keys[i]))
	}

	require.Equal(t, expected.Header.TicketsMark, unmarshaled.Header.WinningTicketsMarker)

	for i := range expected.Header.OffendersMark {
		require.Equal(t, expected.Header.OffendersMark[i], toHex(unmarshaled.Header.OffendersMarkers[i]))
	}

	require.Equal(t, expected.Header.AuthorIndex, unmarshaled.Header.BlockAuthorIndex)
	require.Equal(t, expected.Header.EntropySource, toHex(unmarshaled.Header.VRFSignature))
	require.Equal(t, expected.Header.Seal, toHex(unmarshaled.Header.BlockSealSignature))

	// Extrinsic fields
	for i := range expected.Extrinsic.Tickets {
		require.Equal(t, expected.Extrinsic.Tickets[i].Attempt, unmarshaled.Extrinsic.ET.TicketProofs[i].EntryIndex)
		require.Equal(t, expected.Extrinsic.Tickets[i].Signature, toHex(unmarshaled.Extrinsic.ET.TicketProofs[i].Proof))
	}

	for i := range expected.Extrinsic.Disputes.Verdicts {
		require.Equal(t, expected.Extrinsic.Disputes.Verdicts[i].Target, toHex(unmarshaled.Extrinsic.ED.Verdicts[i].ReportHash))
		require.Equal(t, expected.Extrinsic.Disputes.Verdicts[i].Age, unmarshaled.Extrinsic.ED.Verdicts[i].EpochIndex)
		for j := range expected.Extrinsic.Disputes.Verdicts[i].Votes {
			require.Equal(t, expected.Extrinsic.Disputes.Verdicts[i].Votes[j].Vote, unmarshaled.Extrinsic.ED.Verdicts[i].Judgements[j].IsValid)
			require.Equal(t, expected.Extrinsic.Disputes.Verdicts[i].Votes[j].Index, unmarshaled.Extrinsic.ED.Verdicts[i].Judgements[j].ValidatorIndex)
			require.Equal(t, expected.Extrinsic.Disputes.Verdicts[i].Votes[j].Signature, toHex(unmarshaled.Extrinsic.ED.Verdicts[i].Judgements[j].Signature))
		}
	}

	for i := range expected.Extrinsic.Disputes.Culprits {
		require.Equal(t, expected.Extrinsic.Disputes.Culprits[i].Target, toHex(unmarshaled.Extrinsic.ED.Culprits[i].ReportHash))
		require.Equal(t, expected.Extrinsic.Disputes.Culprits[i].Key, toHex(unmarshaled.Extrinsic.ED.Culprits[i].ValidatorEd25519PublicKey))
		require.Equal(t, expected.Extrinsic.Disputes.Culprits[i].Signature, toHex(unmarshaled.Extrinsic.ED.Culprits[i].Signature))
	}

	for i := range expected.Extrinsic.Disputes.Faults {
		require.Equal(t, expected.Extrinsic.Disputes.Faults[i].Target, toHex(unmarshaled.Extrinsic.ED.Faults[i].ReportHash))
		require.Equal(t, expected.Extrinsic.Disputes.Faults[i].Vote, unmarshaled.Extrinsic.ED.Faults[i].IsValid)
		require.Equal(t, expected.Extrinsic.Disputes.Faults[i].Key, toHex(unmarshaled.Extrinsic.ED.Faults[i].ValidatorEd25519PublicKey))
		require.Equal(t, expected.Extrinsic.Disputes.Faults[i].Signature, toHex(unmarshaled.Extrinsic.ED.Faults[i].Signature))
	}

	for i := range expected.Extrinsic.Preimages {
		require.Equal(t, expected.Extrinsic.Preimages[i].Requester, unmarshaled.Extrinsic.EP[i].ServiceIndex)
		require.Equal(t, expected.Extrinsic.Preimages[i].Blob, toHex(unmarshaled.Extrinsic.EP[i].Data))
	}
	for i := range expected.Extrinsic.Assurances {
		require.Equal(t, expected.Extrinsic.Assurances[i].Anchor, toHex(unmarshaled.Extrinsic.EA[i].Anchor))
		require.Equal(t, expected.Extrinsic.Assurances[i].Bitfield, toHex(unmarshaled.Extrinsic.EA[i].Bitfield))
		require.Equal(t, expected.Extrinsic.Assurances[i].ValidatorIndex, unmarshaled.Extrinsic.EA[i].ValidatorIndex)
		require.Equal(t, expected.Extrinsic.Assurances[i].Signature, toHex(unmarshaled.Extrinsic.EA[i].Signature))
	}

	for i := range expected.Extrinsic.Guarantees {
		require.Equal(t, expected.Extrinsic.Guarantees[i].Report.PackageSpec.Hash, toHex(unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.WorkPackageSpecification.WorkPackageHash))
		require.Equal(t, expected.Extrinsic.Guarantees[i].Report.PackageSpec.Length, unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.WorkPackageSpecification.AuditableWorkBundleLength)
		require.Equal(t, expected.Extrinsic.Guarantees[i].Report.PackageSpec.ErasureRoot, toHex(unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.WorkPackageSpecification.ErasureRoot))
		require.Equal(t, expected.Extrinsic.Guarantees[i].Report.PackageSpec.ExportsRoot, toHex(unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.WorkPackageSpecification.SegmentRoot))
		require.Equal(t, expected.Extrinsic.Guarantees[i].Report.PackageSpec.ExportsCount, unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.WorkPackageSpecification.SegmentCount)

		require.Equal(t, expected.Extrinsic.Guarantees[i].Report.Context.Anchor, toHex(unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.RefinementContext.Anchor.HeaderHash))
		require.Equal(t, expected.Extrinsic.Guarantees[i].Report.Context.StateRoot, toHex(unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.RefinementContext.Anchor.PosteriorStateRoot))
		require.Equal(t, expected.Extrinsic.Guarantees[i].Report.Context.BeefyRoot, toHex(unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.RefinementContext.Anchor.PosteriorBeefyRoot))
		require.Equal(t, expected.Extrinsic.Guarantees[i].Report.Context.LookupAnchor, toHex(unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.RefinementContext.LookupAnchor.HeaderHash))
		require.Equal(t, expected.Extrinsic.Guarantees[i].Report.Context.LookupAnchorSlot, unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.RefinementContext.LookupAnchor.Timeslot)
		assertHashSlicesEqual(t, expected.Extrinsic.Guarantees[i].Report.Context.Prerequisites, unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.RefinementContext.PrerequisiteWorkPackage)

		require.Equal(t, expected.Extrinsic.Guarantees[i].Report.CoreIndex, unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.CoreIndex)
		require.Equal(t, expected.Extrinsic.Guarantees[i].Report.AuthorizerHash, toHex(unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.AuthorizerHash))
		require.Equal(t, expected.Extrinsic.Guarantees[i].Report.AuthOutput, toHex(unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.Output))

		for j := range expected.Extrinsic.Guarantees[i].Report.Results {
			require.Equal(t, expected.Extrinsic.Guarantees[i].Report.Results[j].ServiceId, unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.WorkResults[j].ServiceId)
			require.Equal(t, expected.Extrinsic.Guarantees[i].Report.Results[j].CodeHash, toHex(unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.WorkResults[j].ServiceHashCode))
			require.Equal(t, expected.Extrinsic.Guarantees[i].Report.Results[j].PayloadHash, toHex(unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.WorkResults[j].PayloadHash))
			require.Equal(t, expected.Extrinsic.Guarantees[i].Report.Results[j].Gas, unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.WorkResults[j].GasPrioritizationRatio)
			if expected.Extrinsic.Guarantees[i].Report.Results[j].Result.Ok != nil {
				require.Equal(t, *expected.Extrinsic.Guarantees[i].Report.Results[j].Result.Ok, toHex(unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.WorkResults[j].Output.Inner))
			}
			if expected.Extrinsic.Guarantees[i].Report.Results[j].Result.Error != nil {
				expectedWorkResult, found := toWorkResultErrorMap[*expected.Extrinsic.Guarantees[i].Report.Results[j].Result.Error]
				require.True(t, found)
				require.Equal(t, expectedWorkResult, unmarshaled.Extrinsic.EG.Guarantees[i].WorkReport.WorkResults[j].Output.Inner)
			}
		}

		require.Equal(t, expected.Extrinsic.Guarantees[i].Slot, unmarshaled.Extrinsic.EG.Guarantees[i].Timeslot)

		for j := range expected.Extrinsic.Guarantees[i].Signatures {
			require.Equal(t, expected.Extrinsic.Guarantees[i].Signatures[j].ValidatorIndex, unmarshaled.Extrinsic.EG.Guarantees[i].Credentials[j].ValidatorIndex)
			require.Equal(t, expected.Extrinsic.Guarantees[i].Signatures[j].Signature, toHex(unmarshaled.Extrinsic.EG.Guarantees[i].Credentials[j].Signature))
		}

	}
}

func toHex(data any) string {
	return fmt.Sprintf("0x%x", data)
}

func assertHashSlicesEqual(t *testing.T, expected []crypto.Hash, actual []crypto.Hash) {
	if expected == nil {
		expected = []crypto.Hash{}
	}
	if actual == nil {
		actual = []crypto.Hash{}
	}

	require.Equal(t, expected, actual, "Hashes do not match")
}

func unmarsalExpectedBlock(t *testing.T) expectedBlock {
	b, err := os.ReadFile("vectors/codec/expected_block.json")
	require.NoError(t, err)

	var unmarshaled expectedBlock
	err = json.Unmarshal(b, &unmarshaled)
	require.NoError(t, err)

	return unmarshaled
}

type Result struct {
	Ok    *string
	Error *string
}

func (r *Result) UnmarshalJSON(data []byte) error {
	var temp map[string]*json.RawMessage
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	if _, found := temp["ok"]; found {
		return nil
	}

	for key := range temp {
		r.Error = &key
		break
	}

	return nil
}

type expectedBlock struct {
	Header struct {
		Parent          string           `json:"parent"`
		ParentStateRoot string           `json:"parent_state_root"`
		ExtrinsicHash   string           `json:"extrinsic_hash"`
		Slot            jamtime.Timeslot `json:"slot"`
		EpochMark       struct {
			Entropy        string   `json:"entropy"`
			TicketsEntropy string   `json:"tickets_entropy"`
			Validators     []string `json:"validators"`
		} `json:"epoch_mark"`
		TicketsMark   *block.WinningTicketMarker `json:"tickets_mark"`
		OffendersMark []string                   `json:"offenders_mark"`
		AuthorIndex   uint16                     `json:"author_index"`
		EntropySource string                     `json:"entropy_source"`
		Seal          string                     `json:"seal"`
	} `json:"header"`
	Extrinsic struct {
		Tickets []struct {
			Attempt   uint8  `json:"attempt"`
			Signature string `json:"signature"`
		} `json:"tickets"`
		Preimages []struct {
			Requester uint32 `json:"requester"`
			Blob      string `json:"blob"`
		} `json:"preimages"`
		Guarantees []struct {
			Report struct {
				PackageSpec struct {
					Hash         string `json:"hash"`
					Length       uint32 `json:"length"`
					ErasureRoot  string `json:"erasure_root"`
					ExportsRoot  string `json:"exports_root"`
					ExportsCount uint16 `json:"exports_count"`
				} `json:"package_spec"`
				Context struct {
					Anchor           string           `json:"anchor"`
					StateRoot        string           `json:"state_root"`
					BeefyRoot        string           `json:"beefy_root"`
					LookupAnchor     string           `json:"lookup_anchor"`
					LookupAnchorSlot jamtime.Timeslot `json:"lookup_anchor_slot"`
					Prerequisites    []crypto.Hash    `json:"prerequisites"`
				} `json:"context"`
				CoreIndex         uint16        `json:"core_index"`
				AuthorizerHash    string        `json:"authorizer_hash"`
				AuthOutput        string        `json:"auth_output"`
				SegmentRootLookup []interface{} `json:"segment_root_lookup"`
				Results           []struct {
					ServiceId   block.ServiceId `json:"service_id"`
					CodeHash    string          `json:"code_hash"`
					PayloadHash string          `json:"payload_hash"`
					Gas         uint64          `json:"gas"`
					Result      Result          `json:"result"`
				} `json:"results"`
			} `json:"report"`
			Slot       jamtime.Timeslot `json:"slot"`
			Signatures []struct {
				ValidatorIndex uint16 `json:"validator_index"`
				Signature      string `json:"signature"`
			} `json:"signatures"`
		} `json:"guarantees"`
		Assurances []struct {
			Anchor         string `json:"anchor"`
			Bitfield       string `json:"bitfield"`
			ValidatorIndex uint16 `json:"validator_index"`
			Signature      string `json:"signature"`
		} `json:"assurances"`
		Disputes struct {
			Verdicts []struct {
				Target string `json:"target"`
				Age    uint32 `json:"age"`
				Votes  []struct {
					Vote      bool   `json:"vote"`
					Index     uint16 `json:"index"`
					Signature string `json:"signature"`
				} `json:"votes"`
			} `json:"verdicts"`
			Culprits []struct {
				Target    string `json:"target"`
				Key       string `json:"key"`
				Signature string `json:"signature"`
			} `json:"culprits"`
			Faults []struct {
				Target    string `json:"target"`
				Vote      bool   `json:"vote"`
				Key       string `json:"key"`
				Signature string `json:"signature"`
			} `json:"faults"`
		} `json:"disputes"`
	} `json:"extrinsic"`
}
