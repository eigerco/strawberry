//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const testVectorsPath = "vectors/codec"

func TestCodec(t *testing.T) {
	tests := []struct {
		name       string
		files      []string
		unmarshal  func([]byte) (any, error)
		comparator func(*testing.T, any, any)
		expected   func(*testing.T, string) any
	}{
		{
			name:  "DecodeBlock",
			files: []string{"block"},
			unmarshal: func(b []byte) (any, error) {
				var v block.Block
				err := jam.Unmarshal(b, &v)
				return v, err
			},
			comparator: func(t *testing.T, expected any, unmarshaled any) {
				expectedBlock := expected.(expectedBlock)
				unmarshaledBlock := unmarshaled.(block.Block)

				compareHeader(t, expectedBlock.Header, unmarshaledBlock.Header)
				compareExtrinsicFields(t, expectedBlock.Extrinsic, unmarshaledBlock.Extrinsic)
			},
			expected: func(t *testing.T, file string) any {
				return unmarshalExpected[expectedBlock](t, file)
			},
		},
		{
			name:  "DecodeHeader",
			files: []string{"header_0", "header_1"},
			unmarshal: func(b []byte) (any, error) {
				var v block.Header
				err := jam.Unmarshal(b, &v)
				return v, err
			},
			comparator: func(t *testing.T, expected any, unmarshaled any) {
				compareHeader(t, expected.(ExpectedHeader), unmarshaled.(block.Header))
			},
			expected: func(t *testing.T, file string) any {
				return unmarshalExpected[ExpectedHeader](t, file)
			},
		},
		{
			name:  "DecodeAssurances",
			files: []string{"assurances_extrinsic"},
			unmarshal: func(b []byte) (any, error) {
				var v block.AssurancesExtrinsic
				err := jam.Unmarshal(b, &v)
				return v, err
			},
			comparator: func(t *testing.T, expected any, unmarshaled any) {
				compareAssuranceFields(t, expected.([]ExpectedAssurances), unmarshaled.(block.AssurancesExtrinsic))
			},
			expected: func(t *testing.T, file string) any {
				return unmarshalExpected[[]ExpectedAssurances](t, file)
			},
		},
		{
			name:  "DecodeGuarantees",
			files: []string{"guarantees_extrinsic"},
			unmarshal: func(b []byte) (any, error) {
				var v block.GuaranteesExtrinsic
				err := jam.Unmarshal(b, &v)
				return v, err
			},
			comparator: func(t *testing.T, expected any, unmarshaled any) {
				compareGuaranteesFields(t, expected.([]ExpectedGuarantees), unmarshaled.(block.GuaranteesExtrinsic))
			},
			expected: func(t *testing.T, file string) any {
				return unmarshalExpected[[]ExpectedGuarantees](t, file)
			},
		},
		{
			name:  "DecodePreimages",
			files: []string{"preimages_extrinsic"},
			unmarshal: func(b []byte) (any, error) {
				var v block.PreimageExtrinsic
				err := jam.Unmarshal(b, &v)
				return v, err
			},
			comparator: func(t *testing.T, expected any, unmarshaled any) {
				comparePreimageFields(t, expected.([]ExpectedPreimages), unmarshaled.(block.PreimageExtrinsic))
			},
			expected: func(t *testing.T, file string) any {
				return unmarshalExpected[[]ExpectedPreimages](t, file)
			},
		},
		{
			name:  "DecodeTickets",
			files: []string{"tickets_extrinsic"},
			unmarshal: func(b []byte) (any, error) {
				var v []block.TicketProof
				err := jam.Unmarshal(b, &v)
				return v, err
			},
			comparator: func(t *testing.T, expected any, unmarshaled any) {
				compareTicketFields(t, expected.([]ExpectedTickets), unmarshaled.([]block.TicketProof))
			},
			expected: func(t *testing.T, file string) any {
				return unmarshalExpected[[]ExpectedTickets](t, file)
			},
		},
		{
			name:  "DecodeExtrinsic",
			files: []string{"extrinsic"},
			unmarshal: func(b []byte) (any, error) {
				var v block.Extrinsic
				err := jam.Unmarshal(b, &v)
				return v, err
			},
			comparator: func(t *testing.T, expected any, unmarshaled any) {
				compareExtrinsicFields(t, expected.(ExpectedExtrinsic), unmarshaled.(block.Extrinsic))
			},
			expected: func(t *testing.T, file string) any {
				return unmarshalExpected[ExpectedExtrinsic](t, file)
			},
		},
		{
			name:  "DecodeDisputes",
			files: []string{"disputes_extrinsic"},
			unmarshal: func(b []byte) (any, error) {
				var v block.DisputeExtrinsic
				err := jam.Unmarshal(b, &v)
				return v, err
			},
			comparator: func(t *testing.T, expected any, unmarshaled any) {
				compareDisputeFields(t, expected.(ExpectedDisputes), unmarshaled.(block.DisputeExtrinsic))
			},
			expected: func(t *testing.T, file string) any {
				return unmarshalExpected[ExpectedDisputes](t, file)
			},
		},
		{
			name:  "DecodeRefineContext",
			files: []string{"refine_context"},
			unmarshal: func(b []byte) (any, error) {
				var v block.RefinementContext
				err := jam.Unmarshal(b, &v)
				return v, err
			},
			comparator: func(t *testing.T, expected any, unmarshaled any) {
				compareRefinementContextFields(t, expected.(ExpectedRefinementContext), unmarshaled.(block.RefinementContext))
			},
			expected: func(t *testing.T, file string) any {
				return unmarshalExpected[ExpectedRefinementContext](t, file)
			},
		},
		{
			name:  "DecodeWorkItem",
			files: []string{"work_item"},
			unmarshal: func(b []byte) (any, error) {
				var v work.Item
				err := jam.Unmarshal(b, &v)
				return v, err
			},
			comparator: func(t *testing.T, expected any, unmarshaled any) {
				compareWorkItemFields(t, expected.(ExpectedWorkItem), unmarshaled.(work.Item))
			},
			expected: func(t *testing.T, file string) any {
				return unmarshalExpected[ExpectedWorkItem](t, file)
			},
		},
		{
			name:  "DecodeWorkPackage",
			files: []string{"work_package"},
			unmarshal: func(b []byte) (any, error) {
				var v work.Package
				err := jam.Unmarshal(b, &v)
				return v, err
			},
			comparator: func(t *testing.T, expected any, unmarshaled any) {
				compareWorkPackageFields(t, expected.(ExpectedWorkPackage), unmarshaled.(work.Package))
			},
			expected: func(t *testing.T, file string) any {
				return unmarshalExpected[ExpectedWorkPackage](t, file)
			},
		},
		{
			name:  "DecodeWorkReport",
			files: []string{"work_report"},
			unmarshal: func(b []byte) (any, error) {
				var v block.WorkReport
				err := jam.Unmarshal(b, &v)
				return v, err
			},
			comparator: func(t *testing.T, expected any, unmarshaled any) {
				compareWorkReportFields(t, expected.(ExpectedWorkReport), unmarshaled.(block.WorkReport))
			},
			expected: func(t *testing.T, file string) any {
				return unmarshalExpected[ExpectedWorkReport](t, file)
			},
		},
		{
			name:  "DecodeWorkResult",
			files: []string{"work_result_0", "work_result_1"},
			unmarshal: func(b []byte) (any, error) {
				var v block.WorkResult
				err := jam.Unmarshal(b, &v)
				return v, err
			},
			comparator: func(t *testing.T, expected any, unmarshaled any) {
				compareWorkResultFields(t, expected.(ExpectedWorkResult), unmarshaled.(block.WorkResult))
			},
			expected: func(t *testing.T, file string) any {
				return unmarshalExpected[ExpectedWorkResult](t, file)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, file := range tt.files {
				binFile := fmt.Sprintf("%s/%s.bin", testVectorsPath, file)

				b, err := os.ReadFile(binFile)
				require.NoError(t, err)

				unmarshaled, err := tt.unmarshal(b)
				require.NoError(t, err)

				expected := tt.expected(t, file)

				tt.comparator(t, expected, unmarshaled)
			}
		})
	}
}

func compareHeader(t *testing.T, expected ExpectedHeader, actual block.Header) {
	require.Equal(t, expected.Parent, toHex(actual.ParentHash))
	require.Equal(t, expected.ParentStateRoot, toHex(actual.PriorStateRoot))
	require.Equal(t, expected.ExtrinsicHash, toHex(actual.ExtrinsicHash))
	require.Equal(t, expected.Slot, actual.TimeSlotIndex)

	if expected.EpochMark == nil {
		require.Nil(t, actual.EpochMarker)
	} else {
		require.Equal(t, expected.EpochMark.Entropy, toHex(actual.EpochMarker.Entropy))
		require.Equal(t, expected.EpochMark.TicketsEntropy, toHex(actual.EpochMarker.TicketsEntropy))

		for i := range expected.EpochMark.Validators {
			require.Equal(t, expected.EpochMark.Validators[i].Bandersnatch, toHex(actual.EpochMarker.Keys[i].Bandersnatch))
			require.Equal(t, expected.EpochMark.Validators[i].Ed25519, toHex(actual.EpochMarker.Keys[i].Ed25519))
		}
	}

	if expected.TicketsMark == nil {
		require.Nil(t, actual.WinningTicketsMarker)
	} else {
		for i := range expected.TicketsMark {
			require.Equal(t, expected.TicketsMark[i].Attempt, actual.WinningTicketsMarker[i].EntryIndex)
			require.Equal(t, expected.TicketsMark[i].Id, toHex(actual.WinningTicketsMarker[i].Identifier))
		}
	}

	for i := range expected.OffendersMark {
		require.Equal(t, expected.OffendersMark[i], toHex(actual.OffendersMarkers[i]))
	}

	require.Equal(t, expected.AuthorIndex, actual.BlockAuthorIndex)
	require.Equal(t, expected.EntropySource, toHex(actual.VRFSignature))
	require.Equal(t, expected.Seal, toHex(actual.BlockSealSignature))
}

func compareTicketFields(t *testing.T, expected []ExpectedTickets, actual []block.TicketProof) {
	for i := range expected {
		require.Equal(t, expected[i].Attempt, actual[i].EntryIndex)
		require.Equal(t, expected[i].Signature, toHex(actual[i].Proof))
	}
}

func comparePreimageFields(t *testing.T, expected []ExpectedPreimages, actual block.PreimageExtrinsic) {
	for i := range expected {
		require.Equal(t, expected[i].Requester, actual[i].ServiceIndex)
		require.Equal(t, expected[i].Blob, toHex(actual[i].Data))
	}
}

func compareAssuranceFields(t *testing.T, expected []ExpectedAssurances, actual block.AssurancesExtrinsic) {
	for i := range expected {
		require.Equal(t, expected[i].Anchor, toHex(actual[i].Anchor))
		require.Equal(t, expected[i].Bitfield, toHex(actual[i].Bitfield))
		require.Equal(t, expected[i].ValidatorIndex, actual[i].ValidatorIndex)
		require.Equal(t, expected[i].Signature, toHex(actual[i].Signature))
	}
}

func compareRefinementContextFields(t *testing.T, expected ExpectedRefinementContext, actual block.RefinementContext) {
	require.Equal(t, expected.Anchor, toHex(actual.Anchor.HeaderHash))
	require.Equal(t, expected.StateRoot, toHex(actual.Anchor.PosteriorStateRoot))
	require.Equal(t, expected.BeefyRoot, toHex(actual.Anchor.PosteriorBeefyRoot))
	require.Equal(t, expected.LookupAnchor, toHex(actual.LookupAnchor.HeaderHash))
	require.Equal(t, expected.LookupAnchorSlot, actual.LookupAnchor.Timeslot)
	assertHashSlicesEqual(t, expected.Prerequisites, actual.PrerequisiteWorkPackage)
}

func compareWorkResultFields(t *testing.T, expected ExpectedWorkResult, actual block.WorkResult) {
	require.Equal(t, expected.ServiceId, actual.ServiceId)
	require.Equal(t, expected.CodeHash, toHex(actual.ServiceHashCode))
	require.Equal(t, expected.PayloadHash, toHex(actual.PayloadHash))
	require.Equal(t, expected.AccumulateGas, actual.GasPrioritizationRatio)
	if expected.Result.Ok != nil {
		require.Equal(t, *expected.Result.Ok, toHex(actual.Output.Inner))
	}
	if expected.Result.Error != nil {
		expectedWorkResult, found := toWorkResultErrorMap[*expected.Result.Error]
		require.True(t, found)
		require.Equal(t, expectedWorkResult, actual.Output.Inner)
	}

	require.Equal(t, expected.RefineLoad.GasUsed, actual.GasUsed)
	require.Equal(t, expected.RefineLoad.Imports, actual.ImportsCount)
	require.Equal(t, expected.RefineLoad.ExtrinsicCount, actual.ExtrinsicCount)
	require.Equal(t, expected.RefineLoad.ExtrinsicSize, actual.ExtrinsicSize)
	require.Equal(t, expected.RefineLoad.Exports, actual.ExportsCount)
}

func compareWorkReportFields(t *testing.T, expected ExpectedWorkReport, actual block.WorkReport) {
	require.Equal(t, expected.PackageSpec.Hash, toHex(actual.WorkPackageSpecification.WorkPackageHash))
	require.Equal(t, expected.PackageSpec.Length, actual.WorkPackageSpecification.AuditableWorkBundleLength)
	require.Equal(t, expected.PackageSpec.ErasureRoot, toHex(actual.WorkPackageSpecification.ErasureRoot))
	require.Equal(t, expected.PackageSpec.ExportsRoot, toHex(actual.WorkPackageSpecification.SegmentRoot))
	require.Equal(t, expected.PackageSpec.ExportsCount, actual.WorkPackageSpecification.SegmentCount)

	compareRefinementContextFields(t, expected.Context, actual.RefinementContext)

	require.Equal(t, expected.CoreIndex, actual.CoreIndex)
	require.Equal(t, expected.AuthorizerHash, toHex(actual.AuthorizerHash))
	require.Equal(t, expected.AuthOutput, toHex(actual.Output))

	for j := range expected.Results {
		compareWorkResultFields(t, expected.Results[j], actual.WorkResults[j])
	}

	require.Equal(t, expected.AuthGasUsed, actual.AuthGasUsed)
}

func compareGuaranteesFields(t *testing.T, expected []ExpectedGuarantees, actual block.GuaranteesExtrinsic) {
	for i := range expected {
		compareWorkReportFields(t, expected[i].Report, actual.Guarantees[i].WorkReport)

		require.Equal(t, expected[i].Slot, actual.Guarantees[i].Timeslot)

		for j := range expected[i].Signatures {
			require.Equal(t, expected[i].Signatures[j].ValidatorIndex, actual.Guarantees[i].Credentials[j].ValidatorIndex)
			require.Equal(t, expected[i].Signatures[j].Signature, toHex(actual.Guarantees[i].Credentials[j].Signature))
		}
	}
}

func compareDisputeFields(t *testing.T, expected ExpectedDisputes, actual block.DisputeExtrinsic) {
	for i := range expected.Verdicts {
		require.Equal(t, expected.Verdicts[i].Target, toHex(actual.Verdicts[i].ReportHash))
		require.Equal(t, expected.Verdicts[i].Age, actual.Verdicts[i].EpochIndex)
		for j := range expected.Verdicts[i].Votes {
			require.Equal(t, expected.Verdicts[i].Votes[j].Vote, actual.Verdicts[i].Judgements[j].IsValid)
			require.Equal(t, expected.Verdicts[i].Votes[j].Index, actual.Verdicts[i].Judgements[j].ValidatorIndex)
			require.Equal(t, expected.Verdicts[i].Votes[j].Signature, toHex(actual.Verdicts[i].Judgements[j].Signature))
		}
	}

	for i := range expected.Culprits {
		require.Equal(t, expected.Culprits[i].Target, toHex(actual.Culprits[i].ReportHash))
		require.Equal(t, expected.Culprits[i].Key, toHex(actual.Culprits[i].ValidatorEd25519PublicKey))
		require.Equal(t, expected.Culprits[i].Signature, toHex(actual.Culprits[i].Signature))
	}

	for i := range expected.Faults {
		require.Equal(t, expected.Faults[i].Target, toHex(actual.Faults[i].ReportHash))
		require.Equal(t, expected.Faults[i].Vote, actual.Faults[i].IsValid)
		require.Equal(t, expected.Faults[i].Key, toHex(actual.Faults[i].ValidatorEd25519PublicKey))
		require.Equal(t, expected.Faults[i].Signature, toHex(actual.Faults[i].Signature))
	}
}

func compareExtrinsicFields(t *testing.T, expected ExpectedExtrinsic, actual block.Extrinsic) {
	compareTicketFields(t, expected.Tickets, actual.ET.TicketProofs)
	comparePreimageFields(t, expected.Preimages, actual.EP)
	compareAssuranceFields(t, expected.Assurances, actual.EA)
	compareGuaranteesFields(t, expected.Guarantees, actual.EG)
	compareDisputeFields(t, expected.Disputes, actual.ED)
}

func compareWorkItemFields(t *testing.T, expected ExpectedWorkItem, actual work.Item) {
	require.Equal(t, expected.Service, uint32(actual.ServiceId))
	require.Equal(t, expected.CodeHash, toHex(actual.CodeHash))
	require.Equal(t, expected.Payload, toHex(actual.Payload))
	require.Equal(t, expected.RefineGasLimit, actual.GasLimitRefine)
	require.Equal(t, expected.AccumulateGasLimit, actual.GasLimitAccumulate)

	for i := range expected.ImportSegments {
		require.Equal(t, expected.ImportSegments[i].TreeRoot, toHex(actual.ImportedSegments[i].Hash))
		require.Equal(t, expected.ImportSegments[i].Index, actual.ImportedSegments[i].Index)
	}

	for i := range expected.Extrinsic {
		require.Equal(t, expected.Extrinsic[i].Hash, toHex(actual.Extrinsics[i].Hash))
		require.Equal(t, expected.Extrinsic[i].Len, actual.Extrinsics[i].Length)
	}

	require.Equal(t, expected.ExportCount, actual.ExportedSegments)
}

func compareWorkPackageFields(t *testing.T, expected ExpectedWorkPackage, actual work.Package) {
	require.Equal(t, expected.Authorization, toHex(actual.AuthorizationToken))
	require.Equal(t, expected.AuthCodeHost, actual.AuthorizerService)
	require.Equal(t, expected.Authorizer.CodeHash, toHex(actual.AuthCodeHash))
	require.Equal(t, expected.Authorizer.Params, toHex(actual.Parameterization))
	compareRefinementContextFields(t, expected.Context, actual.Context)

	for i := range expected.Items {
		compareWorkItemFields(t, expected.Items[i], actual.WorkItems[i])
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

func unmarshalExpected[T any](t *testing.T, fileName string) T {
	b, err := os.ReadFile(fmt.Sprintf("%s/%s.json", testVectorsPath, fileName))
	require.NoError(t, err)

	var result T
	err = json.Unmarshal(b, &result)
	require.NoError(t, err)

	return result
}

var toWorkResultErrorMap = map[string]block.WorkResultError{
	"out-of-gas":    block.OutOfGas,
	"panic":         block.UnexpectedTermination,
	"bad-code":      block.CodeNotAvailable,
	"code-oversize": block.CodeTooLarge,
}

type expectedBlock struct {
	Header    ExpectedHeader    `json:"header"`
	Extrinsic ExpectedExtrinsic `json:"extrinsic"`
}

type ExpectedHeader struct {
	Parent          string           `json:"parent"`
	ParentStateRoot string           `json:"parent_state_root"`
	ExtrinsicHash   string           `json:"extrinsic_hash"`
	Slot            jamtime.Timeslot `json:"slot"`
	EpochMark       *struct {
		Entropy        string `json:"entropy"`
		TicketsEntropy string `json:"tickets_entropy"`
		Validators     []struct {
			Bandersnatch string `json:"bandersnatch"`
			Ed25519      string `json:"ed25519"`
		} `json:"validators"`
	} `json:"epoch_mark"`
	TicketsMark []struct {
		Id      string `json:"id"`
		Attempt uint8  `json:"attempt"`
	} `json:"tickets_mark"`
	OffendersMark []string `json:"offenders_mark"`
	AuthorIndex   uint16   `json:"author_index"`
	EntropySource string   `json:"entropy_source"`
	Seal          string   `json:"seal"`
}

type ExpectedExtrinsic struct {
	Tickets    []ExpectedTickets    `json:"tickets"`
	Preimages  []ExpectedPreimages  `json:"preimages"`
	Guarantees []ExpectedGuarantees `json:"guarantees"`
	Assurances []ExpectedAssurances `json:"assurances"`
	Disputes   ExpectedDisputes     `json:"disputes"`
}

type ExpectedTickets struct {
	Attempt   uint8  `json:"attempt"`
	Signature string `json:"signature"`
}

type ExpectedPreimages struct {
	Requester uint32 `json:"requester"`
	Blob      string `json:"blob"`
}

type ExpectedGuarantees struct {
	Report     ExpectedWorkReport `json:"report"`
	Slot       jamtime.Timeslot   `json:"slot"`
	Signatures []struct {
		ValidatorIndex uint16 `json:"validator_index"`
		Signature      string `json:"signature"`
	} `json:"signatures"`
}

type ExpectedWorkReport struct {
	PackageSpec struct {
		Hash         string `json:"hash"`
		Length       uint32 `json:"length"`
		ErasureRoot  string `json:"erasure_root"`
		ExportsRoot  string `json:"exports_root"`
		ExportsCount uint16 `json:"exports_count"`
	} `json:"package_spec"`
	Context           ExpectedRefinementContext `json:"context"`
	CoreIndex         uint16                    `json:"core_index"`
	AuthorizerHash    string                    `json:"authorizer_hash"`
	AuthOutput        string                    `json:"auth_output"`
	SegmentRootLookup []interface{}             `json:"segment_root_lookup"`
	Results           []ExpectedWorkResult      `json:"results"`
	AuthGasUsed       uint                      `json:"auth_gas_used"`
}

type ExpectedWorkResult struct {
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

type ExpectedRefinementContext struct {
	Anchor           string           `json:"anchor"`
	StateRoot        string           `json:"state_root"`
	BeefyRoot        string           `json:"beefy_root"`
	LookupAnchor     string           `json:"lookup_anchor"`
	LookupAnchorSlot jamtime.Timeslot `json:"lookup_anchor_slot"`
	Prerequisites    []crypto.Hash    `json:"prerequisites"`
}

type ExpectedAssurances struct {
	Anchor         string `json:"anchor"`
	Bitfield       string `json:"bitfield"`
	ValidatorIndex uint16 `json:"validator_index"`
	Signature      string `json:"signature"`
}

type ExpectedDisputes struct {
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

type ExpectedWorkItem struct {
	Service            uint32 `json:"service"`
	CodeHash           string `json:"code_hash"`
	Payload            string `json:"payload"`
	RefineGasLimit     uint64 `json:"refine_gas_limit"`
	AccumulateGasLimit uint64 `json:"accumulate_gas_limit"`
	ImportSegments     []struct {
		TreeRoot string `json:"tree_root"`
		Index    uint16 `json:"index"`
	} `json:"import_segments"`
	Extrinsic []struct {
		Hash string `json:"hash"`
		Len  uint32 `json:"len"`
	} `json:"extrinsic"`
	ExportCount uint16 `json:"export_count"`
}

type ExpectedWorkPackage struct {
	Authorization string `json:"authorization"`
	AuthCodeHost  uint32 `json:"auth_code_host"`
	Authorizer    struct {
		CodeHash string `json:"code_hash"`
		Params   string `json:"params"`
	} `json:"authorizer"`
	Context ExpectedRefinementContext `json:"context"`
	Items   []ExpectedWorkItem        `json:"items"`
}
