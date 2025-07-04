//go:build integration

package integration

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/disputing"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/stretchr/testify/require"
)

func ReadJSONFile(filename string) (*JSONData, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var data JSONData
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return &data, nil
}

type Judgement struct {
	IsValid        bool   `json:"vote"`
	ValidatorIndex int    `json:"index"`
	Signature      string `json:"signature"`
}

type Verdict struct {
	ReportHash string        `json:"target"`
	EpochIndex jamtime.Epoch `json:"age"`
	Judgements []Judgement   `json:"votes"`
}

type Culprit struct {
	ReportHash                string `json:"target"`
	ValidatorEd25519PublicKey string `json:"key"`
	Signature                 string `json:"signature"`
}

type Fault struct {
	ReportHash                string `json:"target"`
	IsValid                   bool   `json:"vote"`
	ValidatorEd25519PublicKey string `json:"key"`
	Signature                 string `json:"signature"`
}

type Disputes struct {
	Verdicts []Verdict `json:"verdicts"`
	Culprits []Culprit `json:"culprits"`
	Faults   []Fault   `json:"faults"`
}

type Psi struct {
	Good      []string `json:"good"`
	Bad       []string `json:"bad"`
	Wonky     []string `json:"wonky"`
	Offenders []string `json:"offenders"`
}

type ReportResult struct {
	ServiceID   int                `json:"service_id"`
	CodeHash    string             `json:"code_hash"`
	PayloadHash string             `json:"payload_hash"`
	Gas         uint64             `json:"accumulate_gas"`
	Result      ReportResultOutput `json:"result"`
}

type ReportResultOutput struct {
	Ok string
}

type Context struct {
	Anchor           string   `json:"anchor"`
	StateRoot        string   `json:"state_root"`
	BeefyRoot        string   `json:"beefy_root"`
	LookupAnchor     string   `json:"lookup_anchor"`
	LookupAnchorSlot int      `json:"lookup_anchor_slot"`
	Prerequisites    []string `json:"prerequisites"`
}

type PackageSpec struct {
	Hash         string `json:"hash"`
	Length       uint32 `json:"length"`
	ErasureRoot  string `json:"erasure_root"`
	ExportsRoot  string `json:"exports_root"`
	ExportsCount uint16 `json:"exports_count"`
}

type Report struct {
	PackageSpec       PackageSpec       `json:"package_spec"`
	Context           Context           `json:"context"`
	CoreIndex         uint16            `json:"core_index"`
	AuthorizerHash    string            `json:"authorizer_hash"`
	AuthOutput        string            `json:"auth_output"`
	SegmentRootLookup []SegmentRootPair `json:"segment_root_lookup"`
	Results           []ReportResult    `json:"results"`
}

type SegmentRootPair struct {
	Key string `json:"key"`
	Val string `json:"val"`
}

type Rho struct {
	Report  Report `json:"Report"`
	Timeout int    `json:"Timeout"`
}

type ValidatorKey struct {
	Bandersnatch string `json:"bandersnatch"`
	Ed25519      string `json:"ed25519"`
	BLS          string `json:"bls"`
	Metadata     string `json:"metadata"`
}

type OutputOk struct {
	OffendersMark []string `json:"offenders_mark,omitempty"`
}

type Output struct {
	Ok  OutputOk `json:"ok"`
	Err string   `json:"err"`
}

type State struct {
	Psi    Psi            `json:"psi"`
	Rho    []Rho          `json:"rho"`
	Tau    int            `json:"tau"`
	Kappa  []ValidatorKey `json:"kappa"`
	Lambda []ValidatorKey `json:"lambda"`
}

type Input struct {
	Disputes Disputes `json:"disputes"`
}

type PostState struct {
	Psi    Psi            `json:"psi"`
	Rho    []Rho          `json:"rho"`
	Tau    int            `json:"tau"`
	Kappa  []ValidatorKey `json:"kappa"`
	Lambda []ValidatorKey `json:"lambda"`
}

type JSONData struct {
	Input     Input     `json:"input"`
	PreState  State     `json:"pre_state"`
	Output    Output    `json:"output"`
	PostState PostState `json:"post_state"`
}

func mapRho(rhos []Rho) state.CoreAssignments {
	assignments := state.CoreAssignments{}
	for i, rho := range rhos {
		// Check if this is a null/empty rho (all fields are zero values)
		if rho.Timeout == 0 && len(rho.Report.PackageSpec.Hash) == 0 {
			assignments[i] = nil
		} else {
			r := &state.Assignment{
				WorkReport: mapReport(rho.Report),
				Time:       jamtime.Timeslot(rho.Timeout),
			}
			assignments[i] = r
		}
	}
	return assignments
}

func mapPsi(psi Psi) state.Judgements {
	mapHashes := func(hashes []string) []crypto.Hash {
		mappedHashes := make([]crypto.Hash, len(hashes))
		for i, hash := range hashes {
			mappedHashes[i] = crypto.Hash(mustStringToHex(hash))
		}
		return mappedHashes
	}
	keys := make([]ed25519.PublicKey, 0)
	for _, offender := range psi.Offenders {
		keys = append(keys, ed25519.PublicKey(mustStringToHex(offender)))
	}
	return state.Judgements{
		BadWorkReports:      mapHashes(psi.Bad),
		GoodWorkReports:     mapHashes(psi.Good),
		WonkyWorkReports:    mapHashes(psi.Wonky),
		OffendingValidators: keys,
	}
}

func mapKey(kappa ValidatorKey) crypto.ValidatorKey {
	return crypto.ValidatorKey{
		Bandersnatch: crypto.BandersnatchPublicKey(mustStringToHex(kappa.Bandersnatch)),
		Ed25519:      ed25519.PublicKey(mustStringToHex(kappa.Ed25519)),
		Bls:          crypto.BlsKey(mustStringToHex(kappa.BLS)),
		Metadata:     crypto.MetadataKey(mustStringToHex(kappa.Metadata)),
	}
}

func mapJudgments(judgements []Judgement) [common.ValidatorsSuperMajority]block.Judgement {
	var mappedJudgements [common.ValidatorsSuperMajority]block.Judgement
	for i, judgement := range judgements {
		mappedJudgements[i] = block.Judgement{
			IsValid:        judgement.IsValid,
			ValidatorIndex: uint16(judgement.ValidatorIndex),
			Signature:      crypto.Ed25519Signature(mustStringToHex(judgement.Signature)),
		}
	}
	return mappedJudgements
}

func mapVerdicts(verdicts []Verdict) []block.Verdict {
	mappedVerdicts := make([]block.Verdict, len(verdicts))
	for i, verdict := range verdicts {
		mappedVerdicts[i] = block.Verdict{
			ReportHash: crypto.Hash(mustStringToHex(verdict.ReportHash)),
			EpochIndex: verdict.EpochIndex,
			Judgements: mapJudgments(verdict.Judgements),
		}
	}
	return mappedVerdicts
}

func mapCulprits(culprits []Culprit) []block.Culprit {
	mappedCulprits := make([]block.Culprit, len(culprits))
	for i, culprit := range culprits {
		mappedCulprits[i] = block.Culprit{
			ReportHash:                crypto.Hash(mustStringToHex(culprit.ReportHash)),
			ValidatorEd25519PublicKey: ed25519.PublicKey(mustStringToHex(culprit.ValidatorEd25519PublicKey)),
			Signature:                 crypto.Ed25519Signature(mustStringToHex(culprit.Signature)),
		}
	}
	return mappedCulprits
}

func mapFaults(faults []Fault) []block.Fault {
	mappedFaults := make([]block.Fault, len(faults))
	for i, fault := range faults {
		mappedFaults[i] = block.Fault{
			ReportHash:                crypto.Hash(mustStringToHex(fault.ReportHash)),
			IsValid:                   fault.IsValid,
			ValidatorEd25519PublicKey: ed25519.PublicKey(mustStringToHex(fault.ValidatorEd25519PublicKey)),
			Signature:                 crypto.Ed25519Signature(mustStringToHex(fault.Signature)),
		}
	}
	return mappedFaults
}

func mapDisputes(disputes Disputes) block.DisputeExtrinsic {
	return block.DisputeExtrinsic{
		Verdicts: mapVerdicts(disputes.Verdicts),
		Culprits: mapCulprits(disputes.Culprits),
		Faults:   mapFaults(disputes.Faults),
	}
}

func TestDisputes(t *testing.T) {
	files, err := os.ReadDir("vectors/disputes/tiny")
	require.NoError(t, err, "failed to read tiny directory")

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), "il_assignments-1.json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
			filePath := fmt.Sprintf("vectors/disputes/tiny/%s", file.Name())
			data, err := ReadJSONFile(filePath)
			require.NoError(t, err, "failed to read JSON file: %s", filePath)

			input := data.Input
			disputes := mapDisputes(input.Disputes)
			preState := state.State{}
			pastJudgements := mapPsi(data.PreState.Psi)
			kappa := safrole.ValidatorsData{}
			lambda := safrole.ValidatorsData{}
			for i, key := range data.PreState.Lambda {
				lambda[i] = mapKey(key)
			}
			for i, key := range data.PreState.Kappa {
				kappa[i] = mapKey(key)
			}
			preState.PastJudgements = pastJudgements
			preStateCoreAssignmetns := mapRho(data.PreState.Rho)
			preState.ValidatorState.CurrentValidators = kappa
			preState.ValidatorState.ArchivedValidators = lambda
			preState.TimeslotIndex = jamtime.Timeslot(data.PreState.Tau)

			expectedState := state.State{}
			kappa = safrole.ValidatorsData{}
			for i, key := range data.PostState.Kappa {
				kappa[i] = mapKey(key)
			}
			lambda = safrole.ValidatorsData{}
			for i, key := range data.PostState.Lambda {
				lambda[i] = mapKey(key)
			}
			expectedState.PastJudgements = mapPsi(data.PostState.Psi)
			expectedState.CoreAssignments = mapRho(data.PostState.Rho)
			expectedState.ValidatorState.CurrentValidators = kappa
			expectedState.ValidatorState.ArchivedValidators = lambda
			expectedState.TimeslotIndex = jamtime.Timeslot(data.PostState.Tau)

			newJudgements, err := disputing.ValidateDisputesExtrinsicAndProduceJudgements(preState.TimeslotIndex, disputes, preState.ValidatorState, preState.PastJudgements)
			if data.Output.Err != "" {
				require.Error(t, err)
				require.EqualError(t, err, strings.ReplaceAll(data.Output.Err, "_", " "))
			} else {
				require.NoError(t, err)
				// Manually assign to produce a "new state" since we are not using the full UpdateState func
				preState.PastJudgements = newJudgements
			}

			// If we are supposed to have offenders according to the test vector
			if len(data.Output.Ok.OffendersMark) > 0 {
				offendersMark := make([]ed25519.PublicKey, len(data.Output.Ok.OffendersMark))
				for i, offender := range data.Output.Ok.OffendersMark {
					offendersMark[i] = ed25519.PublicKey(mustStringToHex(offender))
				}
				require.ElementsMatch(t, offendersMark, newJudgements.OffendingValidators)
			}

			newCoreAssignments := disputing.CalculateIntermediateCoreAssignmentsFromExtrinsics(disputes, preStateCoreAssignmetns)
			// Manually assign to produce a "new state" since we are not using the full UpdateState func
			preState.CoreAssignments = newCoreAssignments

			require.ElementsMatch(t, preState.CoreAssignments, expectedState.CoreAssignments)
			require.ElementsMatch(t, preState.ValidatorState.CurrentValidators, expectedState.ValidatorState.CurrentValidators)
			require.ElementsMatch(t, preState.ValidatorState.ArchivedValidators, expectedState.ValidatorState.ArchivedValidators)
			require.ElementsMatch(t, preState.PastJudgements.BadWorkReports, expectedState.PastJudgements.BadWorkReports, "Mismatch in BadWorkReports")
			require.ElementsMatch(t, preState.PastJudgements.GoodWorkReports, expectedState.PastJudgements.GoodWorkReports, "Mismatch in GoodWorkReports")
			require.ElementsMatch(t, preState.PastJudgements.WonkyWorkReports, expectedState.PastJudgements.WonkyWorkReports, "Mismatch in WonkyWorkReports")
			require.ElementsMatch(t, preState.PastJudgements.OffendingValidators, expectedState.PastJudgements.OffendingValidators, "Mismatch in OffendingValidators")
			require.Equal(t, preState.TimeslotIndex, expectedState.TimeslotIndex, "Mismatch in TimeslotIndex")
		})
	}
}
