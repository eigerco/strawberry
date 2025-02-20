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
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
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
	ReportHash string      `json:"target"`
	EpochIndex int         `json:"age"`
	Judgements []Judgement `json:"votes"`
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
	Good      []string `json:"psi_g"`
	Bad       []string `json:"psi_b"`
	Wonky     []string `json:"psi_w"`
	Offenders []string `json:"psi_o"`
}

type ReportResult struct {
	ServiceID   int                `json:"service_id"`
	CodeHash    string             `json:"code_hash"`
	PayloadHash string             `json:"payload_hash"`
	Gas         uint64             `json:"gas"`
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
	Report  *Report `json:"Report"`
	Timeout int     `json:"Timeout"`
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

func mapPsi(psi Psi) state.Judgements {
	mapHashes := func(hashes []string) []crypto.Hash {
		mappedHashes := make([]crypto.Hash, len(hashes))
		for i, hash := range hashes {
			mappedHashes[i] = crypto.Hash(crypto.StringToHex(hash))
		}
		return mappedHashes
	}
	keys := make([]ed25519.PublicKey, 0)
	for _, offender := range psi.Offenders {
		keys = append(keys, ed25519.PublicKey(crypto.StringToHex(offender)))
	}
	return state.Judgements{
		BadWorkReports:      mapHashes(psi.Bad),
		GoodWorkReports:     mapHashes(psi.Good),
		WonkyWorkReports:    mapHashes(psi.Wonky),
		OffendingValidators: keys,
	}
}

func mapKey(kappa ValidatorKey) *crypto.ValidatorKey {
	return &crypto.ValidatorKey{
		Bandersnatch: crypto.BandersnatchPublicKey(crypto.StringToHex(kappa.Bandersnatch)),
		Ed25519:      ed25519.PublicKey(crypto.StringToHex(kappa.Ed25519)),
		Bls:          crypto.BlsKey(crypto.StringToHex(kappa.BLS)),
		Metadata:     crypto.MetadataKey(crypto.StringToHex(kappa.Metadata)),
	}
}

func mapJudgments(judgements []Judgement) [common.ValidatorsSuperMajority]block.Judgement {
	var mappedJudgements [common.ValidatorsSuperMajority]block.Judgement
	for i, judgement := range judgements {
		mappedJudgements[i] = block.Judgement{
			IsValid:        judgement.IsValid,
			ValidatorIndex: uint16(judgement.ValidatorIndex),
			Signature:      crypto.Ed25519Signature(crypto.StringToHex(judgement.Signature)),
		}
	}
	return mappedJudgements
}

func mapVerdicts(verdicts []Verdict) []block.Verdict {
	mappedVerdicts := make([]block.Verdict, len(verdicts))
	for i, verdict := range verdicts {
		mappedVerdicts[i] = block.Verdict{
			ReportHash: crypto.Hash(crypto.StringToHex(verdict.ReportHash)),
			EpochIndex: uint32(verdict.EpochIndex),
			Judgements: mapJudgments(verdict.Judgements),
		}
	}
	return mappedVerdicts
}

func mapCulprits(culprits []Culprit) []block.Culprit {
	mappedCulprits := make([]block.Culprit, len(culprits))
	for i, culprit := range culprits {
		mappedCulprits[i] = block.Culprit{
			ReportHash:                crypto.Hash(crypto.StringToHex(culprit.ReportHash)),
			ValidatorEd25519PublicKey: ed25519.PublicKey(crypto.StringToHex(culprit.ValidatorEd25519PublicKey)),
			Signature:                 crypto.Ed25519Signature(crypto.StringToHex(culprit.Signature)),
		}
	}
	return mappedCulprits
}

func mapFaults(faults []Fault) []block.Fault {
	mappedFaults := make([]block.Fault, len(faults))
	for i, fault := range faults {
		mappedFaults[i] = block.Fault{
			ReportHash:                crypto.Hash(crypto.StringToHex(fault.ReportHash)),
			IsValid:                   fault.IsValid,
			ValidatorEd25519PublicKey: ed25519.PublicKey(crypto.StringToHex(fault.ValidatorEd25519PublicKey)),
			Signature:                 crypto.Ed25519Signature(crypto.StringToHex(fault.Signature)),
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
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
			filePath := fmt.Sprintf("vectors/disputes/tiny/%s", file.Name())
			data, err := ReadJSONFile(filePath)
			require.NoError(t, err, "failed to read JSON file: %s", filePath)

			input := data.Input
			disputes := mapDisputes(input.Disputes)
			preState := state.State{}
			kappa := safrole.ValidatorsData{}
			pastJudgements := mapPsi(data.PreState.Psi)
			for i, key := range data.PreState.Kappa {
				kappa[i] = mapKey(key)
			}
			lambda := safrole.ValidatorsData{}
			for i, key := range data.PreState.Lambda {
				lambda[i] = mapKey(key)
			}
			preState.PastJudgements = pastJudgements
			preState.ValidatorState.CurrentValidators = kappa
			preState.ValidatorState.ArchivedValidators = lambda
			preState.TimeslotIndex = jamtime.Timeslot(data.PreState.Tau)

			postState := state.State{}
			kappa = safrole.ValidatorsData{}
			for i, key := range data.PostState.Kappa {
				kappa[i] = mapKey(key)
			}
			lambda = safrole.ValidatorsData{}
			for i, key := range data.PostState.Lambda {
				lambda[i] = mapKey(key)
			}
			postState.PastJudgements = mapPsi(data.PostState.Psi)
			postState.ValidatorState.CurrentValidators = kappa
			postState.ValidatorState.ArchivedValidators = lambda
			postState.TimeslotIndex = jamtime.Timeslot(data.PostState.Tau)

			newJudgements, err := statetransition.CalculateNewJudgements(preState.TimeslotIndex, disputes, preState.PastJudgements, preState.ValidatorState)
			if data.Output.Err != "" {
				require.Error(t, err)
				require.EqualError(t, err, strings.ReplaceAll(data.Output.Err, "_", " "))
			} else {
				require.NoError(t, err)
			}

			if len(data.Output.Ok.OffendersMark) > 0 {
				offendersMark := make([]ed25519.PublicKey, len(data.Output.Ok.OffendersMark))
				for i, offender := range data.Output.Ok.OffendersMark {
					offendersMark[i] = ed25519.PublicKey(crypto.StringToHex(offender))
				}
				require.ElementsMatch(t, offendersMark, newJudgements.OffendingValidators)
			}
			preState.PastJudgements = newJudgements

			for i, key := range preState.ValidatorState.CurrentValidators {
				require.EqualValues(t, key.Bandersnatch, postState.ValidatorState.CurrentValidators[i].Bandersnatch, "Bandersnatch keys are not equal")
				require.EqualValues(t, key.Ed25519, postState.ValidatorState.CurrentValidators[i].Ed25519, "Ed25519 keys are not equal")
				require.EqualValues(t, key.Bls, postState.ValidatorState.CurrentValidators[i].Bls)
				require.EqualValues(t, key.Metadata, postState.ValidatorState.CurrentValidators[i].Metadata)
			}
			require.ElementsMatch(t, preState.ValidatorState.CurrentValidators, postState.ValidatorState.CurrentValidators)
			require.ElementsMatch(t, preState.PastJudgements.BadWorkReports, postState.PastJudgements.BadWorkReports, "Mismatch in BadWorkReports")
			require.ElementsMatch(t, preState.PastJudgements.GoodWorkReports, postState.PastJudgements.GoodWorkReports, "Mismatch in GoodWorkReports")
			require.ElementsMatch(t, preState.PastJudgements.WonkyWorkReports, postState.PastJudgements.WonkyWorkReports, "Mismatch in WonkyWorkReports")
			require.ElementsMatch(t, preState.PastJudgements.OffendingValidators, postState.PastJudgements.OffendingValidators, "Mismatch in OffendingValidators")
			require.Equal(t, preState.TimeslotIndex, postState.TimeslotIndex, "Mismatch in TimeslotIndex")
		})
	}
}
