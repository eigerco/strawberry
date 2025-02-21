//go:build integration

package integration

import (
	"embed"
	"encoding/json"
	"io"
	"path"
	"strings"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed vectors/assurances
var assurancestestvectors embed.FS

type AssurancesJSONData struct {
	Input     AssurancesInput  `json:"input"`
	PreState  AssurancesState  `json:"pre_state"`
	Output    AssurancesOutput `json:"output"`
	PostState AssurancesState  `json:"post_state"`
}

type AssurancesInput struct {
	Assurances []Assurance      `json:"assurances"`
	Slot       jamtime.Timeslot `json:"slot"`
	Parent     string           `json:"parent"`
}

func mustStringToHex(s string) []byte {
	bytes, err := crypto.StringToHex(s)
	if err != nil {
		panic(err)
	}
	return bytes
}

func mapBlock(i AssurancesInput) block.Block {
	return block.Block{
		Header: block.Header{
			ParentHash:    mapHash(i.Parent),
			TimeSlotIndex: i.Slot,
		},
		Extrinsic: block.Extrinsic{
			EA: mapSlice(i.Assurances, func(a Assurance) block.Assurance {
				return block.Assurance{
					Anchor:         mapHash(a.Anchor),
					Bitfield:       [block.AvailBitfieldBytes]byte(mustStringToHex(a.Bitfield)),
					ValidatorIndex: a.ValidatorIndex,
					Signature:      crypto.Ed25519Signature(mustStringToHex(a.Signature)),
				}
			}),
		},
	}
}

type Assurance struct {
	Anchor         string `json:"anchor"`
	Bitfield       string `json:"bitfield"`
	ValidatorIndex uint16 `json:"validator_index"`
	Signature      string `json:"signature"`
}

type AssurancesState struct {
	AvailAssignments []*Assignment  `json:"avail_assignments"`
	CurrValidators   []ValidatorKey `json:"curr_validators"`
}

type Assignment struct {
	Report  *Report          `json:"report"`
	Timeout jamtime.Timeslot `json:"timeout"`
}

type AssurancesOutput struct {
	Err string `json:"err"`
	Ok  struct {
		Reported []*Report `json:"reported"` // ??
	} `json:"ok"`
}

func mapAssurancesState(s AssurancesState) state.State {
	return state.State{
		CoreAssignments: mapCoreAssignments(s.AvailAssignments),
		ValidatorState: validator.ValidatorState{
			CurrentValidators: mapCurrValidators(s.CurrValidators),
		},
	}
}

func mapCoreAssignments(availAssignments []*Assignment) state.CoreAssignments {
	assignments := mapSlice(availAssignments, func(a *Assignment) *state.Assignment {
		if a == nil {
			return nil
		}
		return &state.Assignment{
			WorkReport: mapReport(a.Report),
			Time:       a.Timeout,
		}
	})
	assignmentsArray := make([]*state.Assignment, common.TotalNumberOfCores)
	copy(assignmentsArray, assignments)
	return state.CoreAssignments(assignmentsArray)
}

func mapCurrValidators(currValidators []ValidatorKey) safrole.ValidatorsData {
	validators := mapSlice(currValidators, mapKey)
	validatorsArray := make([]*crypto.ValidatorKey, common.NumberOfValidators)
	copy(validatorsArray, validators)
	return safrole.ValidatorsData(validatorsArray)
}

func mapSlice[T1, T2 any](s1 []T1, fn func(T1) T2) (s2 []T2) {
	for _, s := range s1 {
		s2 = append(s2, fn(s))
	}
	return
}

func mapReport(r *Report) *block.WorkReport {
	if r == nil {
		return nil
	}
	segmentRootLookup := make(map[crypto.Hash]crypto.Hash)
	for _, pair := range r.SegmentRootLookup {
		segmentRootLookup[mapHash(pair.Key)] = mapHash(pair.Val)
	}
	return &block.WorkReport{
		WorkPackageSpecification: block.WorkPackageSpecification{
			WorkPackageHash:           mapHash(r.PackageSpec.Hash),
			AuditableWorkBundleLength: r.PackageSpec.Length,
			ErasureRoot:               mapHash(r.PackageSpec.ErasureRoot),
			SegmentRoot:               mapHash(r.PackageSpec.ExportsRoot),
			SegmentCount:              r.PackageSpec.ExportsCount,
		},
		RefinementContext: block.RefinementContext{
			Anchor:                  block.RefinementContextAnchor{},
			LookupAnchor:            block.RefinementContextLookupAnchor{},
			PrerequisiteWorkPackage: mapSlice(r.Context.Prerequisites, mapHash),
		},
		CoreIndex:         r.CoreIndex,
		AuthorizerHash:    mapHash(r.AuthorizerHash),
		Output:            mustStringToHex(r.AuthOutput),
		SegmentRootLookup: segmentRootLookup,
		WorkResults: mapSlice(r.Results, func(rr ReportResult) block.WorkResult {
			return block.WorkResult{
				ServiceId:              block.ServiceId(rr.ServiceID),
				ServiceHashCode:        mapHash(rr.CodeHash),
				PayloadHash:            mapHash(rr.PayloadHash),
				GasPrioritizationRatio: rr.Gas,
				Output: block.WorkResultOutputOrError{
					Inner: rr.Result.Ok,
				},
			}
		}),
	}
}

func mapHash(s string) crypto.Hash {
	return crypto.Hash(mustStringToHex(s))
}

func TestAssurancesTiny(t *testing.T) {
	rootPath := "vectors/assurances/tiny"
	ff, err := assurancestestvectors.ReadDir(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range ff {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
			tc := &AssurancesJSONData{}
			f, err := assurancestestvectors.Open(path.Join(rootPath, file.Name()))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = f.Close()
			})
			bb, err := io.ReadAll(f)
			require.NoError(t, err)

			if err := json.Unmarshal(bb, tc); err != nil {
				t.Fatal(err)
			}

			newBlock := mapBlock(tc.Input)
			theState := mapAssurancesState(tc.PreState)
			var removedReports []*block.WorkReport
			theState.CoreAssignments, removedReports, err = statetransition.CalculateIntermediateCoreFromAssurances(theState.ValidatorState.CurrentValidators, theState.CoreAssignments, newBlock.Header, newBlock.Extrinsic.EA)
			if tc.Output.Err != "" {
				require.EqualError(t, err, strings.ReplaceAll(tc.Output.Err, "_", " "))
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, mapAssurancesState(tc.PostState), theState)
			assert.Equal(t, mapSlice(tc.Output.Ok.Reported, mapReport), removedReports)
		})
	}
}
