//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/assuring"
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/validator"
)

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
	Report  Report           `json:"report"`
	Timeout jamtime.Timeslot `json:"timeout"`
}

type AssurancesOutput struct {
	Err string `json:"err"`
	Ok  struct {
		Reported []Report `json:"reported"` // ??
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
	assignmentsArray := make([]*state.Assignment, constants.TotalNumberOfCores)
	copy(assignmentsArray, assignments)
	return state.CoreAssignments(assignmentsArray)
}

func mapCurrValidators(currValidators []ValidatorKey) safrole.ValidatorsData {
	validators := mapSlice(currValidators, mapKey)
	validatorsArray := make([]crypto.ValidatorKey, constants.NumberOfValidators)
	copy(validatorsArray, validators)
	return safrole.ValidatorsData(validatorsArray)
}

func mapSlice[T1, T2 any](s1 []T1, fn func(T1) T2) (s2 []T2) {
	for _, s := range s1 {
		s2 = append(s2, fn(s))
	}
	return
}

func mapReport(r Report) block.WorkReport {
	segmentRootLookup := make(map[crypto.Hash]crypto.Hash)
	for _, pair := range r.SegmentRootLookup {
		segmentRootLookup[mapHash(pair.Key)] = mapHash(pair.Val)
	}
	return block.WorkReport{
		AvailabilitySpecification: block.AvailabilitySpecification{
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
		AuthorizerTrace:   mustStringToHex(r.AuthOutput),
		SegmentRootLookup: segmentRootLookup,
		WorkDigests: mapSlice(r.Results, func(rr ReportResult) block.WorkDigest {
			return block.WorkDigest{
				ServiceId:       block.ServiceId(rr.ServiceID),
				ServiceHashCode: mapHash(rr.CodeHash),
				PayloadHash:     mapHash(rr.PayloadHash),
				GasLimit:        rr.Gas,
				Output: block.WorkResultOutputOrError{
					Inner: mustStringToHex(rr.Result.Ok),
				},
			}
		}),
	}
}

func mapHash(s string) crypto.Hash {
	if s == "" {
		return crypto.Hash{} // returns zero-value Hash (32 zero bytes)
	}
	return crypto.Hash(mustStringToHex(s))
}
func ReadAssurancesJSONFile(filename string) (*AssurancesJSONData, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var data AssurancesJSONData
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return &data, nil
}
func TestAssurancesTiny(t *testing.T) {
	files, err := os.ReadDir(fmt.Sprintf("vectors/assurances/%s", vectorsType))
	require.NoError(t, err, "failed to read directory: vectors/assurances/%s", vectorsType)
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
			filePath := fmt.Sprintf("vectors/assurances/%s/%s", vectorsType, file.Name())
			tc, err := ReadAssurancesJSONFile(filePath)
			require.NoError(t, err, "failed to read JSON file: %s", filePath)

			newBlock := mapBlock(tc.Input)
			theState := mapAssurancesState(tc.PreState)
			var removedReports []block.WorkReport
			theState.CoreAssignments, removedReports, err = assuring.CalculateIntermediateCoreAssignmentsAndAvailableWorkReports(
				newBlock.Extrinsic.EA, theState.ValidatorState.CurrentValidators, theState.CoreAssignments, newBlock.Header)
			if tc.Output.Err != "" {
				require.EqualError(t, err, strings.ReplaceAll(tc.Output.Err, "_", " "))
			} else {
				require.NoError(t, err)
			}
			pstState := mapAssurancesState(tc.PostState)
			assert.Equal(t, pstState, theState)
			assert.Equal(t, mapSlice(tc.Output.Ok.Reported, mapReport), removedReports)
		})
	}
}
