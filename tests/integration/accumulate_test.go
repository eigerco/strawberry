//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

type AccumulateInput struct {
	Slot    jamtime.Timeslot   `json:"slot"`
	Reports []AccumulateReport `json:"reports"`
}

type AccumulateState struct {
	Slot        jamtime.Timeslot   `json:"slot"`
	Entropy     string             `json:"entropy"`
	ReadyQueue  [][]ReadyQueueItem `json:"ready_queue"`
	Accumulated [][]string         `json:"accumulated"`
	Privileges  struct {
		Bless     block.ServiceId `json:"bless"`
		Assign    block.ServiceId `json:"assign"`
		Designate block.ServiceId `json:"designate"`
		AlwaysAcc []struct {
			ServiceId block.ServiceId `json:"service_id"`
			Gas       uint64          `json:"gas"`
		} `json:"always_acc"`
	} `json:"privileges"`
	Accounts []AccumulateServiceAccount `json:"accounts"`
}

type AccumulateReport struct {
	PackageSpec       PackageSpec              `json:"package_spec"`
	Context           Context                  `json:"context"`
	CoreIndex         uint16                   `json:"core_index"`
	AuthorizerHash    string                   `json:"authorizer_hash"`
	AuthOutput        string                   `json:"auth_output"`
	SegmentRootLookup []SegmentRootLookup      `json:"segment_root_lookup"`
	Results           []AccumulateReportResult `json:"results"`
}

type SegmentRootLookup struct {
	WorkPackageHash string `json:"work_package_hash"`
	SegmentTreeRoot string `json:"segment_tree_root"`
}

type AccumulateReportResult struct {
	ServiceId     int    `json:"service_id"`
	CodeHash      string `json:"code_hash"`
	PayloadHash   string `json:"payload_hash"`
	AccumulateGas uint64 `json:"accumulate_gas"`
	Result        struct {
		Ok string `json:"ok"`
	} `json:"result"`
}

type ReadyQueueItem struct {
	Report       AccumulateReport `json:"report"`
	Dependencies []string         `json:"dependencies"`
}

type AccumulateServiceAccount struct {
	Id   block.ServiceId `json:"id"`
	Data struct {
		Service struct {
			CodeHash   string `json:"code_hash"`
			Balance    uint64 `json:"balance"`
			MinItemGas uint64 `json:"min_item_gas"`
			MinMemoGas uint64 `json:"min_memo_gas"`
			Bytes      uint64 `json:"bytes"`
			Items      uint32 `json:"items"`
		} `json:"service"`
		Preimages []struct {
			Hash string `json:"hash"`
			Blob string `json:"blob"`
		} `json:"preimages"`
	} `json:"data"`
}

type AccumulateTestCase struct {
	Input    AccumulateInput `json:"input"`
	PreState AccumulateState `json:"pre_state"`
	Output   struct {
		Ok string `json:"ok"`
	} `json:"output"`
	PostState AccumulateState `json:"post_state"`
}

func TestAccumulate(t *testing.T) {
	files, err := os.ReadDir("vectors/accumulate/tiny")
	require.NoError(t, err)

	for _, file := range files {
		t.Run(file.Name(), func(t *testing.T) {
			f, err := os.Open(fmt.Sprintf("vectors/accumulate/tiny/%s", file.Name()))
			require.NoError(t, err)
			defer f.Close()

			tc := AccumulateTestCase{}
			dec := json.NewDecoder(f)
			err = dec.Decode(&tc)
			require.NoError(t, err)

			buff := dec.Buffered()
			bb, err := io.ReadAll(buff)
			require.NoError(t, err)
			require.Equal(t, len(bb), 1) // must not remain any unread bytes (except \n)

			workReports := mapSlice(tc.Input.Reports, mapAccumulateWorkReport)
			preState := mapAccumulateState(t, tc.PreState)
			postState := mapAccumulateState(t, tc.PostState)

			newState := &state.State{}
			preStateVal := *preState // create shallow copy
			newState = &preStateVal

			header := &block.Header{TimeSlotIndex: tc.Input.Slot}
			newState.TimeslotIndex = statetransition.CalculateNewTimeState(*header)
			newState.AccumulationQueue,
				newState.AccumulationHistory,
				newState.Services,
				newState.PrivilegedServices,
				newState.ValidatorState.QueuedValidators,
				newState.PendingAuthorizersQueues,
				_ = statetransition.CalculateWorkReportsAndAccumulate(header, preState, newState.TimeslotIndex, workReports)
			assert.Equal(t, postState, newState)
		})
	}
}

func mapAccumulateState(t *testing.T, s AccumulateState) *state.State {
	privilegedGas := map[block.ServiceId]uint64{}
	for _, a := range s.Privileges.AlwaysAcc {
		privilegedGas[a.ServiceId] = a.Gas
	}
	return &state.State{
		Services: mapAccumulateServices(t, s.Accounts),
		PrivilegedServices: service.PrivilegedServices{
			ManagerServiceId:        s.Privileges.Bless,
			AssignServiceId:         s.Privileges.Assign,
			DesignateServiceId:      s.Privileges.Designate,
			AmountOfGasPerServiceId: privilegedGas,
		},
		EntropyPool:         state.EntropyPool{mapHash(s.Entropy)},
		TimeslotIndex:       s.Slot,
		AccumulationQueue:   mapAccumulationQueue(s.ReadyQueue),
		AccumulationHistory: mapAccumulateHistory(s.Accumulated),
	}
}

func mapAccumulationQueue(queue [][]ReadyQueueItem) state.AccumulationQueue {
	accQueue := state.AccumulationQueue{}
	for i, queueSlice := range queue {
		for _, queueItem := range queueSlice {
			accQueue[i] = append(accQueue[i], state.WorkReportWithUnAccumulatedDependencies{
				WorkReport:   mapAccumulateWorkReport(queueItem.Report),
				Dependencies: mapSlice2HashSet(queueItem.Dependencies),
			})
		}
	}
	return accQueue
}

func mapAccumulateHistory(history [][]string) state.AccumulationHistory {
	accHistory := state.AccumulationHistory{}
	for i, hashes := range history {
		accHistory[i] = make(map[crypto.Hash]struct{})
		for _, h := range hashes {
			accHistory[i][mapHash(h)] = struct{}{}
		}
	}
	return accHistory
}

func mapSlice2HashSet(slice []string) map[crypto.Hash]struct{} {
	set := make(map[crypto.Hash]struct{})
	for _, dep := range slice {
		set[mapHash(dep)] = struct{}{}
	}
	return set
}

func mapAccumulateWorkReport(r AccumulateReport) block.WorkReport {
	segmentRootLookup := make(map[crypto.Hash]crypto.Hash)
	for _, sr := range r.SegmentRootLookup {
		segmentRootLookup[mapHash(sr.WorkPackageHash)] = mapHash(sr.SegmentTreeRoot)
	}
	return block.WorkReport{
		WorkPackageSpecification: block.WorkPackageSpecification{
			WorkPackageHash:           mapHash(r.PackageSpec.Hash),
			AuditableWorkBundleLength: r.PackageSpec.Length,
			ErasureRoot:               mapHash(r.PackageSpec.ErasureRoot),
			SegmentRoot:               mapHash(r.PackageSpec.ExportsRoot),
			SegmentCount:              r.PackageSpec.ExportsCount,
		},
		RefinementContext: block.RefinementContext{
			Anchor: block.RefinementContextAnchor{
				HeaderHash:         mapHash(r.Context.Anchor),
				PosteriorStateRoot: mapHash(r.Context.StateRoot),
				PosteriorBeefyRoot: mapHash(r.Context.BeefyRoot),
			},
			LookupAnchor: block.RefinementContextLookupAnchor{
				HeaderHash: mapHash(r.Context.LookupAnchor),
				Timeslot:   jamtime.Timeslot(r.Context.LookupAnchorSlot),
			},
			PrerequisiteWorkPackage: mapSlice(r.Context.Prerequisites, mapHash),
		},
		CoreIndex:         r.CoreIndex,
		AuthorizerHash:    mapHash(r.AuthorizerHash),
		Output:            mustStringToHex(r.AuthOutput),
		SegmentRootLookup: segmentRootLookup,
		WorkResults: mapSlice(r.Results, func(rr AccumulateReportResult) block.WorkResult {
			return block.WorkResult{
				ServiceId:              block.ServiceId(rr.ServiceId),
				ServiceHashCode:        mapHash(rr.CodeHash),
				PayloadHash:            mapHash(rr.PayloadHash),
				GasPrioritizationRatio: rr.AccumulateGas,
				Output: block.WorkResultOutputOrError{
					Inner: mustStringToHex(rr.Result.Ok),
				},
			}
		}),
	}
}

func mapAccumulateServices(t *testing.T, accounts []AccumulateServiceAccount) service.ServiceState {
	serviceAccounts := service.ServiceState{}
	for _, account := range accounts {
		sa := service.ServiceAccount{
			PreimageLookup:         make(map[crypto.Hash][]byte),
			CodeHash:               mapHash(account.Data.Service.CodeHash),
			Balance:                account.Data.Service.Balance,
			GasLimitForAccumulator: account.Data.Service.MinItemGas,
			GasLimitOnTransfer:     account.Data.Service.MinMemoGas,
		}
		for _, preimage := range account.Data.Preimages {
			sa.PreimageLookup[mapHash(preimage.Hash)] = mustStringToHex(preimage.Blob)
		}
		assert.Equal(t, account.Data.Service.Bytes, sa.TotalStorageSize())
		assert.Equal(t, account.Data.Service.Items, sa.TotalItems())
		serviceAccounts[account.Id] = sa
	}
	return serviceAccounts
}
