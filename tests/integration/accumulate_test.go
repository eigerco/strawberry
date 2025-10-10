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

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/validator"
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
		Bless     block.ServiceId                            `json:"bless"`
		Assign    [common.TotalNumberOfCores]block.ServiceId `json:"assign"`
		Designate block.ServiceId                            `json:"designate"`
		AlwaysAcc []struct {
			ServiceId block.ServiceId `json:"service_id"`
			Gas       uint64          `json:"gas"`
		} `json:"always_acc"`
	} `json:"privileges"`
	Accounts   []AccumulateServiceAccount `json:"accounts"`
	Statistics []ServiceStat              `json:"statistics"`
}

type ServiceStat struct {
	Id     block.ServiceId `json:"id"`
	Record struct {
		ProvidedCount      int    `json:"provided_count"`
		ProvidedSize       int    `json:"provided_size"`
		RefinementCount    int    `json:"refinement_count"`
		RefinementGasUsed  int    `json:"refinement_gas_used"`
		Imports            int    `json:"imports"`
		Exports            int    `json:"exports"`
		ExtrinsicSize      int    `json:"extrinsic_size"`
		ExtrinsicCount     int    `json:"extrinsic_count"`
		AccumulateCount    uint32 `json:"accumulate_count"`
		AccumulateGasUsed  uint64 `json:"accumulate_gas_used"`
		OnTransfersCount   uint32 `json:"on_transfers_count"`
		OnTransfersGasUsed uint64 `json:"on_transfers_gas_used"`
	} `json:"record"`
}

type AccumulateReport struct {
	PackageSpec       PackageSpec              `json:"package_spec"`
	Context           Context                  `json:"context"`
	CoreIndex         uint16                   `json:"core_index"`
	AuthorizerHash    string                   `json:"authorizer_hash"`
	AuthOutput        string                   `json:"auth_output"`
	SegmentRootLookup []SegmentRootLookup      `json:"segment_root_lookup"`
	Results           []AccumulateReportResult `json:"results"`
	AuthGasUsed       uint64                   `json:"auth_gas_used"`
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

	RefineLoad struct {
		GasUsed        uint64 `json:"gas_used"`
		Imports        uint16 `json:"imports"`
		ExtrinsicCount uint16 `json:"extrinsic_count"`
		ExtrinsicSize  uint32 `json:"extrinsic_size"`
		Exports        uint16 `json:"exports"`
	} `json:"refine_load"`
}

type ReadyQueueItem struct {
	Report       AccumulateReport `json:"report"`
	Dependencies []string         `json:"dependencies"`
}

type AccumulateServiceAccount struct {
	Id   block.ServiceId `json:"id"`
	Data struct {
		Service struct {
			CodeHash             string           `json:"code_hash"`
			Balance              uint64           `json:"balance"`
			MinItemGas           uint64           `json:"min_item_gas"`
			MinMemoGas           uint64           `json:"min_memo_gas"`
			Bytes                uint64           `json:"bytes"`
			Items                uint32           `json:"items"`
			DepositOffset        uint64           `json:"deposit_offset"`
			CreationSlot         jamtime.Timeslot `json:"creation_slot"`
			LastAccumulationSlot jamtime.Timeslot `json:"last_accumulation_slot"`
			ParentService        block.ServiceId  `json:"parent_service"`
		} `json:"service"`
		Preimages []struct {
			Hash string `json:"hash"`
			Blob string `json:"blob"`
		} `json:"preimages"`

		Storage []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"storage"`
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
	files, err := os.ReadDir(fmt.Sprintf("vectors/accumulate/%s", vectorsType))
	require.NoError(t, err, "failed to read directory: vectors/accumulate/%s", vectorsType)

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		t.Run(file.Name(), func(t *testing.T) {
			f, err := os.Open(fmt.Sprintf("vectors/accumulate/%s/%s", vectorsType, file.Name()))
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

			newState := &state.State{
				ActivityStatistics: validator.ActivityStatisticsState{
					Services: make(validator.ServiceStatistics),
				},
				EntropyPool: preState.EntropyPool, // copy the entropy pool, accumulation is not supposed to do any changes to it
			}

			var accStat statetransition.AccumulationStats
			header := &block.Header{TimeSlotIndex: tc.Input.Slot}
			newState.TimeslotIndex = statetransition.CalculateNewTimeState(*header)
			newState.AccumulationQueue,
				newState.AccumulationHistory,
				newState.Services,
				newState.PrivilegedServices,
				newState.ValidatorState.QueuedValidators,
				newState.PendingAuthorizersQueues,
				_, accStat = statetransition.CalculateWorkReportsAndAccumulate(header, preState, newState.TimeslotIndex, workReports)
			for id, stat := range accStat {
				stateStat := newState.ActivityStatistics.Services[id]
				stateStat.AccumulateCount = stat.AccumulateCount
				stateStat.AccumulateGasUsed = stat.AccumulateGasUsed
				newState.ActivityStatistics.Services[id] = stateStat
			}
			assert.EqualExportedValues(t, postState, newState)
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
			AssignedServiceIds:      s.Privileges.Assign,
			DesignateServiceId:      s.Privileges.Designate,
			AmountOfGasPerServiceId: privilegedGas,
		},
		EntropyPool:         state.EntropyPool{mapHash(s.Entropy)},
		TimeslotIndex:       s.Slot,
		AccumulationQueue:   mapAccumulationQueue(s.ReadyQueue),
		AccumulationHistory: mapAccumulateHistory(s.Accumulated),
		ActivityStatistics:  mapStatistics(s.Statistics),
	}
}

func mapStatistics(servicesStats []ServiceStat) validator.ActivityStatisticsState {
	stats := validator.ActivityStatisticsState{
		Services: make(map[block.ServiceId]validator.ServiceActivityRecord),
	}
	for _, svcStat := range servicesStats {
		stats.Services[svcStat.Id] = validator.ServiceActivityRecord{
			AccumulateCount:   svcStat.Record.AccumulateCount,
			AccumulateGasUsed: svcStat.Record.AccumulateGasUsed,
		}
	}
	return stats
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
		AvailabilitySpecification: block.AvailabilitySpecification{
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
		AuthorizerTrace:   mustStringToHex(r.AuthOutput),
		SegmentRootLookup: segmentRootLookup,
		WorkDigests: mapSlice(r.Results, func(rr AccumulateReportResult) block.WorkDigest {
			return block.WorkDigest{
				ServiceId:       block.ServiceId(rr.ServiceId),
				ServiceHashCode: mapHash(rr.CodeHash),
				PayloadHash:     mapHash(rr.PayloadHash),
				GasLimit:        rr.AccumulateGas,
				Output: block.WorkResultOutputOrError{
					Inner: mustStringToHex(rr.Result.Ok),
				},
				GasUsed:               rr.RefineLoad.GasUsed,
				SegmentsImportedCount: rr.RefineLoad.Imports,
				ExtrinsicCount:        rr.RefineLoad.ExtrinsicCount,
				ExtrinsicSize:         rr.RefineLoad.ExtrinsicSize,
				SegmentsExportedCount: rr.RefineLoad.Exports,
			}
		}),
		AuthGasUsed: r.AuthGasUsed,
	}
}

func mapAccumulateServices(t *testing.T, accounts []AccumulateServiceAccount) service.ServiceState {
	serviceAccounts := service.ServiceState{}
	for _, account := range accounts {
		sa := service.ServiceAccount{
			PreimageLookup:                 make(map[crypto.Hash][]byte),
			GratisStorageOffset:            account.Data.Service.DepositOffset,
			CodeHash:                       mapHash(account.Data.Service.CodeHash),
			Balance:                        account.Data.Service.Balance,
			GasLimitForAccumulator:         account.Data.Service.MinItemGas,
			GasLimitOnTransfer:             account.Data.Service.MinMemoGas,
			CreationTimeslot:               account.Data.Service.CreationSlot,
			MostRecentAccumulationTimeslot: account.Data.Service.LastAccumulationSlot,
			ParentService:                  account.Data.Service.ParentService,
		}
		for _, preimage := range account.Data.Preimages {
			sa.PreimageLookup[mapHash(preimage.Hash)] = mustStringToHex(preimage.Blob)

			k, err := statekey.NewPreimageMeta(account.Id, mapHash(preimage.Hash), uint32(len(mustStringToHex(preimage.Blob))))
			require.NoError(t, err)

			err = sa.InsertPreimageMeta(k, uint64(len(mustStringToHex(preimage.Blob))), service.PreimageHistoricalTimeslots{})
			require.NoError(t, err)
		}
		for _, storage := range account.Data.Storage {
			serviceId := account.Id

			// The vectors store the raw key instead of using function C for generating the storage keys
			// our code however implements the storage keys correctly as the output of C not the raw value
			// this creates a discrepancy which fails the tests, so we use the same logic here
			// to create the same result and being able to compare the values properly
			sk, err := statekey.NewStorage(serviceId, mustStringToHex(storage.Key))
			require.NoError(t, err)

			sa.InsertStorage(sk, uint64(len(mustStringToHex(storage.Key))), mustStringToHex(storage.Value))
		}

		// TODO check the latest GP for more info, it is possible we misunderstood something and it is the expected behaviour
		// Skip this test verification, the storage footprint for this service seems to be wrong in the test vector
		// as service does not contain any preimages or storage items so the expected size is zero
		// see issue: https://github.com/w3f/jamtestvectors/issues/50
		if t.Name() != "TestAccumulate/same_code_different_services-1.json" {
			assert.Equal(t, account.Data.Service.Bytes, sa.GetTotalNumberOfOctets())
			assert.Equal(t, account.Data.Service.Items, sa.GetTotalNumberOfItems())
		} else {
			t.Log("ignoring TestAccumulate/same_code_different_services-1.json threshold verification!")
		}
		serviceAccounts[account.Id] = sa
	}
	return serviceAccounts
}
