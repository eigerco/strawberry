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

	"github.com/eigerco/strawberry/internal/assuring"
	"github.com/eigerco/strawberry/internal/disputing"
	"github.com/eigerco/strawberry/internal/guaranteeing"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/db/pebble"

	"github.com/eigerco/strawberry/internal/statetransition"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
)

func ReadReportsJSONFile(filename string) (*ReportsJSONData, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var data ReportsJSONData
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return &data, nil
}

// JSON structures for test vectors
type ServiceInfo struct {
	ID   int `json:"id"`
	Data struct {
		Service struct {
			CodeHash   string `json:"code_hash"`
			Balance    int    `json:"balance"`
			MinItemGas int    `json:"min_item_gas"`
			MinMemoGas int    `json:"min_memo_gas"`
			Bytes      int    `json:"bytes"`
			Items      int    `json:"items"`
		} `json:"service"`
	} `json:"data"`
}

type ServiceDetails struct {
	CodeHash   string `json:"code_hash"`
	Balance    int    `json:"balance"`
	MinItemGas int    `json:"min_item_gas"`
	MinMemoGas int    `json:"min_memo_gas"`
	Bytes      int    `json:"bytes"`
	Items      int    `json:"items"`
}

type WorkPackageSpec struct {
	Hash         string `json:"hash"`
	Length       int    `json:"length"`
	ErasureRoot  string `json:"erasure_root"`
	ExportsRoot  string `json:"exports_root"`
	ExportsCount int    `json:"exports_count"`
}

type WorkResult struct {
	ServiceID   int               `json:"service_id"`
	CodeHash    string            `json:"code_hash"`
	PayloadHash string            `json:"payload_hash"`
	Gas         uint64            `json:"accumulate_gas"`
	Result      map[string]string `json:"result"`
	RefineLoad  struct {
		GasUsed        uint64 `json:"gas_used"`
		Imports        uint16 `json:"imports"`
		ExtrinsicCount uint16 `json:"extrinsic_count"`
		ExtrinsicSize  uint32 `json:"extrinsic_size"`
		Exports        uint16 `json:"exports"`
	} `json:"refine_load"`
}

type SegmentRootLookupEntry struct {
	WorkPackageHash string `json:"work_package_hash"`
	SegmentTreeRoot string `json:"segment_tree_root"`
}

type WorkReport struct {
	PackageSpec       WorkPackageSpec          `json:"package_spec"`
	Context           Context                  `json:"context"`
	CoreIndex         uint16                   `json:"core_index"`
	AuthorizerHash    string                   `json:"authorizer_hash"`
	AuthOutput        string                   `json:"auth_output"`
	SegmentRootLookup []SegmentRootLookupEntry `json:"segment_root_lookup"`
	Results           []WorkResult             `json:"results"`
}

type Signature struct {
	ValidatorIndex uint16 `json:"validator_index"`
	Signature      string `json:"signature"`
}

type Guarantee struct {
	Report     WorkReport  `json:"Report"`
	Slot       int         `json:"slot"`
	Signatures []Signature `json:"signatures"`
}

type ReportsInput struct {
	Guarantees []Guarantee `json:"guarantees"`
	Slot       int         `json:"slot"`
}

type ReportsOutput struct {
	Ok  RepoetsOutputOk `json:"ok"`
	Err string          `json:"err"`
}

type RepoetsOutputOk struct {
	Reported  []ReportedWorkOutput `json:"reported"`
	Reporters []string             `json:"reporters"`
}

type ReportedWorkOutput struct {
	WorkPackageHash string `json:"work_package_hash"`
	SegmentTreeRoot string `json:"segment_tree_root"`
}

type ReportsJSONData struct {
	Input     ReportsInput  `json:"input"`
	PreState  ReportsState  `json:"pre_state"`
	Output    ReportsOutput `json:"output"`
	PostState ReportsState  `json:"post_state"`
}

type AvailAssignments struct {
	Report  WorkReport `json:"report"`
	Timeout int        `json:"timeout"`
}

type CoreStatistics struct {
	DALoad         uint32 `json:"da_load"`
	Popularity     uint16 `json:"popularity"`
	Imports        uint16 `json:"imports"`
	Exports        uint16 `json:"exports"`
	ExtrinsicSize  uint32 `json:"extrinsic_size"`
	ExtrinsicCount uint16 `json:"extrinsic_count"`
	BundleSize     uint32 `json:"bundle_size"`
	GasUsed        uint64 `json:"gas_used"`
}

type ServiceStatisticsRecord struct {
	ProvidedCount      uint16 `json:"provided_count"`
	ProvidedSize       uint32 `json:"provided_size"`
	RefinementCount    uint32 `json:"refinement_count"`
	RefinementGasUsed  uint64 `json:"refinement_gas_used"`
	Imports            uint32 `json:"imports"`
	Exports            uint32 `json:"exports"`
	ExtrinsicSize      uint32 `json:"extrinsic_size"`
	ExtrinsicCount     uint32 `json:"extrinsic_count"`
	AccumulateCount    uint64 `json:"accumulate_count"`
	AccumulateGasUsed  uint64 `json:"accumulate_gas_used"`
	OnTransfersCount   uint32 `json:"on_transfers_count"`
	OnTransfersGasUsed uint64 `json:"on_transfers_gas_used"`
}

type ServiceStatistics struct {
	ID     int                     `json:"id"`
	Record ServiceStatisticsRecord `json:"record"`
}

type ReportsState struct {
	AvailAssignments   []*AvailAssignments `json:"avail_assignments"`
	CurrValidators     []ValidatorKey      `json:"curr_validators"`
	PrevValidators     []ValidatorKey      `json:"prev_validators"`
	Entropy            []string            `json:"entropy"`
	Offenders          []string            `json:"offenders"`
	RecentBlocks       RecentBlocks        `json:"recent_blocks"`
	AuthPools          [][]string          `json:"auth_pools"`
	Services           []ServiceInfo       `json:"accounts"`
	CoresStatistics    []CoreStatistics    `json:"cores_statistics"`
	ServicesStatistics []ServiceStatistics `json:"services_statistics"`
}

type RecentBlocks struct {
	History []BlockState `json:"history"`
	MMR     MMRPeaks     `json:"mmr"`
}

type BlockState struct {
	HeaderHash string         `json:"header_hash"`
	BeefyRoot  string         `json:"beefy_root"`
	StateRoot  string         `json:"state_root"`
	Reported   []ReportedWork `json:"reported"`
}

type ReportedWork struct {
	WorkPackageHash string `json:"hash"`
	SegmentTreeRoot string `json:"exports_root"`
}

type MMRPeaks struct {
	Peaks []string `json:"peaks"`
}

func mapWorkReport(r WorkReport) block.WorkReport {
	segmentRootLookup := make(map[crypto.Hash]crypto.Hash)
	for _, entry := range r.SegmentRootLookup {
		wpHash := crypto.Hash(mustStringToHex(entry.WorkPackageHash))
		segRoot := crypto.Hash(mustStringToHex(entry.SegmentTreeRoot))
		segmentRootLookup[wpHash] = segRoot
	}

	return block.WorkReport{
		AvailabilitySpecification: block.AvailabilitySpecification{
			WorkPackageHash:           crypto.Hash(mustStringToHex(r.PackageSpec.Hash)),
			AuditableWorkBundleLength: uint32(r.PackageSpec.Length),
			ErasureRoot:               crypto.Hash(mustStringToHex(r.PackageSpec.ErasureRoot)),
			SegmentRoot:               crypto.Hash(mustStringToHex(r.PackageSpec.ExportsRoot)),
			SegmentCount:              uint16(r.PackageSpec.ExportsCount),
		},
		RefinementContext: block.RefinementContext{
			Anchor: block.RefinementContextAnchor{
				HeaderHash:         crypto.Hash(mustStringToHex(r.Context.Anchor)),
				PosteriorStateRoot: crypto.Hash(mustStringToHex(r.Context.StateRoot)),
				PosteriorBeefyRoot: crypto.Hash(mustStringToHex(r.Context.BeefyRoot)),
			},
			LookupAnchor: block.RefinementContextLookupAnchor{
				HeaderHash: crypto.Hash(mustStringToHex(r.Context.LookupAnchor)),
				Timeslot:   jamtime.Timeslot(r.Context.LookupAnchorSlot),
			},
			PrerequisiteWorkPackage: mapStringSliceToHashes(r.Context.Prerequisites),
		},
		CoreIndex:         uint16(r.CoreIndex),
		AuthorizerHash:    crypto.Hash(mustStringToHex(r.AuthorizerHash)),
		AuthorizerTrace:   mustStringToHex(r.AuthOutput),
		SegmentRootLookup: segmentRootLookup,
		WorkDigests:       mapWorkResults(r.Results),
	}
}

func mapWorkResults(results []WorkResult) []block.WorkDigest {
	workResults := make([]block.WorkDigest, len(results))
	for i, r := range results {
		var output block.WorkResultOutputOrError
		if val, ok := r.Result["ok"]; ok {
			output.Inner = mustStringToHex(val)
		} else if _, ok := r.Result["err"]; ok {
			output.Inner = block.NoError // Or appropriate error mapping
		}

		workResults[i] = block.WorkDigest{
			ServiceId:             block.ServiceId(r.ServiceID),
			ServiceHashCode:       crypto.Hash(mustStringToHex(r.CodeHash)),
			PayloadHash:           crypto.Hash(mustStringToHex(r.PayloadHash)),
			GasLimit:              r.Gas,
			Output:                output,
			GasUsed:               r.RefineLoad.GasUsed,
			SegmentsImportedCount: r.RefineLoad.Imports,
			ExtrinsicCount:        r.RefineLoad.ExtrinsicCount,
			ExtrinsicSize:         r.RefineLoad.ExtrinsicSize,
			SegmentsExportedCount: r.RefineLoad.Exports,
		}
	}
	return workResults
}

func mapGuarantee(g Guarantee) block.Guarantee {
	credentials := make([]block.CredentialSignature, len(g.Signatures))
	for i, sig := range g.Signatures {
		var signature crypto.Ed25519Signature
		copy(signature[:], mustStringToHex(sig.Signature))
		credentials[i] = block.CredentialSignature{
			ValidatorIndex: uint16(sig.ValidatorIndex),
			Signature:      signature,
		}
	}

	return block.Guarantee{
		WorkReport:  mapWorkReport(g.Report),
		Timeslot:    jamtime.Timeslot(g.Slot),
		Credentials: credentials,
	}
}

func mapServices(services []ServiceInfo) service.ServiceState {
	serviceState := make(service.ServiceState)

	for _, s := range services {
		serviceState[block.ServiceId(s.ID)] = service.ServiceAccount{
			PreimageLookup:         make(map[crypto.Hash][]byte),
			CodeHash:               crypto.Hash(mustStringToHex(s.Data.Service.CodeHash)),
			Balance:                uint64(s.Data.Service.Balance),
			GasLimitForAccumulator: uint64(s.Data.Service.MinItemGas),
			GasLimitOnTransfer:     uint64(s.Data.Service.MinMemoGas),
		}
	}
	return serviceState
}

func mapValidators(validators []ValidatorKey) safrole.ValidatorsData {
	var data safrole.ValidatorsData
	for i, v := range validators {
		if i >= common.NumberOfValidators {
			break
		}
		data[i] = mapKey(v)
	}
	return data
}

// TODO this is a temporary mapping for recent history, when we have new test
// vectors for v0.6.7 this will need to be updated.
func mapRecentHistory(recentBlocks RecentBlocks) state.RecentHistory {
	blocks := recentBlocks.History
	newBlocks := make([]state.BlockState, len(blocks))

	for i, b := range blocks {
		// Map work report hashes
		workReportHashes := make(map[crypto.Hash]crypto.Hash)
		for _, r := range b.Reported {
			wpHash := crypto.Hash(mustStringToHex(r.WorkPackageHash))
			segHash := crypto.Hash(mustStringToHex(r.SegmentTreeRoot))
			workReportHashes[wpHash] = segHash
		}

		headerHash := crypto.Hash(mustStringToHex(b.HeaderHash))
		stateRoot := crypto.Hash(mustStringToHex(b.StateRoot))
		beefyRoot := crypto.Hash(mustStringToHex(b.BeefyRoot))

		newBlocks[i] = state.BlockState{
			HeaderHash: headerHash,
			StateRoot:  stateRoot,
			BeefyRoot:  beefyRoot,
			Reported:   workReportHashes,
		}
	}

	var outputLog []*crypto.Hash
	for _, peak := range recentBlocks.MMR.Peaks {
		if peak == "" {
			outputLog = append(outputLog, nil)
			continue
		}
		hash := crypto.Hash(mustStringToHex(peak))
		outputLog = append(outputLog, &hash)
	}

	return state.RecentHistory{
		BlockHistory:          newBlocks,
		AccumulationOutputLog: outputLog,
	}
}

func mapAuthPools(pools [][]string) state.CoreAuthorizersPool {
	var result state.CoreAuthorizersPool
	totalNumberOfCores := int(common.TotalNumberOfCores)
	for i, pool := range pools {
		if i >= totalNumberOfCores {
			break
		}

		result[i] = make([]crypto.Hash, len(pool))
		for j, hash := range pool {
			result[i][j] = crypto.Hash(mustStringToHex(hash))
		}
	}
	return result
}

func mapAvailAssignments(assignments []*AvailAssignments) state.CoreAssignments {
	var coreAssignments state.CoreAssignments
	if assignments == nil {
		return coreAssignments
	}

	// Iterate through the assignments array
	for i, assignment := range assignments {
		if i >= int(common.TotalNumberOfCores) {
			break
		}

		// Skip nil assignments
		if assignment == nil {
			continue
		}

		// Map the assignment for this core
		workReport := mapWorkReport(assignment.Report)
		coreAssignments[i] = &state.Assignment{
			WorkReport: workReport,
			Time:       jamtime.Timeslot(assignment.Timeout),
		}
	}
	return coreAssignments
}

func mapStringSliceToHashes(strings []string) []crypto.Hash {
	hashes := make([]crypto.Hash, len(strings))
	for i, s := range strings {
		hashes[i] = crypto.Hash(mustStringToHex(s))
	}
	return hashes
}

func mapEntropyPool(entropyStrings []string) state.EntropyPool {
	var entropyPool state.EntropyPool
	for i, entropyHex := range entropyStrings {
		copy(entropyPool[i][:], mustStringToHex(entropyHex))
	}
	return entropyPool
}

func mapPastJudgements(offenders []string) state.Judgements {
	var mapped state.Judgements
	for _, j := range offenders {
		mapped.OffendingValidators = append(mapped.OffendingValidators, ed25519.PublicKey(mustStringToHex(j)))
	}
	return mapped
}

// Helper function to map pre or post state from JSON to internal state
func mapState(s ReportsState) state.State {
	return state.State{
		CoreAssignments: mapAvailAssignments(s.AvailAssignments),
		ValidatorState: validator.ValidatorState{
			CurrentValidators:  mapValidators(s.CurrValidators),
			ArchivedValidators: mapValidators(s.PrevValidators),
		},
		RecentHistory:       mapRecentHistory(s.RecentBlocks),
		CoreAuthorizersPool: mapAuthPools(s.AuthPools),
		Services:            mapServices(s.Services),
		EntropyPool:         mapEntropyPool(s.Entropy),
		PastJudgements:      mapPastJudgements(s.Offenders),
		ActivityStatistics: validator.ActivityStatisticsState{
			Cores:    mapCoresStatistics(s.CoresStatistics),
			Services: mapServiceStatistics(s.ServicesStatistics),
		},
	}
}

// Map []CoreStatistics from JSON to [common.TotalNumberOfCores]validator.CoreStatistics
func mapCoresStatistics(stats []CoreStatistics) [common.TotalNumberOfCores]validator.CoreStatistics {
	var result [common.TotalNumberOfCores]validator.CoreStatistics
	for i, s := range stats {
		if i >= int(common.TotalNumberOfCores) {
			break
		}
		result[i] = validator.CoreStatistics{
			DALoad:         s.DALoad,
			Popularity:     s.Popularity,
			Imports:        s.Imports,
			Exports:        s.Exports,
			ExtrinsicSize:  s.ExtrinsicSize,
			ExtrinsicCount: s.ExtrinsicCount,
			BundleSize:     s.BundleSize,
			GasUsed:        s.GasUsed,
		}
	}
	return result
}

// Map []ServiceStatistics from JSON to validator.ServiceStatistics
func mapServiceStatistics(stats []ServiceStatistics) validator.ServiceStatistics {
	result := make(validator.ServiceStatistics)
	for _, s := range stats {
		result[block.ServiceId(s.ID)] = validator.ServiceActivityRecord{
			ProvidedCount:      s.Record.ProvidedCount,
			ProvidedSize:       s.Record.ProvidedSize,
			RefinementCount:    s.Record.RefinementCount,
			RefinementGasUsed:  s.Record.RefinementGasUsed,
			Imports:            s.Record.Imports,
			Exports:            s.Record.Exports,
			ExtrinsicSize:      s.Record.ExtrinsicSize,
			ExtrinsicCount:     s.Record.ExtrinsicCount,
			AccumulateCount:    uint32(s.Record.AccumulateCount), // Cast if needed
			AccumulateGasUsed:  s.Record.AccumulateGasUsed,
			OnTransfersCount:   s.Record.OnTransfersCount,
			OnTransfersGasUsed: s.Record.OnTransfersGasUsed,
		}
	}
	return result
}

func TestReports(t *testing.T) {
	files, err := os.ReadDir(fmt.Sprintf("vectors/reports/%s", vectorsType))
	require.NoError(t, err, "failed to read directory: vectors/reports/%s')", vectorsType)

	db, err := pebble.NewKVStore()
	require.NoError(t, err)

	chain := store.NewChain(db)
	defer chain.Close()

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
			filePath := fmt.Sprintf("vectors/reports/%s/%s", vectorsType, file.Name())
			data, err := ReadReportsJSONFile(filePath)
			require.NoError(t, err, "failed to read JSON file: %s", filePath)

			preState := mapState(data.PreState)

			// Create block
			header := block.Header{
				TimeSlotIndex: jamtime.Timeslot(data.Input.Slot),
			}
			guarantees := make([]block.Guarantee, len(data.Input.Guarantees))
			for i, g := range data.Input.Guarantees {
				guarantees[i] = mapGuarantee(g)
			}
			newBlock := block.Block{
				Header: header,
				Extrinsic: block.Extrinsic{
					ET: block.TicketExtrinsic{},
					EP: block.PreimageExtrinsic{},
					EG: block.GuaranteesExtrinsic{Guarantees: guarantees},
					EA: block.AssurancesExtrinsic{},
					ED: block.DisputeExtrinsic{},
				},
			}

			var processingError error
			var reporters crypto.ED25519PublicKeySet
			var newCoreAssignments state.CoreAssignments
			var newValidatorStatistics validator.ActivityStatisticsState
			newTimeState := statetransition.CalculateNewTimeState(newBlock.Header)

			// ρ†
			intermediateCoreAssignments := disputing.CalculateIntermediateCoreAssignmentsFromExtrinsics(newBlock.Extrinsic.ED, preState.CoreAssignments)
			// ρ‡
			intermediateCoreAssignments, availableWorkReports, err := assuring.CalculateIntermediateCoreAssignmentsAndAvailableWorkReports(
				newBlock.Extrinsic.EA,
				preState.ValidatorState.CurrentValidators,
				intermediateCoreAssignments,
				newBlock.Header,
			)

			if err != nil {
				processingError = err
			} else {
				// Only proceed if no error in assuring
				reporters, err = guaranteeing.ValidateGuaranteExtrinsicAndReturnReporters(
					newBlock.Extrinsic.EG,
					&preState,
					// TODO find a better way to get correct (new) entropy pool.
					preState.EntropyPool,
					chain,
					newTimeState,
					preState.RecentHistory,
					newBlock.Header,
					intermediateCoreAssignments,
				)

				if err != nil {
					processingError = err
				} else {
					// Only proceed if no error in guaranteeing
					newCoreAssignments = guaranteeing.CalculatePosteriorCoreAssignments(newBlock.Extrinsic.EG, intermediateCoreAssignments, newTimeState)
					preState.CoreAssignments = newCoreAssignments
					_, _, _, _, _, _, _, accumulationStats, transferStats := statetransition.CalculateWorkReportsAndAccumulate(
						&newBlock.Header,
						&preState,
						newBlock.Header.TimeSlotIndex,
						availableWorkReports,
					)

					newValidatorStatistics = statetransition.CalculateNewActivityStatistics(
						newBlock,
						preState.TimeslotIndex,
						preState.ActivityStatistics,
						reporters,
						preState.ValidatorState.CurrentValidators,
						[]block.WorkReport{},
						accumulationStats,
						transferStats,
					)
					preState.ActivityStatistics = newValidatorStatistics
				}
			}

			// Now handle assertions based on whether we had an error
			if processingError != nil {
				// If we expected an error, verify it matches
				if data.Output.Err != "" {
					require.Error(t, processingError, "Expected error but got none")
					require.EqualError(t, processingError, strings.ReplaceAll(data.Output.Err, "_", " "))
				} else {
					// We got an error but didn't expect one
					require.NoError(t, processingError, "Unexpected error occurred")
				}

			} else {
				// No error occurred - verify we didn't expect one
				if data.Output.Err != "" {
					t.Errorf("Expected error '%s' but got none", data.Output.Err)
				}

				// Now do all the success-case assertions
				expectedPostState := mapState(data.PostState)

				// Verify reporters if present in output
				if len(data.Output.Ok.Reporters) > 0 {
					// Verify each expected reporter exists in the reporters set
					for _, reporter := range data.Output.Ok.Reporters {
						reporterKey := ed25519.PublicKey(mustStringToHex(reporter))
						require.True(t, reporters.Has(reporterKey), "Missing expected reporter")
					}
					// Verify no extra reporters
					require.Equal(t, len(data.Output.Ok.Reporters), len(reporters))
				}

				// Verify output.Ok.Reported
				if len(data.Output.Ok.Reported) > 0 {
					for _, r := range data.Output.Ok.Reported {
						wpHash := crypto.Hash(mustStringToHex(r.WorkPackageHash))
						segRoot := crypto.Hash(mustStringToHex(r.SegmentTreeRoot))
						found := false
						for _, newCoreAssignment := range newCoreAssignments {
							if newCoreAssignment.WorkReport.AvailabilitySpecification.WorkPackageHash == wpHash &&
								newCoreAssignment.WorkReport.AvailabilitySpecification.SegmentRoot == segRoot {
								found = true
								break
							}
						}
						require.True(t, found, "Reported work package not found in guarantees: %s", r.WorkPackageHash)
					}
				}

				// Set ValidatorsCurrent and ValidatorsLast to empty as the test vectors do not include it
				preState.ActivityStatistics.ValidatorsCurrent = [common.NumberOfValidators]validator.ValidatorStatistics{}
				preState.ActivityStatistics.ValidatorsLast = [common.NumberOfValidators]validator.ValidatorStatistics{}

				require.Equal(t, expectedPostState, preState)
			}
		})
	}
}
