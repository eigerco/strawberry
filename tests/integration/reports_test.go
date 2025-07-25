//go:build integration

package integration_test

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
	"github.com/eigerco/strawberry/internal/merkle/mountain_ranges"
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

type Context struct {
	Anchor           string   `json:"anchor"`
	StateRoot        string   `json:"state_root"`
	BeefyRoot        string   `json:"beefy_root"`
	LookupAnchor     string   `json:"lookup_anchor"`
	LookupAnchorSlot int      `json:"lookup_anchor_slot"`
	Prerequisites    []string `json:"prerequisites"`
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

type Report struct {
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
	Report     Report      `json:"Report"`
	Slot       int         `json:"slot"`
	Signatures []Signature `json:"signatures"`
}

type Input struct {
	Guarantees []Guarantee `json:"guarantees"`
	Slot       int         `json:"slot"`
}

type Output struct {
	Ok  OutputOk `json:"ok"`
	Err string   `json:"err"`
}

type OutputOk struct {
	Reported  []ReportedWorkOutput `json:"reported"`
	Reporters []string             `json:"reporters"`
}

type ReportedWorkOutput struct {
	WorkPackageHash string `json:"work_package_hash"`
	SegmentTreeRoot string `json:"segment_tree_root"`
}

type JSONData struct {
	Input     Input  `json:"input"`
	PreState  State  `json:"pre_state"`
	Output    Output `json:"output"`
	PostState State  `json:"post_state"`
}

type ValidatorKey struct {
	Bandersnatch string `json:"bandersnatch"`
	Ed25519      string `json:"ed25519"`
	BLS          string `json:"bls"`
	Metadata     string `json:"metadata"`
}

type AvailAssignments struct {
	Report  Report `json:"report"`
	Timeout int    `json:"timeout"`
}

type State struct {
	AvailAssignments []*AvailAssignments `json:"avail_assignments"`
	CurrValidators   []ValidatorKey      `json:"curr_validators"`
	PrevValidators   []ValidatorKey      `json:"prev_validators"`
	Entropy          []string            `json:"entropy"`
	Offenders        []string            `json:"offenders"`
	RecentBlocks     []BlockState        `json:"recent_blocks"`
	AuthPools        [][]string          `json:"auth_pools"`
	Services         []ServiceInfo       `json:"accounts"`
}

type BlockState struct {
	HeaderHash string         `json:"header_hash"`
	MMR        MMRPeaks       `json:"mmr"`
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

func mapKey(v ValidatorKey) crypto.ValidatorKey {
	return crypto.ValidatorKey{
		Bandersnatch: crypto.BandersnatchPublicKey(mustStringToHex(v.Bandersnatch)),
		Ed25519:      ed25519.PublicKey(mustStringToHex(v.Ed25519)),
		Bls:          crypto.BlsKey(mustStringToHex(v.BLS)),
		Metadata:     crypto.MetadataKey(mustStringToHex(v.Metadata)),
	}
}

func mustStringToHex(s string) []byte {
	bytes, err := crypto.StringToHex(s)
	if err != nil {
		panic(err)
	}
	return bytes
}

func mapWorkReport(r Report) block.WorkReport {
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

func TestReports(t *testing.T) {
	files, err := os.ReadDir("vectors/reports/tiny")
	require.NoError(t, err, "failed to read tiny directory")

	db, err := pebble.NewKVStore()
	require.NoError(t, err)

	chain := store.NewChain(db)
	defer chain.Close()

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
			filePath := fmt.Sprintf("vectors/reports/tiny/%s", file.Name())
			data, err := ReadJSONFile(filePath)
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

			newTimeState := statetransition.CalculateNewTimeState(newBlock.Header)
			// ρ†
			intermediateCoreAssignments := disputing.CalculateIntermediateCoreAssignmentsFromExtrinsics(newBlock.Extrinsic.ED, preState.CoreAssignments)
			// ρ‡
			intermediateCoreAssignments, _, err = assuring.CalculateIntermediateCoreAssignmentsAndAvailableWorkReports(newBlock.Extrinsic.EA, preState.ValidatorState.CurrentValidators, intermediateCoreAssignments,
				newBlock.Header)
			require.NoError(t, err)

			reporters, err := guaranteeing.ValidateGuaranteExtrinsicAndReturnReporters(newBlock.Extrinsic.EG, &preState, chain, newTimeState, preState.RecentHistory,
				newBlock.Header, intermediateCoreAssignments)
			//Verify results
			if data.Output.Err != "" {
				require.Error(t, err)
				require.EqualError(t, err, strings.ReplaceAll(data.Output.Err, "_", " "))
				return
			}
			require.NoError(t, err)
			newCoreAssignments := guaranteeing.CalculatePosteriorCoreAssignments(newBlock.Extrinsic.EG, intermediateCoreAssignments, newTimeState)

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

			// Verify core assignments
			require.Equal(t, len(expectedPostState.CoreAssignments), len(newCoreAssignments),
				"Mismatch in CoreAssignments length")
			for i := range expectedPostState.CoreAssignments {
				if expectedPostState.CoreAssignments[i] == nil {
					require.Nil(t, newCoreAssignments[i],
						"CoreAssignment[%d] should be nil", i)
					continue
				}
				require.Equal(t, expectedPostState.CoreAssignments[i].Time,
					newCoreAssignments[i].Time,
					"Mismatch in CoreAssignment[%d] Time", i)
				require.Equal(t, expectedPostState.CoreAssignments[i].WorkReport,
					newCoreAssignments[i].WorkReport,
					"Mismatch in CoreAssignment[%d] WorkReport", i)
			}

			// Verify validators haven't changed
			require.ElementsMatch(t, expectedPostState.ValidatorState.CurrentValidators,
				preState.ValidatorState.CurrentValidators,
				"CurrentValidators should not have changed")
			require.ElementsMatch(t, expectedPostState.ValidatorState.ArchivedValidators,
				preState.ValidatorState.ArchivedValidators,
				"ArchivedValidators should not have changed")

			// Verify entropy pool hasn't changed
			for i := range expectedPostState.EntropyPool {
				require.Equal(t, expectedPostState.EntropyPool[i], preState.EntropyPool[i],
					"EntropyPool should not have changed")
			}
		})
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
func mapRecentHistory(blocks []BlockState) state.RecentHistory {
	newBlocks := make([]state.BlockState, len(blocks))

	for i, b := range blocks {
		// Map work report hashes
		workReportHashes := make(map[crypto.Hash]crypto.Hash)
		for _, r := range b.Reported {
			wpHash := crypto.Hash(mustStringToHex(r.WorkPackageHash))
			segHash := crypto.Hash(mustStringToHex(r.SegmentTreeRoot))
			workReportHashes[wpHash] = segHash
		}

		// MMR peaks conversion
		mmr := make([]*crypto.Hash, len(b.MMR.Peaks))
		for j, peak := range b.MMR.Peaks {
			if peak == "" {
				mmr[j] = nil
				continue
			}
			hash := crypto.Hash(mustStringToHex(peak))
			mmr[j] = &hash
		}
		mountainRange := mountain_ranges.New()
		beefRoot := mountainRange.SuperPeak(mmr, crypto.KeccakData)

		headerHash := crypto.Hash(mustStringToHex(b.HeaderHash))
		stateRoot := crypto.Hash(mustStringToHex(b.StateRoot))

		newBlocks[i] = state.BlockState{
			HeaderHash: headerHash,
			StateRoot:  stateRoot,
			BeefyRoot:  beefRoot,
			Reported:   workReportHashes,
		}
	}

	var outputLog []*crypto.Hash
	if len(blocks) > 0 {
		lastBlock := blocks[len(blocks)-1]
		for _, peak := range lastBlock.MMR.Peaks {
			if peak == "" {
				outputLog = append(outputLog, nil)
				continue
			}
			hash := crypto.Hash(mustStringToHex(peak))
			outputLog = append(outputLog, &hash)
		}

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

// Helper function to map pre or post state from JSON to internal state
func mapState(s State) state.State {
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
	}
}
