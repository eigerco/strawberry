//go:build integration

package integration_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/db/pebble"

	"github.com/eigerco/strawberry/internal/statetransition"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/stretchr/testify/require"
)

func stringToHex(s string) []byte {
	// Remove 0x prefix if present
	s = strings.TrimPrefix(s, "0x")

	// Decode hex string
	bytes, err := hex.DecodeString(s)
	if err != nil {
		log.Printf("Error decoding hex string '%s': %v", s, err)
		panic(err)
	}
	return bytes
}

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
	ID   int            `json:"id"`
	Info ServiceDetails `json:"info"`
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
	Gas         int               `json:"accumulate_gas"`
	Result      map[string]string `json:"result"`
}

type SegmentRootLookupEntry struct {
	WorkPackageHash string `json:"work_package_hash"`
	SegmentTreeRoot string `json:"segment_tree_root"`
}

type Report struct {
	PackageSpec       WorkPackageSpec          `json:"package_spec"`
	Context           Context                  `json:"context"`
	CoreIndex         int                      `json:"core_index"`
	AuthorizerHash    string                   `json:"authorizer_hash"`
	AuthOutput        string                   `json:"auth_output"`
	SegmentRootLookup []SegmentRootLookupEntry `json:"segment_root_lookup"`
	Results           []WorkResult             `json:"results"`
}

type Signature struct {
	ValidatorIndex int    `json:"validator_index"`
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
	Services         []ServiceInfo       `json:"services"`
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

func mapKey(v ValidatorKey) *crypto.ValidatorKey {
	return &crypto.ValidatorKey{
		Bandersnatch: crypto.BandersnatchPublicKey(stringToHex(v.Bandersnatch)),
		Ed25519:      ed25519.PublicKey(stringToHex(v.Ed25519)),
		Bls:          crypto.BlsKey(stringToHex(v.BLS)),
		Metadata:     crypto.MetadataKey(stringToHex(v.Metadata)),
	}
}

func mapWorkReport(r Report) block.WorkReport {
	segmentRootLookup := make(map[crypto.Hash]crypto.Hash)
	for _, entry := range r.SegmentRootLookup {
		wpHash := crypto.Hash(stringToHex(entry.WorkPackageHash))
		segRoot := crypto.Hash(stringToHex(entry.SegmentTreeRoot))
		segmentRootLookup[wpHash] = segRoot
	}

	return block.WorkReport{
		WorkPackageSpecification: block.WorkPackageSpecification{
			WorkPackageHash:           crypto.Hash(stringToHex(r.PackageSpec.Hash)),
			AuditableWorkBundleLength: uint32(r.PackageSpec.Length),
			ErasureRoot:               crypto.Hash(stringToHex(r.PackageSpec.ErasureRoot)),
			SegmentRoot:               crypto.Hash(stringToHex(r.PackageSpec.ExportsRoot)),
			SegmentCount:              uint16(r.PackageSpec.ExportsCount),
		},
		RefinementContext: block.RefinementContext{
			Anchor: block.RefinementContextAnchor{
				HeaderHash:         crypto.Hash(stringToHex(r.Context.Anchor)),
				PosteriorStateRoot: crypto.Hash(stringToHex(r.Context.StateRoot)),
				PosteriorBeefyRoot: crypto.Hash(stringToHex(r.Context.BeefyRoot)),
			},
			LookupAnchor: block.RefinementContextLookupAnchor{
				HeaderHash: crypto.Hash(stringToHex(r.Context.LookupAnchor)),
				Timeslot:   jamtime.Timeslot(r.Context.LookupAnchorSlot),
			},
			PrerequisiteWorkPackage: mapStringSliceToHashes(r.Context.Prerequisites),
		},
		CoreIndex:         uint16(r.CoreIndex),
		AuthorizerHash:    crypto.Hash(stringToHex(r.AuthorizerHash)),
		Output:            stringToHex(r.AuthOutput),
		SegmentRootLookup: segmentRootLookup,
		WorkResults:       mapWorkResults(r.Results),
	}
}

func mapWorkResults(results []WorkResult) []block.WorkResult {
	workResults := make([]block.WorkResult, len(results))
	for i, r := range results {
		var output block.WorkResultOutputOrError
		if val, ok := r.Result["ok"]; ok {
			output.Inner = stringToHex(val)
		} else if _, ok := r.Result["err"]; ok {
			output.Inner = block.NoError // Or appropriate error mapping
		}

		workResults[i] = block.WorkResult{
			ServiceId:              block.ServiceId(r.ServiceID),
			ServiceHashCode:        crypto.Hash(stringToHex(r.CodeHash)),
			PayloadHash:            crypto.Hash(stringToHex(r.PayloadHash)),
			GasPrioritizationRatio: uint64(r.Gas),
			Output:                 output,
		}
	}
	return workResults
}

func mapGuarantee(g Guarantee) block.Guarantee {
	credentials := make([]block.CredentialSignature, len(g.Signatures))
	for i, sig := range g.Signatures {
		var signature [crypto.Ed25519SignatureSize]byte
		copy(signature[:], stringToHex(sig.Signature))
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
		failsOnValidateExtrinsicsGuarantees := true

		t.Run(file.Name(), func(t *testing.T) {
			switch file.Name() {
			case "bad_signature-1.json", "wrong_assignment-1.json":
				failsOnValidateExtrinsicsGuarantees = false // These tests are NOT expected to fail on ValidateExtrinsicGuarantees, but later
			}
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
			err = statetransition.ValidateExtrinsicGuarantees(newBlock.Header, &preState, newBlock.Extrinsic.EG, preState.CoreAssignments, newTimeState, chain)
			//Verify results
			if data.Output.Err != "" && failsOnValidateExtrinsicsGuarantees {
				require.Error(t, err)
				require.EqualError(t, err, strings.ReplaceAll(data.Output.Err, "_", " "))
				return
			}
			require.NoError(t, err)

			intermediateCoreAssignments := statetransition.CalculateIntermediateCoreAssignmentsFromExtrinsics(newBlock.Extrinsic.ED, preState.CoreAssignments)
			intermediateCoreAssignments, _, err = statetransition.CalculateIntermediateCoreAssignmentsFromAvailability(newBlock.Extrinsic.EA, intermediateCoreAssignments, newBlock.Header)
			require.NoError(t, err)

			newCoreAssignments, reporters, err := statetransition.CalculateNewCoreAssignments(newBlock.Extrinsic.EG, intermediateCoreAssignments, preState.ValidatorState, newTimeState, preState.EntropyPool)
			if data.Output.Err != "" {
				require.Error(t, err)
				require.EqualError(t, err, strings.ReplaceAll(data.Output.Err, "_", " "))
				return
			}
			require.NoError(t, err)

			workReports := statetransition.GetAvailableWorkReports(newCoreAssignments)

			_, _, _, _, _, newPendingCoreAuthorizations, _ := statetransition.CalculateWorkReportsAndAccumulate(
				&newBlock.Header,
				&preState,
				newTimeState,
				workReports,
			)

			newCoreAuthorizations := statetransition.CalculateNewCoreAuthorizations(newBlock.Header, newBlock.Extrinsic.EG, newPendingCoreAuthorizations, preState.CoreAuthorizersPool)

			expectedPostState := mapState(data.PostState)

			// Verify reporters if present in output
			if len(data.Output.Ok.Reporters) > 0 {
				// Verify each expected reporter exists in the reporters set
				for _, reporter := range data.Output.Ok.Reporters {
					reporterKey := ed25519.PublicKey(stringToHex(reporter))
					require.True(t, reporters.Has(reporterKey), "Missing expected reporter")
				}
				// Verify no extra reporters
				require.Equal(t, len(data.Output.Ok.Reporters), len(reporters))
			}

			// Verify output.Ok.Reported
			if len(data.Output.Ok.Reported) > 0 {
				for _, r := range data.Output.Ok.Reported {
					wpHash := crypto.Hash(stringToHex(r.WorkPackageHash))
					segRoot := crypto.Hash(stringToHex(r.SegmentTreeRoot))
					found := false
					for _, newCoreAssignment := range newCoreAssignments {
						if newCoreAssignment.WorkReport.WorkPackageSpecification.WorkPackageHash == wpHash &&
							newCoreAssignment.WorkReport.WorkPackageSpecification.SegmentRoot == segRoot {
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

			// Verify authorization pools
			require.Equal(t, len(expectedPostState.CoreAuthorizersPool), len(newCoreAuthorizations),
				"Mismatch in CoreAuthorizersPool length")
			for i := range expectedPostState.CoreAuthorizersPool {
				require.ElementsMatch(t, expectedPostState.CoreAuthorizersPool[i],
					newCoreAuthorizations[i],
					"Mismatch in CoreAuthorizersPool[%d]", i)
			}
		})
	}
}

func mapServices(services []ServiceInfo) service.ServiceState {
	serviceState := make(service.ServiceState)

	for _, s := range services {
		serviceState[block.ServiceId(s.ID)] = service.ServiceAccount{
			Storage:                make(map[crypto.Hash][]byte),
			PreimageLookup:         make(map[crypto.Hash][]byte),
			PreimageMeta:           make(map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots),
			CodeHash:               crypto.Hash(stringToHex(s.Info.CodeHash)),
			Balance:                uint64(s.Info.Balance),
			GasLimitForAccumulator: uint64(s.Info.MinItemGas),
			GasLimitOnTransfer:     uint64(s.Info.MinMemoGas),
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

func mapRecentBlocks(blocks []BlockState) []state.BlockState {
	result := make([]state.BlockState, len(blocks))

	for i, b := range blocks {
		// Map work report hashes
		workReportHashes := make(map[crypto.Hash]crypto.Hash)
		for _, r := range b.Reported {
			wpHash := crypto.Hash(stringToHex(r.WorkPackageHash))
			segHash := crypto.Hash(stringToHex(r.SegmentTreeRoot))
			workReportHashes[wpHash] = segHash
		}

		// MMR peaks conversion
		mmr := make([]*crypto.Hash, len(b.MMR.Peaks))
		for j, peak := range b.MMR.Peaks {
			if peak == "" {
				mmr[j] = nil
				continue
			}
			hash := crypto.Hash(stringToHex(peak))
			mmr[j] = &hash
		}

		headerHash := crypto.Hash(stringToHex(b.HeaderHash))
		stateRoot := crypto.Hash(stringToHex(b.StateRoot))

		result[i] = state.BlockState{
			HeaderHash:            headerHash,
			StateRoot:             stateRoot,
			AccumulationResultMMR: mmr,
			WorkReportHashes:      workReportHashes,
		}
	}
	return result
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
			result[i][j] = crypto.Hash(stringToHex(hash))
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
			WorkReport: &workReport,
			Time:       jamtime.Timeslot(assignment.Timeout),
		}
	}
	return coreAssignments
}

func mapStringSliceToHashes(strings []string) []crypto.Hash {
	hashes := make([]crypto.Hash, len(strings))
	for i, s := range strings {
		hashes[i] = crypto.Hash(stringToHex(s))
	}
	return hashes
}

func mapEntropyPool(entropyStrings []string) state.EntropyPool {
	var entropyPool state.EntropyPool
	for i, entropyHex := range entropyStrings {
		copy(entropyPool[i][:], stringToHex(entropyHex))
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
		RecentBlocks:        mapRecentBlocks(s.RecentBlocks),
		CoreAuthorizersPool: mapAuthPools(s.AuthPools),
		Services:            mapServices(s.Services),
		EntropyPool:         mapEntropyPool(s.Entropy),
	}
}
