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
	Gas         int               `json:"gas"`
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
	Reported  []ReportedWork `json:"reported"`
	Reporters []string       `json:"reporters"`
}

type ReportedWork struct {
	WorkPackageHash string `json:"hash"`
	SegmentTreeRoot string `json:"exports_root"`
}

type JSONData struct {
	Input     Input     `json:"input"`
	PreState  PreState  `json:"pre_state"`
	Output    Output    `json:"output"`
	PostState PostState `json:"post_state"`
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

type PreState struct {
	AvailAssignments []*AvailAssignments `json:"avail_assignments"`
	CurrValidators   []ValidatorKey      `json:"curr_validators"`
	PrevValidators   []ValidatorKey      `json:"prev_validators"`
	Entropy          []string            `json:"entropy"`
	Offenders        []string            `json:"offenders"`
	RecentBlocks     []BlockState        `json:"recent_blocks"`
	AuthPools        [][]string          `json:"auth_pools"`
	Services         []ServiceInfo       `json:"services"`
}

type PostState struct {
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

type MMRPeaks struct {
	Peaks []string `json:"peaks"`
}

func mapKey(v ValidatorKey) crypto.ValidatorKey {
	return crypto.ValidatorKey{
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

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
			filePath := fmt.Sprintf("vectors/reports/tiny/%s", file.Name())
			data, err := ReadJSONFile(filePath)
			require.NoError(t, err, "failed to read JSON file: %s", filePath)

			// Create pre-state
			preState := state.State{}
			preState.Services = mapServices(data.PreState.Services)
			preState.ValidatorState.CurrentValidators = mapValidators(data.PreState.CurrValidators)
			preState.ValidatorState.ArchivedValidators = mapValidators(data.PreState.PrevValidators)
			preState.RecentBlocks = mapRecentBlocks(data.PreState.RecentBlocks)
			preState.CoreAuthorizersPool = mapAuthPools(data.PreState.AuthPools)
			preState.CoreAssignments = mapAvailAssignments(data.PreState.AvailAssignments)
			log.Printf("\n=== Test Details ===")
			log.Printf("Input Slot: %d", data.Input.Slot)
			log.Printf("Number of guarantees: %d", len(data.Input.Guarantees))
			for i, g := range data.Input.Guarantees {
				log.Printf("\nGuarantee[%d]:", i)
				log.Printf("  Core Index: %d", g.Report.CoreIndex)
				log.Printf("  Slot: %d", g.Slot)
				log.Printf("  Validator signatures:")
				for _, sig := range g.Signatures {
					log.Printf("    Validator %d", sig.ValidatorIndex)
				}
			}

			log.Printf("\n=== Validator State ===")
			log.Printf("Current Validators: %d", len(data.PreState.CurrValidators))
			log.Printf("Previous Validators: %d", len(data.PreState.PrevValidators))

			log.Printf("\n=== Entropy Pool ===")
			for i, entropyHex := range data.PreState.Entropy {
				copy(preState.EntropyPool[i][:], stringToHex(entropyHex))
				log.Printf("Entropy[%d]: %s", i, entropyHex)
			}
			// For lookup anchors, store in singleton
			for _, blockState := range data.PreState.RecentBlocks {
				header := block.Header{
					TimeSlotIndex: jamtime.Timeslot(data.Input.Slot),
					ParentHash:    crypto.Hash(stringToHex(blockState.HeaderHash)),
				}
				err := block.AncestorStoreSingleton.StoreHeader(header)
				require.NoError(t, err)
			}

			// Create block
			header := block.Header{
				TimeSlotIndex: jamtime.Timeslot(data.Input.Slot),
			}
			// Create Guarantees extrinsic
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
			log.Printf("\n=== Starting Validation ===")
			newTimeState := statetransition.CalculateNewTimeState(newBlock.Header)
			fmt.Printf("PreState Core Assignments: %+v\n", preState.CoreAssignments)
			err = statetransition.ValidateExtrinsicGuarantees(newBlock.Header, &preState, newBlock.Extrinsic.EG, preState.CoreAssignments, newTimeState, block.AncestorStoreSingleton)
			// Verify results
			if data.Output.Err != "" {
				require.Error(t, err)
				require.EqualError(t, err, strings.ReplaceAll(data.Output.Err, "_", " "))
				return
			}

			safroleInput, err := statetransition.NewSafroleInputFromBlock(newBlock)
			// Verify results
			if data.Output.Err != "" {
				require.Error(t, err)
				require.EqualError(t, err, strings.ReplaceAll(data.Output.Err, "_", " "))
				return
			}

			newEntropyPool, _, _, err := statetransition.UpdateSafroleState(safroleInput, preState.TimeslotIndex, preState.EntropyPool, preState.ValidatorState)
			// Verify results
			if data.Output.Err != "" {
				require.Error(t, err)
				require.EqualError(t, err, strings.ReplaceAll(data.Output.Err, "_", " "))
				return
			}

			intermediateCoreAssignments := statetransition.CalculateIntermediateCoreAssignmentsFromExtrinsics(newBlock.Extrinsic.ED, preState.CoreAssignments)
			intermediateCoreAssignments = statetransition.CalculateIntermediateCoreAssignmentsFromAvailability(newBlock.Extrinsic.EA, intermediateCoreAssignments)
			_, err = statetransition.CalculateNewCoreAssignments(newBlock.Extrinsic.EG, intermediateCoreAssignments, preState.ValidatorState, newTimeState, newEntropyPool)

			// Verify results
			if data.Output.Err != "" {
				require.Error(t, err)
				require.EqualError(t, err, strings.ReplaceAll(data.Output.Err, "_", " "))
				return
			}

			require.NoError(t, err)

			//require.NotNil(t, result)
			//
			//// Compare with expected output
			//if len(data.Output.Ok.Reported) > 0 {
			//	require.Equal(t, len(data.Output.Ok.Reported), len(result.Reported))
			//	for i, Report := range data.Output.Ok.Reported {
			//		require.Equal(t, Report.WorkPackageHash, result.Reported[i].WorkPackageHash.String())
			//		require.Equal(t, Report.SegmentTreeRoot, result.Reported[i].SegmentTreeRoot.String())
			//	}
			//}
			//
			//// Verify reporters
			//if len(data.Output.Ok.Reporters) > 0 {
			//	reporters := make([]ed25519.PublicKey, len(data.Output.Ok.Reporters))
			//	for i, reporter := range data.Output.Ok.Reporters {
			//		reporters[i] = ed25519.PublicKey(stringToHex(reporter))
			//	}
			//	require.ElementsMatch(t, reporters, result.Reporters)
			//}
			//
			//// Verify post state
			//postState := data.PostState
			//require.Equal(t, len(postState.AvailAssignments), len(preState.CoreAssignments))
			//require.ElementsMatch(t, postState.CurrValidators, preState.ValidatorState.CurrentValidators)
			//require.ElementsMatch(t, postState.PrevValidators, preState.ValidatorState.ArchivedValidators)
			//require.Equal(t, len(postState.RecentBlocks), len(preState.RecentBlocks))
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
		log.Printf("Mapping block %d", i)
		log.Printf("  Header hash: %s", b.HeaderHash)
		log.Printf("  Number of reported packages: %d", len(b.Reported))
		// MMR peaks conversion
		mmr := make([]*crypto.Hash, len(b.MMR.Peaks))
		for j, peak := range b.MMR.Peaks {
			if peak == "" {
				mmr[j] = nil
			} else {
				bytes := stringToHex(peak)
				var hash crypto.Hash
				copy(hash[:], bytes)
				mmr[j] = &hash
			}
		}

		// Map work Report hashes
		workReportHashes := make(map[crypto.Hash]crypto.Hash)
		for _, r := range b.Reported {
			log.Printf("  Raw WorkPackageHash: %s", r.WorkPackageHash)
			log.Printf("  Raw SegmentTreeRoot: %s", r.SegmentTreeRoot)

			var wpHash, segHash crypto.Hash
			copy(wpHash[:], stringToHex(r.WorkPackageHash))
			copy(segHash[:], stringToHex(r.SegmentTreeRoot))
			log.Printf("  After conversion - wpHash: %x", wpHash)
			log.Printf("  After conversion - segHash: %x", segHash)
			workReportHashes[wpHash] = segHash
		}

		// Header and state root
		var headerHash, stateRoot crypto.Hash
		copy(headerHash[:], stringToHex(b.HeaderHash))
		copy(stateRoot[:], stringToHex(b.StateRoot))

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
		coreAssignments[i] = state.Assignment{
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
