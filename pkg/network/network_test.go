package network_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/internal/work/results"
	"github.com/eigerco/strawberry/pkg/db/pebble"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	chainState "github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/node"
	"github.com/eigerco/strawberry/pkg/network/peer"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

func setupNodes(ctx context.Context, t *testing.T, state chainState.State, numNodes int) []*node.Node {
	nodes := []*node.Node{}
	validatorsData := safrole.ValidatorsData{}
	nodeKeys := []validator.ValidatorKeys{}
	for i := 0; i < numNodes; i++ {
		pub, prv, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		keys := validator.ValidatorKeys{
			EdPrv: prv,
			EdPub: pub,
		}
		nodeKeys = append(nodeKeys, keys)

		addr := "127.0.0.1"
		port := 10000 + i
		key := crypto.ValidatorKey{}
		key.Ed25519 = pub
		key.Metadata = crypto.MetadataKey(createMockMetadata(t, addr, uint16(port)))
		validatorsData[i] = key
	}
	vstate := validator.ValidatorState{
		CurrentValidators:  validatorsData,
		ArchivedValidators: validatorsData,
		QueuedValidators:   validatorsData,
	}

	state.ValidatorState = vstate

	for i := 0; i < numNodes; i++ {
		addr, err := peer.NewPeerAddressFromMetadata(validatorsData[i].Metadata[:])
		require.NoError(t, err)
		node, err := node.NewNode(ctx, addr, nodeKeys[i], state, uint16(i))
		require.NoError(t, err)
		nodes = append(nodes, node)
	}
	return nodes
}

func stopNode(t *testing.T, node *node.Node) {
	t.Helper()
	if err := node.Stop(); err != nil {
		t.Logf("Failed to stop node: %v", err)
	}
}

func createMockMetadata(t *testing.T, ipStr string, port uint16) []byte {
	ip := net.ParseIP(ipStr)
	require.NotNil(t, ip, "Failed to parse IP")

	// Ensure IP is in IPv6 format
	ipv6 := ip.To16()
	require.NotNil(t, ipv6, "Failed to convert to IPv6")

	// Create metadata: 16 bytes IP + 2 bytes port (little endian)
	metadata := make([]byte, 128) // Full metadata length is 128 bytes
	copy(metadata[:16], ipv6)
	metadata[16] = byte(port & 0xFF)        // Low byte
	metadata[17] = byte((port >> 8) & 0xFF) // High byte

	return metadata
}

// MockImportSegmentsFetcher implements handlers.SegmentsFetcher for testing
type MockImportSegmentsFetcher struct {
	mu                 sync.Mutex
	fetchedSegments    map[crypto.Hash]struct{}
	receivedWorkItems  []work.Item
	receivedExtrinsics []byte
	receivedCoreIndex  uint16
}

func NewMockImportSegmentsFetcher() *MockImportSegmentsFetcher {
	return &MockImportSegmentsFetcher{
		fetchedSegments: make(map[crypto.Hash]struct{}),
	}
}

func (m *MockImportSegmentsFetcher) Fetch(segmentRoot crypto.Hash, segmentIndexes ...uint16) ([]work.Segment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.fetchedSegments[segmentRoot] = struct{}{}
	// Return mock segment data
	seg := work.Segment{}
	copy(seg[:], "mock_segment_data")
	return []work.Segment{seg}, nil
}

func (m *MockImportSegmentsFetcher) RecordWorkPackage(coreIndex uint16, items []work.Item, extrinsics []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.receivedCoreIndex = coreIndex
	m.receivedWorkItems = items
	m.receivedExtrinsics = extrinsics
}

func (m *MockImportSegmentsFetcher) GetFetchedSegmentsCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.fetchedSegments)
}

func (m *MockImportSegmentsFetcher) VerifyReceivedWorkPackage(t *testing.T, expectedCoreIndex uint16, expectedItems []work.Item, expectedExtrinsics []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.receivedCoreIndex != expectedCoreIndex {
		t.Errorf("Expected core index %d, got %d", expectedCoreIndex, m.receivedCoreIndex)
		return false
	}

	if len(m.receivedWorkItems) != len(expectedItems) {
		t.Errorf("Expected %d work items, got %d", len(expectedItems), len(m.receivedWorkItems))
		return false
	}

	// Compare work items
	for i, item := range expectedItems {
		if string(m.receivedWorkItems[i].Payload) != string(item.Payload) {
			t.Errorf("Work item %d payload mismatch", i)
			return false
		}
	}

	if string(m.receivedExtrinsics) != string(expectedExtrinsics) {
		t.Errorf("Extrinsics mismatch")
		return false
	}

	return true
}

type mockAuthorizationInvoker struct{}

func (m mockAuthorizationInvoker) InvokePVM(workPackage work.Package, coreIndex uint16) ([]byte, error) {
	return []byte("Authorized"), nil
}

type MockRefineInvoker struct {
	out []byte
}

func (m MockRefineInvoker) InvokePVM(
	itemIndex uint32,
	workPackage work.Package,
	authorizerHashOutput []byte,
	importedSegments []work.Segment,
	exportOffset uint64,
) ([]byte, []work.Segment, uint64, error) {
	exported := []work.Segment{
		{},
	}
	return m.out, exported, 0, nil
}

func NewMockRefine(out []byte) *MockRefineInvoker {
	return &MockRefineInvoker{
		out: out,
	}
}

// ExtendedWorkPackageSubmissionHandler extends the original handler to record the received package
type ExtendedWorkPackageSubmissionHandler struct {
	*handlers.WorkPackageSubmissionHandler
	MockFetcher *MockImportSegmentsFetcher
}

func NewExtendedWorkPackageSubmissionHandler(fetcher *MockImportSegmentsFetcher) *ExtendedWorkPackageSubmissionHandler {
	_, prv, _ := ed25519.GenerateKey(nil)
	return &ExtendedWorkPackageSubmissionHandler{
		WorkPackageSubmissionHandler: handlers.NewWorkPackageSubmissionHandler(
			fetcher,
			handlers.NewWorkReportGuarantor(uint16(1), prv, mockAuthorizationInvoker{}, NewMockRefine([]byte("out")), chainState.State{Services: make(service.ServiceState)}, peer.NewPeerSet(), nil, nil, nil, nil)),
		MockFetcher: fetcher,
	}
}

// Override HandleStream to record the received package before processing
func (h *ExtendedWorkPackageSubmissionHandler) HandleStream(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error {
	// Read the first message containing the core index and work package
	msg1, err := handlers.ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to read message 1: %w", err)
	}

	if len(msg1.Content) < 2 {
		return fmt.Errorf("message is too short")
	}

	var coreIndex uint16
	if err = jam.Unmarshal(msg1.Content[:2], &coreIndex); err != nil {
		return fmt.Errorf("failed to unmarshal core index: %w", err)
	}

	var pkg work.Package
	if err = jam.Unmarshal(msg1.Content[2:], &pkg); err != nil {
		return fmt.Errorf("failed to unmarshal work package: %w", err)
	}

	if err = pkg.ValidateSize(); err != nil {
		return fmt.Errorf("failed to validate work package: %w", err)
	}

	// Read the second message containing extrinsics
	msg2, err := handlers.ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to read extrinsics message: %w", err)
	}
	extrinsics := msg2.Content

	// Record the received work package for verification
	h.MockFetcher.RecordWorkPackage(coreIndex, pkg.WorkItems, extrinsics)

	// Process imported segments as in the original handler
	for _, item := range pkg.WorkItems {
		for _, imp := range item.ImportedSegments {
			_, err = h.Fetcher.Fetch(imp.Hash)
			if err != nil {
				continue
			}
		}
	}

	return stream.Close()
}

func TestTwoNodesAnnounceBlocks(t *testing.T) {
	// Create contexts for both nodes
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nodes := setupNodes(ctx, t, chainState.State{}, 2)
	node1 := nodes[0]
	node2 := nodes[1]
	// Start both nodes
	err := node1.Start()
	require.NoError(t, err)
	defer stopNode(t, node1)

	err = node2.Start()
	require.NoError(t, err)
	defer stopNode(t, node2)

	// Allow time for the nodes to start
	time.Sleep(100 * time.Millisecond)

	// Connect node1 to node2
	addr, err := peer.NewPeerAddressFromMetadata(nodes[1].ValidatorManager.State.CurrentValidators[1].Metadata[:])
	require.NoError(t, err)
	err = node1.ConnectToPeer(addr)
	require.NoError(t, err)

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	// Verify nodes are connected
	node1Peer := node1.PeersSet.GetByAddress(addr.String())
	require.NotNil(t, node1Peer, "Node1 should have Node2 as a peer")

	// Create a mock block for node1 to announce to node2
	mockHeader := &block.Header{
		ParentHash:       node1.BlockService.LatestFinalized.Hash,
		TimeSlotIndex:    jamtime.Timeslot(2),
		BlockAuthorIndex: 0,
	}
	mockBLock := &block.Block{
		Header: *mockHeader,
	}
	err = node1.BlockService.Store.PutBlock(*mockBLock)
	require.NoError(t, err)

	// Node1 announces the block to node2
	err = node1.AnnounceBlock(ctx, mockHeader, node1Peer)
	require.NoError(t, err)

	// Allow time for the announcement to be processed
	time.Sleep(100 * time.Millisecond)

	// Calculate the hash of the mock header
	headerHash, err := mockHeader.Hash()
	require.NoError(t, err)

	// Check if node2 has added the block to its known leaves
	_, exists := node2.BlockService.KnownLeaves[headerHash]
	require.True(t, exists, "Node2 should have the announced block in its known leaves")

	// Verify the block is in node2's store
	header, err := node2.BlockService.Store.GetHeader(headerHash)
	require.NoError(t, err, "Node2 should have the header in its store")
	require.Equal(t, mockHeader.TimeSlotIndex, header.TimeSlotIndex, "The stored header should match the announced one")

	t.Log("Successfully verified block announcement between nodes")
}

func TestTwoNodesRequestBlock(t *testing.T) {
	// Create contexts for both nodes
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nodes := setupNodes(ctx, t, chainState.State{}, 2)
	node1 := nodes[0]
	node2 := nodes[1]
	// Start both nodes
	err := node1.Start()
	require.NoError(t, err)
	defer stopNode(t, node1)

	err = node2.Start()
	require.NoError(t, err)
	defer stopNode(t, node2)

	// Allow time for the nodes to start
	time.Sleep(100 * time.Millisecond)

	// Connect node1 to node2
	node2Addr, err := peer.NewPeerAddressFromMetadata(nodes[1].ValidatorManager.State.CurrentValidators[1].Metadata[:])
	require.NoError(t, err)
	err = node1.ConnectToPeer(node2Addr)
	require.NoError(t, err)

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	// Verify nodes are connected
	node2Peer := node1.PeersSet.GetByAddress(node2Addr.String())
	require.NotNil(t, node2Peer, "Node1 should have Node2 as a peer")

	// Create a mock block for node1 to announce to node2
	mockHeader := &block.Header{
		ParentHash:       node1.BlockService.LatestFinalized.Hash,
		TimeSlotIndex:    jamtime.Timeslot(2),
		BlockAuthorIndex: 0,
	}
	mockBLock := &block.Block{
		Header: *mockHeader,
	}
	err = node2.BlockService.Store.PutBlock(*mockBLock)
	require.NoError(t, err)
	hash, err := mockBLock.Header.Hash()
	require.NoError(t, err)
	blocks, err := node1.RequestBlocks(ctx, hash, false, 1, node2Peer.Ed25519Key)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	recievedHash, err := blocks[0].Header.Hash()
	require.NoError(t, err)
	require.Equal(t, hash, recievedHash)
}

func TestTwoNodesSubmitWorkPackage(t *testing.T) {
	// Create contexts for both nodes
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Setup nodes using the existing setup function
	nodes := setupNodes(ctx, t, chainState.State{}, 2)
	node1 := nodes[0]
	node2 := nodes[1]

	// Create a mock fetcher for tracking received packages
	mockFetcher := NewMockImportSegmentsFetcher()

	// Replace the default handler with our extended handler in node2
	// TODO: remove mocks in this e2e test
	extendedHandler := NewExtendedWorkPackageSubmissionHandler(mockFetcher)
	node2.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkPackageSubmit, extendedHandler)

	// Start both nodes
	err := node1.Start()
	require.NoError(t, err)
	defer stopNode(t, node1)

	err = node2.Start()
	require.NoError(t, err)
	defer stopNode(t, node2)

	// Allow time for the nodes to start
	time.Sleep(100 * time.Millisecond)

	// Connect node1 to node2
	node2Addr, err := peer.NewPeerAddressFromMetadata(nodes[1].ValidatorManager.State.CurrentValidators[1].Metadata[:])
	require.NoError(t, err)
	err = node1.ConnectToPeer(node2Addr)
	require.NoError(t, err)

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	// Verify nodes are connected
	node2Peer := node1.PeersSet.GetByAddress(node2Addr.String())
	require.NotNil(t, node2Peer, "Node1 should have Node2 as a peer")

	// Create a test work package with imported segments
	importedSegment := work.ImportedSegment{
		Hash: crypto.Hash{1, 2, 3, 4, 5}, // Example hash
	}

	workItem := work.Item{
		Payload:          []byte("work item payload"),
		ImportedSegments: []work.ImportedSegment{importedSegment},
	}

	workPackage := work.Package{
		WorkItems: []work.Item{workItem},
	}

	extrinsics := []byte("extrinsic_data_for_testing")
	coreIndex := uint16(1)

	// Submit the work package from node1 to node2
	err = node1.SubmitWorkPackage(ctx, coreIndex, workPackage, extrinsics, node2Peer.Ed25519Key)
	require.NoError(t, err)

	// Wait for the submission to be processed
	time.Sleep(500 * time.Millisecond)

	// Verify that node2 received and processed the work package correctly
	receivedCorrectly := mockFetcher.VerifyReceivedWorkPackage(t, coreIndex, workPackage.WorkItems, extrinsics)
	require.True(t, receivedCorrectly, "Work package was not received correctly")

	// Verify that the imported segments were fetched
	segmentsFetched := mockFetcher.GetFetchedSegmentsCount()
	require.Equal(t, 1, segmentsFetched, "Expected 1 imported segment to be fetched")

	t.Log("Work package submission test completed successfully")
}

func TestWorkPackageSubmissionToWorkReportGuarantee(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	coreIndex := uint16(1)

	// Create a mock work package bundle with authorization
	authCode := []byte("auth token")
	authHash := crypto.HashData(authCode)
	pkg := work.Package{
		AuthorizationToken: authCode,
		AuthorizerService:  1,
		AuthCodeHash:       authHash,
		Parameterization:   []byte("params"),
		Context: block.RefinementContext{
			LookupAnchor: block.RefinementContextLookupAnchor{
				Timeslot: jamtime.Timeslot(0),
			},
		},
		WorkItems: []work.Item{
			{
				ServiceId:        1,
				CodeHash:         crypto.Hash{},
				Payload:          []byte("payload"),
				ExportedSegments: 1,
			},
		},
	}

	builder, err := work.NewPackageBundleBuilder(pkg, make(map[crypto.Hash]crypto.Hash), make(map[crypto.Hash][]work.Segment), []byte{})
	require.NoError(t, err)

	bundle, err := builder.Build()
	require.NoError(t, err)

	// Generate validator key for mainGuarantor
	pub, prv, _ := ed25519.GenerateKey(nil)
	serviceState := getServiceState()

	// Add the auth hash to the core's authorization pool
	pool := chainState.CoreAuthorizersPool{}
	pool[coreIndex] = []crypto.Hash{bundle.Package().AuthCodeHash}
	currentState := chainState.State{
		Services:            serviceState,
		CoreAuthorizersPool: pool,
		TimeslotIndex:       jamtime.Timeslot(599),
	}

	// Spin up 6 nodes
	// 0: builder
	// 1: mainGuarantor
	// 2-3: remote co-guarantors
	// 4-5: validators
	nodes := setupNodes(ctx, t, currentState, 6)
	builderNode := nodes[0]
	mainGuarantor := nodes[1]
	remoteGuarantor2 := nodes[2]
	remoteGuarantor3 := nodes[3]
	validator1 := nodes[4]
	validator2 := nodes[5]

	require.NoError(t, builderNode.Start())
	defer stopNode(t, builderNode)
	require.NoError(t, mainGuarantor.Start())
	defer stopNode(t, mainGuarantor)
	require.NoError(t, remoteGuarantor2.Start())
	defer stopNode(t, remoteGuarantor2)
	require.NoError(t, remoteGuarantor3.Start())
	defer stopNode(t, remoteGuarantor3)
	require.NoError(t, validator1.Start())
	defer stopNode(t, validator1)
	require.NoError(t, validator2.Start())
	defer stopNode(t, validator2)

	time.Sleep(100 * time.Millisecond)

	// Extract addresses from metadata for connecting nodes
	mainGuarantorAddr, err := peer.NewPeerAddressFromMetadata(
		nodes[1].ValidatorManager.State.CurrentValidators[1].Metadata[:],
	)
	require.NoError(t, err)

	remoteGuarantor2Addr, err := peer.NewPeerAddressFromMetadata(
		nodes[2].ValidatorManager.State.CurrentValidators[2].Metadata[:],
	)
	require.NoError(t, err)

	remoteGuarantor3Addr, err := peer.NewPeerAddressFromMetadata(nodes[3].ValidatorManager.State.CurrentValidators[3].Metadata[:])
	require.NoError(t, err)

	validator1Addr, err := peer.NewPeerAddressFromMetadata(nodes[4].ValidatorManager.State.CurrentValidators[4].Metadata[:])
	require.NoError(t, err)

	validator2Addr, err := peer.NewPeerAddressFromMetadata(nodes[5].ValidatorManager.State.CurrentValidators[5].Metadata[:])
	require.NoError(t, err)

	// Connect mainGuarantor to co-guarantors and validators
	require.NoError(t, mainGuarantor.ConnectToPeer(remoteGuarantor2Addr))
	require.NoError(t, mainGuarantor.ConnectToPeer(remoteGuarantor3Addr))

	require.NoError(t, mainGuarantor.ConnectToPeer(validator1Addr))
	require.NoError(t, mainGuarantor.ConnectToPeer(validator2Addr))

	// Connect builder to the mainGuarantor (submitting WP will happen over this connection)
	require.NoError(t, builderNode.ConnectToPeer(mainGuarantorAddr))
	time.Sleep(100 * time.Millisecond)

	// Register peer set with mainGuarantor
	peerSet := peer.NewPeerSet()

	// remote guarantor
	peer2 := mainGuarantor.GetByAddress(remoteGuarantor2Addr.String())
	index2 := uint16(2)
	peer2.ValidatorIndex = &index2
	peer2.Ed25519Key = pub
	peerSet.AddPeer(peer2)

	// remote guarantor
	peer3 := mainGuarantor.GetByAddress(remoteGuarantor3Addr.String())
	index3 := uint16(3)
	peer3.ValidatorIndex = &index3
	peer3.Ed25519Key = pub
	peerSet.AddPeer(peer3)

	// validators
	peer4 := mainGuarantor.GetByAddress(validator1Addr.String())
	index4 := uint16(4)
	peer4.ValidatorIndex = &index4
	peerSet.AddPeer(peer4)
	peer5 := mainGuarantor.GetByAddress(validator2Addr.String())
	index5 := uint16(5)
	peer5.ValidatorIndex = &index5
	peerSet.AddPeer(peer5)

	mainGuarantor.PeersSet = peerSet

	// Set current + next validators in state (needed for distribution step)
	var validators safrole.ValidatorsData
	validators[4] = crypto.ValidatorKey{
		Ed25519: peer4.Ed25519Key,
	}
	validators[5] = crypto.ValidatorKey{
		Ed25519: peer5.Ed25519Key,
	}
	currentState.ValidatorState.CurrentValidators = validators
	currentState.ValidatorState.SafroleState = safrole.State{
		NextValidators: validators,
	}

	requester := handlers.NewWorkReportRequester()

	mockRefine := NewMockRefine([]byte("out"))
	shardData, expectedWorkReport, err := results.ProduceWorkReport(mockRefine, getServiceState(), []byte("Authorized"), coreIndex, bundle, make(map[crypto.Hash]crypto.Hash))
	require.NoError(t, err)
	require.NotNil(t, shardData)

	expectedWorkReportHash, err := expectedWorkReport.Hash()
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		// start with an empty store
		kvStore, err := pebble.NewKVStore()
		require.NoError(t, err)
		defer kvStore.Close()

		reportStore := store.NewWorkReport(kvStore)

		// TODO: remove mocks in this e2e test
		mockPVMSharingHandler := handlers.NewWorkPackageSharingHandler(
			mockAuthorizationInvoker{},
			mockRefine,
			prv,
			serviceState,
			reportStore,
		)

		// override handlers in order to mock pvm invocations
		remoteGuarantor2.WorkPackageSharingHandler = mockPVMSharingHandler
		remoteGuarantor2.WorkPackageSharingHandler.SetCurrentCore(coreIndex)
		remoteGuarantor2.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkPackageShare, remoteGuarantor2.WorkPackageSharingHandler)
		remoteGuarantor2.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkReportRequest, handlers.NewWorkReportRequestHandler(reportStore))

		remoteGuarantor3.WorkPackageSharingHandler = mockPVMSharingHandler
		remoteGuarantor3.WorkPackageSharingHandler.SetCurrentCore(coreIndex)
		remoteGuarantor3.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkPackageShare, remoteGuarantor3.WorkPackageSharingHandler)
		remoteGuarantor3.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkReportRequest, handlers.NewWorkReportRequestHandler(reportStore))

		// TODO: remove mocks in this e2e test
		mainGuarantor.WorkReportGuarantor = handlers.NewWorkReportGuarantor(
			uint16(1),
			prv,
			mockAuthorizationInvoker{},
			mockRefine,
			currentState,
			peerSet,
			reportStore,
			requester,
			handlers.NewWorkPackageSharingRequester(),
			handlers.NewWorkReportDistributionSender(),
		)

		submissionHandler := handlers.NewWorkPackageSubmissionHandler(
			&MockImportSegmentsFetcher{},
			mainGuarantor.WorkReportGuarantor)
		mainGuarantor.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkPackageSubmit, submissionHandler)

		mainGuarantor.WorkReportGuarantor.SetGuarantors([]*peer.Peer{
			peer2,
			peer3,
		})
		// send work package builder->guarantor to initiate the flow (CE-133 → CE-134 → CE-135)
		err = builderNode.SubmitWorkPackage(ctx, coreIndex, bundle.Package(), []byte{}, mainGuarantor.ValidatorManager.Keys.EdPub)
		require.NoError(t, err)

		time.Sleep(500 * time.Millisecond)

		report, err := mainGuarantor.RequestWorkReport(ctx, expectedWorkReportHash, peer2.Ed25519Key)
		require.NoError(t, err)

		require.Equal(t, &expectedWorkReport, report)
	})
	t.Run("success_local_ignored", func(t *testing.T) {
		// start with an empty store
		kvStore, err := pebble.NewKVStore()
		require.NoError(t, err)
		defer kvStore.Close()

		reportStore := store.NewWorkReport(kvStore)

		// TODO: remove mocks in this e2e test
		mockPVMSharingHandler := handlers.NewWorkPackageSharingHandler(
			mockAuthorizationInvoker{},
			mockRefine,
			prv,
			serviceState,
			reportStore,
		)

		// override handlers in order to mock pvm invocations
		remoteGuarantor2.WorkPackageSharingHandler = mockPVMSharingHandler
		remoteGuarantor2.WorkPackageSharingHandler.SetCurrentCore(coreIndex)
		remoteGuarantor2.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkPackageShare, remoteGuarantor2.WorkPackageSharingHandler)
		remoteGuarantor2.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkReportRequest, handlers.NewWorkReportRequestHandler(reportStore))

		remoteGuarantor3.WorkPackageSharingHandler = mockPVMSharingHandler
		remoteGuarantor3.WorkPackageSharingHandler.SetCurrentCore(coreIndex)
		remoteGuarantor3.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkPackageShare, remoteGuarantor3.WorkPackageSharingHandler)
		remoteGuarantor3.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkReportRequest, handlers.NewWorkReportRequestHandler(reportStore))

		// produce different work report/hash locally, this will result to fetch and use remote work report
		// TODO: remove mocks in this e2e test
		mainGuarantor.WorkReportGuarantor = handlers.NewWorkReportGuarantor(
			uint16(1),
			prv,
			mockAuthorizationInvoker{},
			NewMockRefine([]byte("different output")), // produce different hash in local refinement
			currentState,
			peerSet,
			reportStore,
			requester,
			handlers.NewWorkPackageSharingRequester(),
			handlers.NewWorkReportDistributionSender(),
		)

		submissionHandler := handlers.NewWorkPackageSubmissionHandler(
			&MockImportSegmentsFetcher{},
			mainGuarantor.WorkReportGuarantor)
		mainGuarantor.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkPackageSubmit, submissionHandler)

		mainGuarantor.WorkReportGuarantor.SetGuarantors([]*peer.Peer{
			peer2,
			peer3,
		})

		// send work package builder->guarantor to initiate the flow (CE-133 → CE-134 → CE-135)
		err = builderNode.SubmitWorkPackage(ctx, coreIndex, bundle.Package(), []byte{}, mainGuarantor.ValidatorManager.Keys.EdPub)
		require.NoError(t, err)

		time.Sleep(500 * time.Millisecond)

		report, err := mainGuarantor.RequestWorkReport(ctx, expectedWorkReportHash, peer2.Ed25519Key)
		require.NoError(t, err)

		require.Equal(t, &expectedWorkReport, report)
	})
}

func getServiceState() service.ServiceState {
	authCode := []byte("auth token")
	hash := crypto.HashData(authCode)
	timeslot := jamtime.Timeslot(0)

	metaKey := service.PreImageMetaKey{
		Hash:   hash,
		Length: service.PreimageLength(len(authCode)),
	}
	return service.ServiceState{
		1: {
			PreimageLookup: map[crypto.Hash][]byte{
				hash: authCode,
			},
			PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
				metaKey: {timeslot},
			},
		},
	}
}

func TestTwoNodesDistributeShard(t *testing.T) {
	// Create contexts for both nodes
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Setup nodes using the existing setup function
	nodes := setupNodes(ctx, t, chainState.State{}, 2)
	node1 := nodes[0]
	node2 := nodes[1]

	erasureRoot := testutils.RandomHash(t)
	shardIndex := uint16(4)
	expectedBundleShard := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	expectedSegmentShard := [][]byte{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		{13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
	}

	hash1 := testutils.RandomHash(t)
	hash2 := testutils.RandomHash(t)

	expectedJustification := [][]byte{hash1[:], hash2[:], append(hash1[:], hash2[:]...)}

	validatorSvc := validator.NewValidatorServiceMock()
	validatorSvc.On("ShardDistribution", mock.Anything, erasureRoot, shardIndex).Return(expectedBundleShard, expectedSegmentShard, expectedJustification, nil)

	node2.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindShardDist, handlers.NewShardDistributionHandler(validatorSvc))

	// Start both nodes
	err := node1.Start()
	require.NoError(t, err)
	defer stopNode(t, node1)

	err = node2.Start()
	require.NoError(t, err)
	defer stopNode(t, node2)

	// Allow time for the nodes to start
	time.Sleep(100 * time.Millisecond)

	// Connect node1 to node2
	node2Addr, err := peer.NewPeerAddressFromMetadata(nodes[1].ValidatorManager.State.CurrentValidators[1].Metadata[:])
	require.NoError(t, err)
	err = node1.ConnectToPeer(node2Addr)
	require.NoError(t, err)

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	// Verify nodes are connected
	node2Peer := node1.PeersSet.GetByAddress(node2Addr.String())
	require.NotNil(t, node2Peer, "Node1 should have Node2 as a peer")

	node1.ValidatorManager.Index = 1

	// Send shards and justification
	bundleShard, segmentShard, justification, err := node1.ShardDistributionSend(ctx, node2Peer.Ed25519Key, 3, erasureRoot)
	require.NoError(t, err)
	assert.Equal(t, expectedBundleShard, bundleShard)
	assert.Equal(t, expectedSegmentShard, segmentShard)
	assert.Equal(t, expectedJustification, justification)

	t.Log("Shard distribution has been sent")
}

func TestTwoNodesAuditShard(t *testing.T) {
	// Create contexts for both nodes
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Setup nodes using the existing setup function
	nodes := setupNodes(ctx, t, chainState.State{}, 2)
	node1 := nodes[0]
	node2 := nodes[1]

	erasureRoot := testutils.RandomHash(t)
	shardIndex := uint16(100)
	expectedBundleShard := []byte{91, 28, 37, 46, 55, 64, 73, 82, 91, 20}

	hash1 := testutils.RandomHash(t)
	hash2 := testutils.RandomHash(t)

	expectedJustification := [][]byte{hash1[:], hash2[:], append(hash1[:], hash2[:]...)}

	err := node2.AvailabilityStore.PutShardsAndJustification(erasureRoot, shardIndex, expectedBundleShard, nil, expectedJustification)
	require.NoError(t, err)

	// Start both nodes
	err = node1.Start()
	require.NoError(t, err)
	defer stopNode(t, node1)

	err = node2.Start()
	require.NoError(t, err)
	defer stopNode(t, node2)

	// Allow time for the nodes to start
	time.Sleep(100 * time.Millisecond)

	// Connect node1 to node2
	node2Addr, err := peer.NewPeerAddressFromMetadata(nodes[1].ValidatorManager.State.CurrentValidators[1].Metadata[:])
	require.NoError(t, err)
	err = node1.ConnectToPeer(node2Addr)
	require.NoError(t, err)

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	// Verify nodes are connected
	node2Peer := node1.PeersSet.GetByAddress(node2Addr.String())
	require.NotNil(t, node2Peer, "Node1 should have Node2 as a peer")

	// Send shards and justification
	bundleShard, justification, err := node1.AuditShardRequestSend(ctx, node2Peer.Ed25519Key, erasureRoot, shardIndex)
	require.NoError(t, err)
	assert.Equal(t, expectedBundleShard, bundleShard)
	assert.Equal(t, expectedJustification, justification)

	t.Log("Audit shard has been sent")
}

func TestTwoNodesSegmentShard(t *testing.T) {
	// Create contexts for both nodes
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Setup nodes using the existing setup function
	nodes := setupNodes(ctx, t, chainState.State{}, 2)
	node1 := nodes[0]
	node2 := nodes[1]

	erasureRoot := testutils.RandomHash(t)
	shardIndex := uint16(100)
	segmentIndexes := []uint16{0, 1, 2}
	expectedSegmentShard := [][]byte{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		{13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
		{23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34},
	}

	err := node2.AvailabilityStore.PutShardsAndJustification(erasureRoot, shardIndex, nil, expectedSegmentShard, nil)
	require.NoError(t, err)

	// Start both nodes
	err = node1.Start()
	require.NoError(t, err)
	defer stopNode(t, node1)

	err = node2.Start()
	require.NoError(t, err)
	defer stopNode(t, node2)

	// Allow time for the nodes to start
	time.Sleep(100 * time.Millisecond)

	// Connect node1 to node2
	node2Addr, err := peer.NewPeerAddressFromMetadata(nodes[1].ValidatorManager.State.CurrentValidators[1].Metadata[:])
	require.NoError(t, err)
	err = node1.ConnectToPeer(node2Addr)
	require.NoError(t, err)

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	// Verify nodes are connected
	node2Peer := node1.PeersSet.GetByAddress(node2Addr.String())
	require.NotNil(t, node2Peer, "Node1 should have Node2 as a peer")

	// Send shards request
	segmentShards, err := node1.SegmentShardRequestSend(ctx, node2Peer.Ed25519Key, erasureRoot, shardIndex, segmentIndexes)
	require.NoError(t, err)
	assert.Equal(t, expectedSegmentShard, segmentShards)

	t.Log("Segments shards have been sent")
}

func TestTwoNodesSegmentJustificationShard(t *testing.T) {
	// Create contexts for both nodes
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Setup nodes using the existing setup function
	nodes := setupNodes(ctx, t, chainState.State{}, 2)
	node1 := nodes[0]
	node2 := nodes[1]

	erasureRoot := testutils.RandomHash(t)
	shardIndex := uint16(77)
	segmentIndexes := []uint16{0, 1, 2}
	expectedSegmentShard := [][]byte{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		{13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
		{23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34},
	}
	hash1 := testutils.RandomHash(t)
	hash2 := testutils.RandomHash(t)
	hash3 := testutils.RandomHash(t)
	hash4 := testutils.RandomHash(t)

	baseJustification := [][]byte{hash1[:], hash2[:], append(hash3[:], hash4[:]...)}

	err := node2.AvailabilityStore.PutShardsAndJustification(erasureRoot, shardIndex, nil, expectedSegmentShard, baseJustification)
	require.NoError(t, err)

	// Start both nodes
	err = node1.Start()
	require.NoError(t, err)
	defer stopNode(t, node1)

	err = node2.Start()
	require.NoError(t, err)
	defer stopNode(t, node2)

	// Allow time for the nodes to start
	time.Sleep(100 * time.Millisecond)

	// Connect node1 to node2
	node2Addr, err := peer.NewPeerAddressFromMetadata(nodes[1].ValidatorManager.State.CurrentValidators[1].Metadata[:])
	require.NoError(t, err)
	err = node1.ConnectToPeer(node2Addr)
	require.NoError(t, err)

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	// Verify nodes are connected
	node2Peer := node1.PeersSet.GetByAddress(node2Addr.String())
	require.NotNil(t, node2Peer, "Node1 should have Node2 as a peer")

	// Send shards request
	segmentShards, justification, err := node1.SegmentShardRequestJustificationSend(ctx, node2Peer.Ed25519Key, erasureRoot, shardIndex, segmentIndexes)
	require.NoError(t, err)
	assert.Equal(t, expectedSegmentShard, segmentShards)
	if assert.Len(t, justification, len(expectedSegmentShard)) {
		for i := 0; i < len(expectedSegmentShard); i++ {
			assert.Equal(t, justification[i][:3], baseJustification)
		}
	}

	t.Log("Segments shards have been sent")
}

// TestTwoNodesStateRequest tests the state request functionality between two nodes
func TestTwoNodesStateRequest(t *testing.T) {
	// Create contexts for both nodes
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nodes := setupNodes(ctx, t, chainState.State{}, 2)
	node1 := nodes[0]
	node2 := nodes[1]

	// Create trie with keys and values
	keys, values := setupTestKeys()
	pairs := make([][2][]byte, len(keys))
	for i := range keys {
		pairs[i] = [2][]byte{keys[i], values[i]}
	}
	// Store the trie in node2's state trie
	hash, err := node2.StateTrieStore.MerklizeAndCommit(pairs)
	require.NoError(t, err)

	// Start both nodes
	err = node1.Start()
	require.NoError(t, err)
	defer stopNode(t, node1)

	err = node2.Start()
	require.NoError(t, err)
	defer stopNode(t, node2)

	// Allow time for the nodes to start
	time.Sleep(100 * time.Millisecond)

	// Connect node1 to node2
	node2Addr, err := peer.NewPeerAddressFromMetadata(nodes[1].ValidatorManager.State.CurrentValidators[1].Metadata[:])
	require.NoError(t, err)
	err = node1.ConnectToPeer(node2Addr)
	require.NoError(t, err)

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	// Verify nodes are connected
	node2Peer := node1.PeersSet.GetByAddress(node2Addr.String())
	require.NotNil(t, node2Peer, "Node1 should have Node2 as a peer")

	// Node 1 requests state from Node 2
	// Send state request with start key = 3, end key = 4
	// This should return keys 3 and 4, with their values and 5 boundary nodes
	stateResponse, err := node1.RequestState(ctx, hash, toFixed31Byte(keys[2]), toFixed31Byte(keys[3]), uint32(10000000), node2Peer.Ed25519Key)
	require.NoError(t, err)
	require.Len(t, stateResponse.Pairs, 2)
	require.Equal(t, stateResponse.Pairs[0].Key, toFixed31Byte(keys[2]))
	require.Equal(t, stateResponse.Pairs[0].Value, values[2])
	require.Equal(t, stateResponse.Pairs[1].Key, toFixed31Byte(keys[3]))
	require.Equal(t, stateResponse.Pairs[1].Value, values[3])
	require.Equal(t, len(stateResponse.BoundaryNodes), 5)
}

// setupTestKeys creates test keys and values with a predictable binary trie structure
func toFixed31Byte(slice []byte) [31]byte {
	var fixed [31]byte
	copy(fixed[:], slice)
	return fixed
}

// setupTestKeys creates test keys and values with a predictable binary trie structure
/*
                          			  ROOT
                 	   /           	             \
           LEFT BRANCH(0)    		    		 RIGHT BRANCH(1)
            /        \       		         /       			   \
      0x01(00)      0x41(01) 		 LEFT BRANCH(10) 			RIGHT RIGHT BRANCH(11)
                      		         /          \    			    /          \
                      		   0x81(100)     0xA1(101) 		0xC1(110)  RIGHT RIGHT RIGHT BRANCH(111)
                      		                             		         /          \
                      		                       	     		  0xE1(1110)     0xFF(1111)

Keys:
0x01 - 0000 0001 - Key 1 - Path: 00 (Left, Left)
0x41 - 0100 0001 - Key 2 - Path: 01 (Left, Right)
0x81 - 1000 0001 - Key 3 - Path: 100 (Right, Left, Left)
0xA1 - 1010 0001 - Key 4 - Path: 101 (Right, Left, Right)
0xC1 - 1100 0001 - Key 5 - Path: 110 (Right, Right, Left)
0xE1 - 1110 0001 - Key 6 - Path: 1110 (Right, Right, Right, Left)
0xFF - 1111 1111 - Key 7 - Path: 1111 (Right, Right, Right, Right)
*/

func setupTestKeys() ([][]byte, [][]byte) {
	// Create keys with a structure that ensures a binary tree with various depths
	// Keys are designed to create a deeper structure on the right side
	keys := [][]byte{
		{0x01, 0x01, 0x01}, // 0000 0001 ... - Path starts with 0 (Left, Left branch)
		{0x41, 0x01, 0x01}, // 0100 0001 ... - Path starts with 0 (Left, Right branch)
		{0x81, 0x01, 0x01}, // 1000 0001 ... - Path starts with 1 (Right, Left branch)
		{0xA1, 0x01, 0x01}, // 1010 0001 ... - Path starts with 1 (Right, Left, Right branch)
		{0xC1, 0x01, 0x01}, // 1100 0001 ... - Path starts with 1 (Right, Right, Left branch)
		{0xE1, 0x01, 0x01}, // 1110 0001 ... - Path starts with 1 (Right. Right, Right, Left branch)
		{0xFF, 0x01, 0x01}, // 1111 1111 ... - Path starts with 1 (Right, Right, Right, Right branch)
	}

	// Pad keys to full length (31 bytes for the trie)
	for i := range keys {
		keys[i] = append(keys[i], bytes.Repeat([]byte{0x00}, 32-len(keys[i]))...)
	}

	// Create values with known sizes
	fixedValueSize := 16
	values := make([][]byte, len(keys))
	for i := range values {
		values[i] = fmt.Appendf(nil, "Value-%d-%s", i, strings.Repeat("X", fixedValueSize-8))
	}

	return keys, values
}

func connectPeer(t *testing.T, nodes []*node.Node, fromIndex, toIndex uint16) *peer.Peer {
	t.Helper()
	toAddr, err := peer.NewPeerAddressFromMetadata(nodes[fromIndex].ValidatorManager.State.CurrentValidators[toIndex].Metadata[:])
	require.NoError(t, err)

	err = nodes[fromIndex].ConnectToPeer(toAddr)
	require.NoError(t, err)

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	// Verify nodes are connected
	fromPeer := nodes[fromIndex].PeersSet.GetByAddress(toAddr.String())
	require.NotNil(t, fromPeer, "Node1 should have Node2 as a peer")

	// Manually set the ValidatorIndex so that later we can identify the peer using PeersSet.GetByValidatorIndex()
	fromPeer.ValidatorIndex = &nodes[toIndex].ValidatorManager.Index

	nodes[fromIndex].PeersSet.AddPeer(fromPeer)
	return fromPeer
}

func TestAnnounceBlocksAndDistributeShards(t *testing.T) {
	// Create contexts for both nodes
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nodes := setupNodes(ctx, t, chainState.State{}, 3)
	const (
		node1Id      = 0
		guarantor1Id = 1
		assurer1Id   = 2
	)

	erasureRoot := testutils.RandomHash(t)

	mockValidatorService := validator.NewValidatorServiceMock()

	bundleShard := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	segmentsShards := [][]byte{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		{13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
	}

	hash1 := testutils.RandomHash(t)
	hash2 := testutils.RandomHash(t)

	justification := [][]byte{hash1[:], hash2[:], append(hash1[:], hash2[:]...)}

	// TODO once shard distribution is implemented we should take the shards from the actual service instead of mocking it
	mockValidatorService.On("ShardDistribution", mock.Anything, erasureRoot, nodes[assurer1Id].ValidatorManager.Index).
		Return(bundleShard, segmentsShards, justification, nil).Once()

	nodes[guarantor1Id].ProtocolManager.Registry.RegisterHandler(protocol.StreamKindShardDist, handlers.NewShardDistributionHandler(mockValidatorService))

	err := nodes[node1Id].Start()
	require.NoError(t, err)
	defer stopNode(t, nodes[node1Id])

	err = nodes[guarantor1Id].Start()
	require.NoError(t, err)
	defer stopNode(t, nodes[guarantor1Id])

	err = nodes[assurer1Id].Start()
	require.NoError(t, err)
	defer stopNode(t, nodes[assurer1Id])

	// Allow time for the nodes to start
	time.Sleep(100 * time.Millisecond)

	// Connect node1 to assurer1
	assurer1Peer := connectPeer(t, nodes, node1Id, assurer1Id)

	// Connect the assurer to at least one guarantor
	connectPeer(t, nodes, assurer1Id, guarantor1Id)

	mockHeader := &block.Header{
		ParentHash:       nodes[node1Id].BlockService.LatestFinalized.Hash,
		TimeSlotIndex:    jamtime.Timeslot(2),
		BlockAuthorIndex: 0,
	}

	mockBLock := &block.Block{
		Header: *mockHeader,
		Extrinsic: block.Extrinsic{
			EG: block.GuaranteesExtrinsic{
				Guarantees: []block.Guarantee{
					{
						WorkReport: block.WorkReport{
							WorkPackageSpecification: block.WorkPackageSpecification{
								ErasureRoot: erasureRoot,
							},
						},
						Credentials: []block.CredentialSignature{{
							ValidatorIndex: nodes[guarantor1Id].ValidatorManager.Index,
						}},
					},
				},
			},
		},
	}

	err = nodes[node1Id].BlockService.Store.PutBlock(*mockBLock)
	require.NoError(t, err)

	// Announce the newly generated block, this block supposedly contains new guarantees that were executed previously
	err = nodes[node1Id].AnnounceBlock(ctx, mockHeader, assurer1Peer)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	mockValidatorService.AssertExpectations(t)

	// Assert that the assurer node now contains it's appropriate shard from the guarantor
	actualSegmentsShards, err := nodes[assurer1Id].AvailabilityStore.GetSegmentsShard(erasureRoot, nodes[assurer1Id].ValidatorManager.Index)
	require.NoError(t, err)
	actualBundleShard, err := nodes[assurer1Id].AvailabilityStore.GetAuditShard(erasureRoot, nodes[assurer1Id].ValidatorManager.Index)
	require.NoError(t, err)
	actualJustification, err := nodes[assurer1Id].AvailabilityStore.GetJustification(erasureRoot, nodes[assurer1Id].ValidatorManager.Index)
	require.NoError(t, err)

	assert.Equal(t, segmentsShards, actualSegmentsShards)
	assert.Equal(t, bundleShard, actualBundleShard)
	assert.Equal(t, justification, actualJustification)
}
