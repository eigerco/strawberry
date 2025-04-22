package network_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/eigerco/strawberry/internal/testutils"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"

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

func setupNodes(ctx context.Context, t *testing.T, numNodes int) []*node.Node {
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
		key := &crypto.ValidatorKey{}
		key.Ed25519 = pub
		key.Metadata = crypto.MetadataKey(createMockMetadata(t, addr, uint16(port)))
		validatorsData[i] = key
	}
	vstate := validator.ValidatorState{
		CurrentValidators:  validatorsData,
		ArchivedValidators: validatorsData,
		QueuedValidators:   validatorsData,
	}

	state := chainState.State{
		ValidatorState: vstate,
	}

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

// MockImportSegmentsFetcher implements handlers.ImportedSegmentsFetcher for testing
type MockImportSegmentsFetcher struct {
	mu                 sync.Mutex
	fetchedSegments    map[string]struct{}
	receivedWorkItems  []work.Item
	receivedExtrinsics []byte
	receivedCoreIndex  uint16
}

func NewMockImportSegmentsFetcher() *MockImportSegmentsFetcher {
	return &MockImportSegmentsFetcher{
		fetchedSegments: make(map[string]struct{}),
	}
}

func (m *MockImportSegmentsFetcher) FetchImportedSegment(hash crypto.Hash) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.fetchedSegments[string(hash[:])] = struct{}{}
	// Return mock segment data
	return []byte("mock_segment_data"), nil
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

type mockRefineInvoker struct{}

func (m mockRefineInvoker) InvokePVM(
	itemIndex uint32,
	workPackage work.Package,
	authorizerHashOutput []byte,
	importedSegments []work.Segment,
	exportOffset uint64,
) ([]byte, []work.Segment, error) {
	out := []byte("RefineOutput")
	exported := []work.Segment{
		{},
	}
	return out, exported, nil
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
			handlers.NewWorkReportGuarantor(uint16(1), prv, mockAuthorizationInvoker{}, mockRefineInvoker{}, chainState.State{Services: make(service.ServiceState)}, peer.NewPeerSet())),
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
			_, err = h.Fetcher.FetchImportedSegment(imp.Hash)
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

	nodes := setupNodes(ctx, t, 2)
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

	nodes := setupNodes(ctx, t, 2)
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
	nodes := setupNodes(ctx, t, 2)
	node1 := nodes[0]
	node2 := nodes[1]

	// Create a mock fetcher for tracking received packages
	mockFetcher := NewMockImportSegmentsFetcher()

	// Replace the default handler with our extended handler in node2
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

func TestWorkReportGuarantee(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nodes := setupNodes(ctx, t, 3)
	node1 := nodes[0]
	node2 := nodes[1]
	node3 := nodes[2]

	_, prv, _ := ed25519.GenerateKey(rand.Reader)
	serviceState := getServiceState()

	handler2 := handlers.NewWorkPackageSharingHandler(
		mockAuthorizationInvoker{},
		mockRefineInvoker{},
		prv,
		serviceState,
	)

	_, prv3, _ := ed25519.GenerateKey(rand.Reader)
	handler3 := handlers.NewWorkPackageSharingHandler(
		mockAuthorizationInvoker{},
		mockRefineInvoker{},
		prv3,
		serviceState,
	)

	coreIndex := uint16(1)

	handler2.SetCurrentCore(1)
	handler3.SetCurrentCore(1)

	node2.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkPackageShare, handler2)
	node3.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkPackageShare, handler3)

	distHandler2 := handlers.NewWorkReportDistributionHandler()
	distHandler3 := handlers.NewWorkReportDistributionHandler()

	node2.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkReportDist, distHandler2)
	node3.ProtocolManager.Registry.RegisterHandler(protocol.StreamKindWorkReportDist, distHandler3)

	require.NoError(t, node1.Start())
	defer stopNode(t, node1)
	require.NoError(t, node2.Start())
	defer stopNode(t, node2)
	require.NoError(t, node3.Start())
	defer stopNode(t, node3)

	time.Sleep(100 * time.Millisecond)

	node2Addr, err := peer.NewPeerAddressFromMetadata(
		nodes[1].ValidatorManager.State.CurrentValidators[1].Metadata[:],
	)
	require.NoError(t, err)
	node3Addr, err := peer.NewPeerAddressFromMetadata(nodes[2].ValidatorManager.State.CurrentValidators[2].Metadata[:])
	require.NoError(t, err)

	require.NoError(t, node1.ConnectToPeer(node2Addr))
	require.NoError(t, node1.ConnectToPeer(node3Addr))
	time.Sleep(100 * time.Millisecond)

	authCode := []byte("auth token")
	authHash := crypto.HashData(authCode)

	bundle := work.PackageBundle{
		Package: work.Package{
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
		},
	}

	peerSet := peer.NewPeerSet()
	peer2 := node1.PeersSet.GetByAddress(node2Addr.String())
	index2 := uint16(2)
	peer2.ValidatorIndex = &index2
	peerSet.AddPeer(peer2)

	peer3 := node1.PeersSet.GetByAddress(node3Addr.String())
	index3 := uint16(3)
	peer3.ValidatorIndex = &index3
	peerSet.AddPeer(peer3)

	var validators safrole.ValidatorsData
	validators[0] = &crypto.ValidatorKey{
		Ed25519: peer2.Ed25519Key,
	}
	validators[1] = &crypto.ValidatorKey{
		Ed25519: peer3.Ed25519Key,
	}

	currentState := chainState.State{
		Services: serviceState,
		ValidatorState: validator.ValidatorState{
			CurrentValidators: validators,
			SafroleState: safrole.State{
				NextValidators: validators,
			},
		},
		TimeslotIndex: jamtime.Timeslot(599),
	}

	sharer := handlers.NewWorkReportGuarantor(
		coreIndex,
		prv,
		mockAuthorizationInvoker{},
		mockRefineInvoker{},
		currentState,
		peerSet,
	)

	sharer.SetGuarantors([]*peer.Peer{
		peer2,
		peer3,
	})

	err = sharer.ValidateAndProcessWorkPackage(ctx, coreIndex, bundle)

	time.Sleep(100 * time.Millisecond)

	require.NoError(t, err)

	// TODO improve this test by checking the results after we store the guarantee
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
	nodes := setupNodes(ctx, t, 2)
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

	// Send shards and justification
	bundleShard, segmentShard, justification, err := node1.ShardDistributionSend(ctx, node2Peer.Ed25519Key, erasureRoot, shardIndex)
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
	nodes := setupNodes(ctx, t, 2)
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
	nodes := setupNodes(ctx, t, 2)
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
	nodes := setupNodes(ctx, t, 2)
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
