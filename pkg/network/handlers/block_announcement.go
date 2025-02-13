package handlers

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/chain"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/pkg/network"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/ed25519"
)

type ConnState int

const (
	headerSize                 = 297
	SendingHandshake ConnState = iota
	ReceivingHandshake
	Ready
)

type BlockRequestor interface {
	RequestBlock(ctx context.Context, hash crypto.Hash, ascending bool, peerKey ed25519.PublicKey) ([]byte, error)
}

// BlockAnnouncementHandler handles the UP 0 block announcement protocol
type BlockAnnouncementHandler struct {
	*chain.BlockService
	mu sync.RWMutex
	// Map of active announcement Announcers per peer key
	Announcers map[string]*BlockAnnouncer
	requestor  BlockRequestor
}

func NewBlockAnnouncementHandler(bs *chain.BlockService, requestor BlockRequestor) *BlockAnnouncementHandler {
	return &BlockAnnouncementHandler{
		BlockService: bs,
		Announcers:   make(map[string]*BlockAnnouncer),
		requestor:    requestor,
	}
}

// BlockAnnouncer manages sending block announcements over a UP stream
type BlockAnnouncer struct {
	*chain.BlockService
	stream      quic.Stream
	ctx         context.Context
	cancel      context.CancelFunc
	stateLock   sync.Mutex
	state       ConnState
	handshakeCh chan struct{} // Signals handshake completion
	readyCh     chan struct{} // Signals ready for announcements
	sendCh      chan []byte   // Channel for outgoing messages
	receiveCh   chan []byte   // Channel for incoming messages
	requestor   BlockRequestor
	peerKey     ed25519.PublicKey
}

// NewBlockAnnouncer creates a new announcer for the given stream
func (bh *BlockAnnouncementHandler) NewBlockAnnouncer(bs *chain.BlockService, ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) *BlockAnnouncer {
	announcerCtx, cancel := context.WithCancel(ctx)
	bh.Mu.RLock()
	defer bh.Mu.RUnlock()

	ba := &BlockAnnouncer{
		BlockService: bs,
		stream:       stream,
		ctx:          announcerCtx,
		cancel:       cancel,
		state:        SendingHandshake,
		handshakeCh:  make(chan struct{}),
		readyCh:      make(chan struct{}),
		sendCh:       make(chan []byte, 10),
		receiveCh:    make(chan []byte, 10),
		requestor:    bh.requestor,
		peerKey:      peerKey,
	}
	bh.Announcers[string(peerKey)] = ba
	return ba
}

func (bh *BlockAnnouncementHandler) HandleStream(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error {
	bh.mu.Lock()
	defer bh.mu.Unlock()

	existingAnnouncer, exists := bh.Announcers[string(peerKey)]

	if exists {
		// Compare stream IDs - keep the one with greater ID
		if stream.StreamID() > existingAnnouncer.stream.StreamID() {
			// Cancel read/write on old stream
			existingAnnouncer.stream.CancelRead(quic.StreamErrorCode(0))
			existingAnnouncer.stream.CancelWrite(quic.StreamErrorCode(0))
			// Cancel existing announcer's context to stop its goroutines
			existingAnnouncer.cancel()
			// Create new announcer with the new stream
			handler := bh.NewBlockAnnouncer(bh.BlockService, ctx, stream, peerKey)
			return handler.Start()
		} else {
			// Cancel read/write on new stream as it has lower ID
			stream.CancelRead(quic.StreamErrorCode(0))
			stream.CancelWrite(quic.StreamErrorCode(0))
			return nil
		}
	}

	// If no announcer exists yet, create new one and start handshake process
	handler := bh.NewBlockAnnouncer(bh.BlockService, ctx, stream, peerKey)
	return handler.Start()
}

// Start begins handling the announcement stream
func (ba *BlockAnnouncer) Start() error {
	// First handle handshake
	go ba.handleHandshake()

	// Wait for ready state before returning
	select {
	case <-ba.readyCh:
		return nil
	case <-ba.ctx.Done():
		log.Println("BlockAnnouncer Start() - Context canceled before handshake completed")
		return ba.ctx.Err()
	}
}

// SendAnnouncement sends a block announcement to this peer
func (ba *BlockAnnouncer) SendAnnouncement(header *block.Header) error {
	// Wait for ready state
	select {
	case <-ba.readyCh:
		// Continue with send
	case <-ba.ctx.Done():
		return ba.ctx.Err()
	}
	// Format: header + finalized(hash + slot)
	content := make([]byte, 333) // 297 for header + finalHash 36 for finalized, + 4 for slot
	hb, err := header.Bytes()
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}
	copy(content[0:], hb)
	copy(content[297:], ba.LatestFinalized.Hash[:])
	binary.LittleEndian.PutUint32(content[329:], uint32(ba.LatestFinalized.TimeSlotIndex))
	// Send the message through the channel
	select {
	case ba.sendCh <- content:
		return nil
	case <-ba.ctx.Done():
		return ba.ctx.Err()
	}
}

func (ba *BlockAnnouncer) handleHandshake() {

	if err := ba.sendHandshake(); err != nil {
		return
	}

	close(ba.handshakeCh)
	if err := ba.receiveHandshake(); err != nil {
		log.Println("[ERROR] (ba *BlockAnnouncer) receiveHandshake() - Handshake failed:", err)
		return
	}

	ba.stateLock.Lock()
	ba.state = Ready
	ba.stateLock.Unlock()
	close(ba.readyCh)

	// Start processing announcements
	go ba.sendLoop()
	go ba.receiveLoop()
}

func (ba *BlockAnnouncer) receiveHandshake() error {
	ba.stateLock.Lock()
	ba.state = ReceivingHandshake
	ba.stateLock.Unlock()

	msg, err := ReadMessageWithContext(ba.ctx, ba.stream)
	if err != nil {
		return fmt.Errorf("failed to receive handshake: %w", err)
	}

	return ba.processHandshake(msg.Content)
}

func (ba *BlockAnnouncer) sendHandshake() error {
	ba.Mu.RLock()
	content := serializeHandshake(ba.LatestFinalized, ba.KnownLeaves)
	ba.Mu.RUnlock()

	return WriteMessageWithContext(ba.ctx, ba.stream, content)
}

// sendLoop handles sending messages to the peer
func (ba *BlockAnnouncer) sendLoop() {
	for {
		select {
		case <-ba.ctx.Done():
			log.Println("(ba *BlockAnnouncer) sendLoop() - Context canceled, stopping")
			return
		case msg := <-ba.sendCh:
			if ba.stream == nil {
				log.Println("(ba *BlockAnnouncer) sendLoop() - Stream is nil, cannot send message")
				return
			}

			if err := WriteMessageWithContext(ba.ctx, ba.stream, msg); err != nil {
				log.Println("(ba *BlockAnnouncer) sendLoop() - Failed to send message:", err)
				return
			}
		}
	}
}

// receiveLoop handles receiving messages from the peer
func (ba *BlockAnnouncer) receiveLoop() {
	for {
		select {
		case <-ba.ctx.Done():
			return
		default:
			msg, err := ReadMessageWithContext(ba.ctx, ba.stream)
			if err != nil {
				log.Println("(ba *BlockAnnouncer) receiveLoop() - Failed to read message:", err)
				return
			}
			if err := ba.processAnnouncement(msg.Content); err != nil {
				log.Println("(ba *BlockAnnouncer) receiveLoop() - Failed to process announcement:", err)
				return
			}
		}
	}
}

// processAnnouncement handles a block announcement message
func (ba *BlockAnnouncer) processAnnouncement(content []byte) error {
	if len(content) < 333 { // Minimum size: header(297) + finalized(36)
		return fmt.Errorf("announcement message too short")
	}

	// Extract header
	var header block.Header
	peerFinalized := chain.LatestFinalized{}

	err := jam.Unmarshal(content[:headerSize], &header)
	if err != nil {
		return fmt.Errorf("failed to unmarshal header: %w", err)
	}
	copy(peerFinalized.Hash[:], content[headerSize:headerSize+32])

	peerFinalized.TimeSlotIndex = jamtime.Timeslot(binary.LittleEndian.Uint32(content[headerSize+32:]))

	// Validate the announcement
	if header.TimeSlotIndex <= peerFinalized.TimeSlotIndex {
		return fmt.Errorf("announced block slot (%d) not after peer's finalized slot (%d)", header.TimeSlotIndex, peerFinalized.TimeSlotIndex)
	}

	_, err = ba.Store.GetHeader(peerFinalized.Hash)
	if err != nil {
		if errors.Is(err, store.ErrHeaderNotFound) {
			// We don't know peer's finalized block - might need to sync
			fmt.Printf("Warning: Peer's finalized block %x unknown", peerFinalized.Hash)
		} else {
			return fmt.Errorf("failed checking peer's finalized block: %w", err)
		}
	}

	if err := ba.Store.PutHeader(header); err != nil {
		return fmt.Errorf("failed to store announced header: %w", err)
	}

	if err = ba.HandleNewHeader(&header); err != nil {
		return fmt.Errorf("failed to process new block: %w", err)
	}
	h, err := header.Hash()
	if err != nil {
		return fmt.Errorf("failed to hash header: %w", err)
	}

	ctx, cancel := context.WithTimeout(ba.ctx, 6*time.Second)
	defer cancel()
	network.LogBlockEvent(time.Now(), "requesting", h, header.TimeSlotIndex.ToEpoch(), header.TimeSlotIndex)
	blockData, err := ba.requestor.RequestBlock(ctx, h, false, ba.peerKey)
	var block block.Block
	if err != nil {
		log.Printf("Warning: failed to request block %x: %v", h[:5], err)
	} else {
		// Process the received block

		if err := jam.Unmarshal(blockData, &block); err != nil {
			log.Printf("Warning: failed to unmarshal requested block %x: %v", h[:5], err)
		} else {
			if err := ba.Store.PutBlock(block); err != nil {
				log.Printf("Warning: failed to store requested block %x: %v", h[:5], err)
			}
		}
	}

	network.LogBlockEvent(time.Now(), "imported", h, block.Header.TimeSlotIndex.ToEpoch(), block.Header.TimeSlotIndex)
	return nil
}

func serializeHandshake(finalized chain.LatestFinalized, leaves map[crypto.Hash]uint32) []byte {
	size := 40 + (len(leaves) * 36)
	content := make([]byte, size)
	offset := 0

	copy(content[offset:], finalized.Hash[:])
	offset += 32
	binary.LittleEndian.PutUint32(content[offset:], uint32(finalized.TimeSlotIndex))
	offset += 4

	binary.LittleEndian.PutUint32(content[offset:], uint32(len(leaves)))
	offset += 4

	for hash, slot := range leaves {
		copy(content[offset:], hash[:])
		offset += 32
		binary.LittleEndian.PutUint32(content[offset:], slot)
		offset += 4
	}

	return content
}

// processHandshake processes a received handshake message
func (ba *BlockAnnouncer) processHandshake(content []byte) error {
	if len(content) < 40 { // Minimum size: finalized(36) + numLeaves(4)
		return fmt.Errorf("handshake message too short")
	}

	// Read finalized block info
	var finalized chain.LatestFinalized
	copy(finalized.Hash[:], content[:32])
	finalized.TimeSlotIndex = jamtime.Timeslot(binary.LittleEndian.Uint32(content[32:36]))

	// Read number of leaves
	numLeaves := binary.LittleEndian.Uint32(content[36:40])

	// Validate message size
	expectedSize := 40 + (numLeaves * 36)
	if len(content) != int(expectedSize) {
		return fmt.Errorf("invalid handshake size")
	}

	// Process each leaf
	offset := 40
	leaves := make(map[crypto.Hash]uint32)
	for i := uint32(0); i < numLeaves; i++ {
		var hash crypto.Hash
		copy(hash[:], content[offset:offset+32])
		slot := binary.LittleEndian.Uint32(content[offset+32 : offset+36])
		leaves[hash] = slot
		offset += 36
	}

	// Update state
	ba.Mu.Lock()
	ba.LatestFinalized = finalized
	ba.KnownLeaves = leaves
	ba.Mu.Unlock()

	return nil
}
