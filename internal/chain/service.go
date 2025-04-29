package chain

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/eigerco/strawberry/pkg/network"
)

// BlockService manages the node's view of the blockchain state, including:
// - Known leaf blocks (blocks with no known children)
// - Latest finalized block
// - Block storage and retrieval
//
// It handles block announcements according to UP 0 protocol specification,
// maintaining the set of leaf blocks and tracking finalization status.
type BlockService struct {
	mu              sync.RWMutex
	KnownLeaves     map[crypto.Hash]jamtime.Timeslot // Maps leaf block hashes to their timeslots
	LatestFinalized LatestFinalized                  // Tracks the most recently finalized block
	Store           *store.Chain                     // Persistent block storage
}

// LatestFinalized represents the latest finalized block in the chain.
// A block is considered finalized when it has a chain of 5 descendant blocks
// built on top of it according to the finalization rules.
type LatestFinalized struct {
	Hash          crypto.Hash      // Hash of the finalized block
	TimeSlotIndex jamtime.Timeslot // Timeslot of the finalized block
}

// Leaf represents a block with no known children (a tip of the chain).
// The BlockService tracks all known leaves to implement the UP 0 protocol's
// requirement of announcing all leaves in handshake messages.
type Leaf struct {
	Hash          crypto.Hash      // Hash of the leaf block
	TimeSlotIndex jamtime.Timeslot // Timeslot of the leaf block
}

// NewBlockService initializes a new BlockService with:
// - Empty leaf block set
// - Persistent block storage using PebbleDB
// - Genesis block as the latest finalized block
func NewBlockService(kvStore *pebble.KVStore) (*BlockService, error) {
	chain := store.NewChain(kvStore)
	bs := &BlockService{
		Store:       chain,
		KnownLeaves: make(map[crypto.Hash]jamtime.Timeslot),
	}
	// Initialize by finding leaves and finalized block
	if err := bs.initializeState(); err != nil {
		// Log error but continue - we can recover state as we process blocks
		fmt.Printf("Failed to initialize block manager state: %v\n", err)
	}
	return bs, nil
}

// initializeState sets up the initial blockchain state:
// 1. Creates and stores the genesis block
// 2. Sets genesis as the latest finalized block
//
// TODO: This is still a `mock` implementation.
func (bs *BlockService) initializeState() error {
	// For now use genesis block
	genesisHeader := block.Header{
		ParentHash:       crypto.Hash{1},
		TimeSlotIndex:    jamtime.Timeslot(1),
		BlockAuthorIndex: 0,
	}
	hash, err := genesisHeader.Hash()
	if err != nil {
		return fmt.Errorf("failed to hash genesis block: %w", err)
	}
	if err := bs.Store.PutHeader(genesisHeader); err != nil {
		return fmt.Errorf("failed to store genesis block: %w", err)
	}
	b := block.Block{
		Header: genesisHeader,
	}
	if err := bs.Store.PutBlock(b); err != nil {
		return fmt.Errorf("failed to store genesis block: %w", err)
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.LatestFinalized = LatestFinalized{
		Hash:          hash,
		TimeSlotIndex: genesisHeader.TimeSlotIndex,
	}
	return nil
}

// checkFinalization determines if a block can be finalized by:
// 1. Walking back 5 generations from the given block hash
// 2. If a complete chain of 5 blocks exists, finalizing the oldest block
// 3. Updating the latest finalized pointer
// 4. Removing the finalized block from the leaf set if present
//
// Returns nil if finalization check succeeds, error if any operations fail.
// Note: May return nil even if finalization isn't possible (e.g., missing ancestors).
// This is due to genesis block handling and is not considered an error.
func (bs *BlockService) checkFinalization(hash crypto.Hash) error {
	// Start from current header and walk back 6 generations
	currentHash := hash
	var ancestorChain []block.Header

	// Walk back 6`` generations
	for i := 0; i < 6; i++ {
		header, err := bs.Store.GetHeader(currentHash)
		if err != nil {
			if errors.Is(err, store.ErrHeaderNotFound) {
				// If we can't find a parent, we can't finalize
				return nil
			}
			return fmt.Errorf("failed to get header in chain: %w", err)
		}

		ancestorChain = append(ancestorChain, header)
		currentHash = header.ParentHash
	}

	// Get the oldest header (the one we'll finalize)
	finalizeHeader := ancestorChain[len(ancestorChain)-1]
	finalizeHash, err := finalizeHeader.Hash()
	if err != nil {
		return fmt.Errorf("failed to hash header during finalization: %w", err)
	}

	bs.RemoveLeaf(finalizeHash)
	bs.UpdateLatestFinalized(finalizeHash, finalizeHeader.TimeSlotIndex)

	return nil
}

// HandleNewHeader processes a new block header announcement by:
// 1. Storing the header in persistent storage
// 2. Updating the leaf block set (removing parent, adding new block)
// 3. Checking if the parent block can now be finalized
//
// This implements the core block processing logic required by UP 0 protocol,
// maintaining the node's view of chain tips and finalization status.
func (bs *BlockService) HandleNewHeader(header *block.Header) error {
	// Get the header hash
	hash, err := header.Hash()
	if err != nil {
		return fmt.Errorf("hash header: %w", err)
	}
	// Need to verify this block is a descendant of latest finalized block
	// before considering it as a potential leaf
	isDescendant, err := bs.IsDescendantOfFinalized(header)
	if err != nil {
		return fmt.Errorf("check if block is descendant of finalized: %w", err)
	}
	if !isDescendant {
		return fmt.Errorf("block %s is not a descendant of latest finalized block", hash)
	}

	// First store the header
	if err := bs.Store.PutHeader(*header); err != nil {
		return fmt.Errorf("store header: %w", err)
	}

	// Only update leaves if this is a descendant of finalized block
	bs.RemoveLeaf(header.ParentHash)
	bs.AddLeaf(hash, header.TimeSlotIndex)

	// Check if this creates a finalization condition starting from parent
	if err := bs.checkFinalization(header.ParentHash); err != nil {
		// Log but don't fail on finalization check errors
		fmt.Printf("check finalization: %v\n", err)
	}

	return nil
}

// UpdateLatestFinalized updates the latest finalized block pointer.
func (bs *BlockService) UpdateLatestFinalized(hash crypto.Hash, slot jamtime.Timeslot) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.LatestFinalized = LatestFinalized{Hash: hash, TimeSlotIndex: slot}
	network.LogBlockEvent(time.Now(), "finalizing", hash, slot.ToEpoch(), slot)
}

// AddLeaf adds a block to the set of known leaves.
func (bs *BlockService) AddLeaf(hash crypto.Hash, slot jamtime.Timeslot) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.KnownLeaves[hash] = slot
}

// RemoveLeaf removes a block from the set of known leaves.
func (bs *BlockService) RemoveLeaf(hash crypto.Hash) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	delete(bs.KnownLeaves, hash)
}

// IsDescendantOfFinalized checks if a block is a descendant of the latest finalized block
// by walking back through its ancestors until we either:
// - Find the latest finalized block (true)
// - Find a different block at the same height as latest finalized (false)
// - Can't find a parent (error)
func (bs *BlockService) IsDescendantOfFinalized(header *block.Header) (bool, error) {
	bs.mu.RLock()
	finalizedSlot := bs.LatestFinalized.TimeSlotIndex
	finalizedHash := bs.LatestFinalized.Hash
	bs.mu.RUnlock()

	current := header
	for current.TimeSlotIndex > finalizedSlot {
		parent, err := bs.Store.GetHeader(current.ParentHash)
		if err != nil {
			return false, fmt.Errorf("get parent block: %w", err)
		}
		current = &parent
	}

	// If we found the finalized block, this is a descendant
	if current.TimeSlotIndex == finalizedSlot {
		currentHash, err := current.Hash()
		if err != nil {
			return false, err
		}
		return currentHash == finalizedHash, nil
	}
	return false, nil
}
