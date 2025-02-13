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

// BlockService handles common block announcement state
type BlockService struct {
	Mu              sync.RWMutex
	KnownLeaves     map[crypto.Hash]uint32
	LatestFinalized LatestFinalized
	Store           *store.Chain
}

// LatestFinalized represents the latest finalized block
type LatestFinalized struct {
	Hash          crypto.Hash
	TimeSlotIndex jamtime.Timeslot
}

// Leaf represents a leaf block (one with no known children)
type Leaf struct {
	Hash          crypto.Hash
	TimeSlotIndex jamtime.Timeslot
}

func NewBlockService() (*BlockService, error) {
	kvStore, err := pebble.NewKVStore()
	if err != nil {
		return nil, err
	}
	chain := store.NewChain(kvStore)
	bs := &BlockService{
		Store:       chain,
		KnownLeaves: make(map[crypto.Hash]uint32),
	}
	// Initialize by finding leaves and finalized block
	if err := bs.initializeState(); err != nil {
		// Log error but continue - we can recover state as we process blocks
		fmt.Printf("Failed to initialize block manager state: %v\n", err)
	}
	return bs, nil
}

func (bs *BlockService) initializeState() error {
	// TODO: Get latest finalized block from consensus
	// For now use genesis block
	genesisHeader := block.Header{
		ParentHash:       crypto.Hash{},
		TimeSlotIndex:    jamtime.Timeslot(jamtime.CurrentTimeslot()),
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
	bs.Mu.Lock()
	bs.LatestFinalized = LatestFinalized{
		Hash:          hash,
		TimeSlotIndex: genesisHeader.TimeSlotIndex,
	}
	bs.Mu.Unlock()
	return nil
}

// BlockService additions

// checkFinalization checks if this header completes a chain of 5 that can be finalized
func (bs *BlockService) checkFinalization(hash crypto.Hash) error {
	// Start from current header and walk back 5 generations
	currentHash := hash
	var ancestorChain []block.Header

	// Walk back 5 generations (current + 4 parents = 5 total)
	for i := 0; i < 5; i++ {
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

// HandleNewHeader processes a new header announcement and checks finalization
func (bs *BlockService) HandleNewHeader(header *block.Header) error {
	// First store the header
	if err := bs.Store.PutHeader(*header); err != nil {
		return fmt.Errorf("failed to store header: %w", err)
	}

	// Get the header hash
	hash, err := header.Hash()
	if err != nil {
		return fmt.Errorf("failed to hash header: %w", err)
	}

	// Remove parent from leaves and add this as new leaf
	bs.RemoveLeaf(header.ParentHash)
	bs.AddLeaf(hash, uint32(header.TimeSlotIndex))

	// Check if this creates a finalization condition starting from parent
	if err := bs.checkFinalization(header.ParentHash); err != nil {
		// Log but don't fail on finalization check errors
		fmt.Printf("Failed to check finalization: %v\n", err)
	}

	return nil
}

func (bs *BlockService) UpdateLatestFinalized(hash crypto.Hash, slot jamtime.Timeslot) {
	bs.Mu.Lock()
	defer bs.Mu.Unlock()
	bs.LatestFinalized = LatestFinalized{Hash: hash, TimeSlotIndex: slot}
	network.LogBlockEvent(time.Now(), "finalizing", hash, slot.ToEpoch(), slot)
}

func (bs *BlockService) AddLeaf(hash crypto.Hash, slot uint32) {
	bs.Mu.Lock()
	defer bs.Mu.Unlock()
	bs.KnownLeaves[hash] = slot
}

func (bs *BlockService) RemoveLeaf(hash crypto.Hash) {
	bs.Mu.Lock()
	defer bs.Mu.Unlock()
	delete(bs.KnownLeaves, hash)
}
