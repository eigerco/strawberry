package store

import (
	"errors"
	"fmt"
	"log"
	"sync/atomic"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/db"
	"github.com/eigerco/strawberry/pkg/db/pebble"
)

var (
	ErrBlockNotFound  = errors.New("block not found")
	ErrHeaderNotFound = errors.New("header not found")
	ErrChainClosed    = errors.New("chain store is closed")
)

const (
	prefixHeader byte = iota + 1
	prefixBlock
)

// Chain manages blockchain storage using a key-value store
type Chain struct {
	db     db.KVStore
	closed atomic.Bool
}

// NewChain creates a new chain store using KVStore
func NewChain(db db.KVStore) *Chain {
	return &Chain{db: db}
}

// PutHeader stores a header in the chain store
func (c *Chain) PutHeader(h block.Header) error {
	if c.closed.Load() {
		return ErrChainClosed
	}
	bytes, err := h.Bytes()
	if err != nil {
		return fmt.Errorf("marshal header: %w", err)
	}
	hash, err := h.Hash()
	if err != nil {
		return fmt.Errorf("hash header: %w", err)
	}
	if err := c.db.Put(makeKey(prefixHeader, hash[:]), bytes); err != nil {
		return fmt.Errorf("store header: %w", err)
	}
	return nil
}

// GetHeader retrieves a header by its hash
func (c *Chain) GetHeader(hash crypto.Hash) (block.Header, error) {
	if c.closed.Load() {
		return block.Header{}, ErrChainClosed
	}

	headerBytes, err := c.db.Get(makeKey(prefixHeader, hash[:]))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return block.Header{}, ErrHeaderNotFound
		}
		return block.Header{}, fmt.Errorf("get header: %w", err)
	}

	return block.HeaderFromBytes(headerBytes)
}

// FindHeader searches for a header that matches the given predicate function.
// Returns the first matching header and nil error if found.
// Returns zero header and nil error if no match is found.
// Returns zero header and error if the chain is closed or if database operations fail.
func (c *Chain) FindHeader(fn func(header block.Header) bool) (block.Header, error) {
	if c.closed.Load() {
		return block.Header{}, ErrChainClosed
	}

	// Create iterator for header prefix
	iter, err := c.db.NewIterator([]byte{prefixHeader}, []byte{prefixHeader + 1})
	if err != nil {
		return block.Header{}, fmt.Errorf("create iterator: %w", err)
	}
	defer iter.Close()

	// Iterate through headers
	for iter.Next() {
		headerBytes, err := iter.Value()
		if err != nil {
			return block.Header{}, fmt.Errorf("get header value: %w", err)
		}

		header, err := block.HeaderFromBytes(headerBytes)
		if err != nil {
			return block.Header{}, fmt.Errorf("parse header from bytes: %w", err)
		}

		if fn(header) {
			return header, nil
		}
	}

	return block.Header{}, nil
}

// PutBlock stores a block and its header atomically
func (c *Chain) PutBlock(b block.Block) error {
	if c.closed.Load() {
		return ErrChainClosed
	}
	// Create new batch for atomic operations
	batch := c.db.NewBatch()
	defer batch.Close()
	headerHash, err := b.Header.Hash()
	if err != nil {
		return fmt.Errorf("hash header: %w", err)
	}

	// Store the header
	headerBytes, err := b.Header.Bytes()
	if err != nil {
		return fmt.Errorf("marshal header: %w", err)
	}
	if err := batch.Put(makeKey(prefixHeader, headerHash[:]), headerBytes); err != nil {
		return fmt.Errorf("store header: %w", err)
	}

	// Store full block
	blockBytes, err := b.Bytes()
	if err != nil {
		return fmt.Errorf("marshal block: %w", err)
	}
	if err := batch.Put(makeKey(prefixBlock, headerHash[:]), blockBytes); err != nil {
		return fmt.Errorf("store block: %w", err)
	}
	// Commit the batch
	if err := batch.Commit(); err != nil {
		return fmt.Errorf("commit batch: %w", err)
	}
	return nil
}

// GetBlock retrieves a block by its header hash
func (c *Chain) GetBlock(hash crypto.Hash) (block.Block, error) {
	if c.closed.Load() {
		return block.Block{}, ErrChainClosed
	}

	blockBytes, err := c.db.Get(makeKey(prefixBlock, hash[:]))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return block.Block{}, ErrBlockNotFound
		}
		return block.Block{}, fmt.Errorf("get block: %w", err)
	}

	return block.BlockFromBytes(blockBytes)
}

// FindChildren finds all immediate child blocks for a given block hash
func (c *Chain) FindChildren(parentHash crypto.Hash) ([]block.Block, error) {
	if c.closed.Load() {
		return nil, ErrChainClosed
	}

	var children []block.Block

	// Create iterator for block prefix
	iter, err := c.db.NewIterator([]byte{prefixBlock}, []byte{prefixBlock + 1})
	if err != nil {
		return nil, fmt.Errorf("create iterator: %w", err)
	}
	defer iter.Close()

	// Iterate through blocks
	for iter.Next() {
		blockBytes, err := iter.Value()
		if err != nil {
			log.Println("read block value from iterator", err)
			continue
		}
		b, err := block.BlockFromBytes(blockBytes)
		if err != nil {
			log.Println("parse block from bytes", err)
			continue
		}

		if b.Header.ParentHash == parentHash {
			children = append(children, b)
		}
	}

	return children, nil
}

// GetBlockSequence retrieves a sequence of blocks.
// If ascending is true, returns children of the start block (exclusive).
// If ascending is false, returns the start block and its ancestors (inclusive).
func (c *Chain) GetBlockSequence(startHash crypto.Hash, ascending bool, maxBlocks uint32) ([]block.Block, error) {
	if c.closed.Load() {
		return nil, ErrChainClosed
	}

	currentBlock, err := c.GetBlock(startHash)
	if err != nil {
		if errors.Is(err, ErrBlockNotFound) {
			return nil, fmt.Errorf("starting block not found: %w", err)
		}
		return nil, fmt.Errorf("get starting block: %w", err)
	}

	var blocks []block.Block
	currentHash := startHash

	for uint32(len(blocks)) < maxBlocks {
		if ascending {
			// For ascending (exclusive), skip first block
			if currentHash != startHash {
				blocks = append(blocks, currentBlock)
			}
			// Find children and take the first one
			children, err := c.FindChildren(currentHash)
			if err != nil || len(children) == 0 {
				break
			}

			// Get hash for next iteration
			currentHash, err = children[0].Header.Hash()
			if err != nil {
				return nil, fmt.Errorf("marshal child header: %w", err)
			}
		} else {
			// For descending (inclusive), include current and follow parent
			blocks = append(blocks, currentBlock)
			currentHash = currentBlock.Header.ParentHash
		}

		// Retrieve next block
		currentBlock, err = c.GetBlock(currentHash)
		if err != nil {
			if errors.Is(err, ErrBlockNotFound) {
				break
			}
			return nil, fmt.Errorf("get block in sequence: %w", err)
		}
	}

	return blocks, nil
}

// Close closes the chain store
func (c *Chain) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	return c.db.Close()
}

// PrefixToString converts a prefix byte to a string
func PrefixToString(p byte) string {
	switch p {
	case prefixHeader:
		return "header"
	case prefixBlock:
		return "block"
	default:
		return "unknown"
	}
}

// makeKey creates a key from a prefix and hash
func makeKey(prefix byte, hash []byte) []byte {
	key := make([]byte, 1+len(hash))
	key[0] = prefix
	copy(key[1:], hash)
	return key
}
