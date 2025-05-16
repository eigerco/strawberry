package validator

import (
	"crypto/ed25519"
	"fmt"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safrole"
	"math"
)

// GridMapper manages the mapping between grid indices and validator information across epochs.
// It maintains data for three sets of validators:
// - Current validators: The active set in the current epoch
// - Archived validators: The set from the previous epoch
// - Queued validators: The set for the next epoch
//
// The grid structure arranges validators in a square-like grid where validators are considered
// neighbors if they share the same row or column. This structure is used primarily for block
// announcements and other network communications.
type GridMapper struct {
	currentValidators  safrole.ValidatorsData
	archivedValidators safrole.ValidatorsData
	queuedValidators   safrole.ValidatorsData
}

// NewGridMapper creates a new mapper instance using the provided validator state.
// The state must contain information about current, archived, and queued validators.
func NewGridMapper(state ValidatorState) GridMapper {
	return GridMapper{
		currentValidators:  state.CurrentValidators,
		archivedValidators: state.ArchivedValidators,
		queuedValidators:   state.QueuedValidators,
	}
}

// GetAllEpochsNeighborValidators returns all neighbor validators across epochs for a given index.
// This includes:
// - All grid neighbors from the current epoch (same row or column)
// - The validator with the same index from the previous epoch
// - The validator with the same index from the next epoch
func (m GridMapper) GetAllEpochsNeighborValidators(index uint16) ([]crypto.ValidatorKey, error) {
	neighborsSameEpoch, err := m.GetCurrentEpochNeighborValidators(index)
	if err != nil {
		return nil, fmt.Errorf("failed to get current epoch neighbor validators: %w", err)
	}

	// Initialize with capacity for same epoch neighbors plus potentially two more
	neighbors := make([]crypto.ValidatorKey, 0, len(neighborsSameEpoch)+2)

	// Add previous epoch validator if index exists
	if index < uint16(len(m.archivedValidators)) {
		neighbors = append(neighbors, m.archivedValidators[index])
	}

	// Add next epoch validator if index exists
	if index < uint16(len(m.queuedValidators)) {
		neighbors = append(neighbors, m.queuedValidators[index])
	}

	// Add current epoch neighbors
	neighbors = append(neighbors, neighborsSameEpoch...)

	return neighbors, nil
}

// GetCurrentEpochNeighborValidators returns all grid neighbors for a validator
// within the current epoch. Grid neighbors are validators that share either
// the same row or column in the grid structure.
func (m GridMapper) GetCurrentEpochNeighborValidators(index uint16) ([]crypto.ValidatorKey, error) {
	neighborIndices := getCurrentEpochNeighborIndices(index)
	neighbors := make([]crypto.ValidatorKey, 0, len(neighborIndices))

	for _, idx := range neighborIndices {
		neighbors = append(neighbors, m.currentValidators[idx])
	}

	return neighbors, nil
}

// IsNeighbor determines if two validators are neighbors based on their public keys.
// Two validators are considered neighbors if either:
// - They are in the same epoch and share the same row or column in the grid
// - They are in different epochs but have the same grid index
// Parameters:
//   - key1, key2: The Ed25519 public keys of the two validators
//   - sameEpoch: Whether both validators are from the same epoch
func (m GridMapper) IsNeighbor(key1, key2 ed25519.PublicKey, sameEpoch bool) bool {
	// Self-connections are not considered neighbors
	if key1.Equal(key2) {
		return false
	}

	if sameEpoch {
		idx1, found1 := m.FindValidatorIndex(key1)
		idx2, found2 := m.FindValidatorIndex(key2)

		if !found1 || !found2 {
			return false
		}
		return areGridNeighbors(idx1, idx2)
	}

	// For different epochs, validators are neighbors if they have the same index
	indices1 := m.getValidatorIndices(key1)
	if len(indices1) == 0 {
		return false // key1 not found in any epoch
	}

	indices2 := m.getValidatorIndices(key2)
	// Check if there are any matching indices between the two validators
	for idx := range indices2 {
		if indices1[idx] {
			return true
		}
	}

	return false
}

// FindValidatorIndex searches for a validator's grid index in the current validator set
// by their Ed25519 public key. Returns the index and true if found, or 0 and false if not found.
func (m GridMapper) FindValidatorIndex(key ed25519.PublicKey) (uint16, bool) {
	return findValidatorIndexInSlice(m.currentValidators, key)
}

// FindValidatorIndexInArchived searches for a validator's grid index in the previous epoch's
// validator set by their Ed25519 public key. Returns the index and true if found,
// or 0 and false if not found.
func (m GridMapper) FindValidatorIndexInArchived(key ed25519.PublicKey) (uint16, bool) {
	return findValidatorIndexInSlice(m.archivedValidators, key)
}

// FindValidatorIndexInQueued searches for a validator's grid index in the next epoch's
// validator set by their Ed25519 public key. Returns the index and true if found,
// or 0 and false if not found.
func (m GridMapper) FindValidatorIndexInQueued(key ed25519.PublicKey) (uint16, bool) {
	return findValidatorIndexInSlice(m.queuedValidators, key)
}

// getValidatorIndices finds all possible indices for a validator across epochs.
func (m GridMapper) getValidatorIndices(key ed25519.PublicKey) map[uint16]bool {
	indices := make(map[uint16]bool)

	if idx, found := m.FindValidatorIndexInArchived(key); found {
		indices[idx] = true
	}
	if idx, found := m.FindValidatorIndex(key); found {
		indices[idx] = true
	}
	if idx, found := m.FindValidatorIndexInQueued(key); found {
		indices[idx] = true
	}

	return indices
}

// findValidatorIndexInSlice searches for a validator's grid index
// in a given validator set by their Ed25519 public key. It returns the index and true if found,
// or 0 and false if not found. The index can be used to determine the validator's position
// in the grid structure.
func findValidatorIndexInSlice(validators safrole.ValidatorsData, key ed25519.PublicKey) (uint16, bool) {
	for i, validator := range validators {
		if !validator.IsEmpty() && ed25519.PublicKey.Equal(validator.Ed25519, key) {
			return uint16(i), true
		}
	}
	return 0, false
}

// getCurrentEpochNeighborIndices returns all validator indices that are considered
// neighbors within the same epoch based on the grid structure. This includes all
// validators that share either:
// - The same row (index / gridWidth)
// - The same column (index % gridWidth)
// The returned slice excludes the input validatorIndex itself.
func getCurrentEpochNeighborIndices(validatorIndex uint16) []uint16 {
	gridWidth := getGridWidth()

	// Pre-allocate with maximum possible capacity
	// Maximum size is (gridWidth - 1) for row + (gridWidth - 1) for column
	neighbors := make([]uint16, 0, 2*(gridWidth-1))

	// Calculate row neighbors
	rowStart := (validatorIndex / gridWidth) * gridWidth
	rowEnd := min(rowStart+gridWidth, common.NumberOfValidators)
	for i := rowStart; i < rowEnd; i++ {
		if i != validatorIndex {
			neighbors = append(neighbors, i)
		}
	}

	// Calculate column neighbors
	for i := validatorIndex % gridWidth; i < common.NumberOfValidators; i += gridWidth {
		if i != validatorIndex {
			neighbors = append(neighbors, i)
		}
	}

	return neighbors
}

// areGridNeighbors determines if two validators within the same epoch are neighbors
// in the grid structure by checking if they share the same row or column.
// The grid width is calculated as floor(sqrt(total_validators)).
func areGridNeighbors(validatorIndex1, validatorIndex2 uint16) bool {
	gridWidth := getGridWidth()
	row1, col1 := validatorIndex1/gridWidth, validatorIndex1%gridWidth
	row2, col2 := validatorIndex2/gridWidth, validatorIndex2%gridWidth

	return row1 == row2 || col1 == col2
}

// getGridWidth calculates the width of the validator grid.
// The grid is arranged as a square-like structure with width = floor(sqrt(number_of_validators)).
// This ensures the grid dimensions are as close to square as possible while accommodating
// all validators.
func getGridWidth() uint16 {
	// floor(sqrt(numValidators))
	return uint16(math.Floor(math.Sqrt(float64(common.NumberOfValidators))))
}
