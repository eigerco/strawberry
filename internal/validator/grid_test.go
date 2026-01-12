package validator

import (
	"math"
	"testing"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/stretchr/testify/assert"
)

func TestNewGridMapper(t *testing.T) {
	state := ValidatorState{
		CurrentValidators:  safrole.ValidatorsData{},
		ArchivedValidators: safrole.ValidatorsData{},
		QueuedValidators:   safrole.ValidatorsData{},
	}
	mapper := NewGridMapper(state)

	assert.Equal(t, state.CurrentValidators, mapper.currentValidators)
	assert.Equal(t, state.ArchivedValidators, mapper.archivedValidators)
	assert.Equal(t, state.QueuedValidators, mapper.queuedValidators)
}

func TestGetAllEpochsNeighborValidators(t *testing.T) {
	validators := safrole.ValidatorsData{}
	mapper := GridMapper{
		currentValidators:  validators,
		archivedValidators: validators,
		queuedValidators:   validators,
	}

	neighbors, err := mapper.GetAllEpochsNeighborValidators(0)
	assert.NoError(t, err)
	assert.Len(t, neighbors, 64) //62 neighbors + 1 archived + 1 queued
}

func TestFindValidatorIndex(t *testing.T) {
	key := ed25519.PublicKey("key")
	validators := safrole.ValidatorsData{}
	validators[1] = crypto.ValidatorKey{Ed25519: key}
	mapper := GridMapper{currentValidators: validators}
	index, found := mapper.FindValidatorIndex(key)
	assert.True(t, found)
	assert.Equal(t, uint16(1), index)

	_, found = mapper.FindValidatorIndex(ed25519.PublicKey("missing"))
	assert.False(t, found)
}

func TestIsNeighbor(t *testing.T) {
	// Setup basic validator data structures
	currentValidators := safrole.ValidatorsData{}
	archivedValidators := safrole.ValidatorsData{}
	queuedValidators := safrole.ValidatorsData{}

	// Create test keys
	key1 := ed25519.PublicKey("key1")
	key2 := ed25519.PublicKey("key2")
	key3 := ed25519.PublicKey("key3")
	key4 := ed25519.PublicKey("key4")
	key5 := ed25519.PublicKey("key5")
	keyNotValidator := ed25519.PublicKey("notvalidator")

	// Calculate grid width based on total validator count
	gridWidth := uint16(math.Floor(math.Sqrt(float64(constants.NumberOfValidators))))

	// Setup indices for different test scenarios
	sameRowIdx1 := uint16(0)
	sameRowIdx2 := uint16(1)
	sameColIdx2 := gridWidth
	differentIdx := gridWidth + 1
	crossEpochIdx := uint16(42)

	// Setup validators in current epoch
	currentValidators[sameRowIdx1] = crypto.ValidatorKey{Ed25519: key1}
	currentValidators[sameRowIdx2] = crypto.ValidatorKey{Ed25519: key2}
	currentValidators[sameColIdx2] = crypto.ValidatorKey{Ed25519: key3}
	currentValidators[differentIdx] = crypto.ValidatorKey{Ed25519: key4}
	currentValidators[crossEpochIdx] = crypto.ValidatorKey{Ed25519: key5}

	// Setup validators in archived and queued epochs
	archivedValidators[crossEpochIdx] = crypto.ValidatorKey{Ed25519: key1}
	queuedValidators[crossEpochIdx] = crypto.ValidatorKey{Ed25519: key2}

	mapper := GridMapper{
		currentValidators:  currentValidators,
		archivedValidators: archivedValidators,
		queuedValidators:   queuedValidators,
	}

	tests := []struct {
		name      string
		key1      ed25519.PublicKey
		key2      ed25519.PublicKey
		sameEpoch bool
		want      bool
		reason    string
	}{
		{
			name:      "same epoch - same row",
			key1:      key1,
			key2:      key2,
			sameEpoch: true,
			want:      true,
			reason:    "validators in same row should be neighbors",
		},
		{
			name:      "same epoch - same column",
			key1:      key1,
			key2:      key3,
			sameEpoch: true,
			want:      true,
			reason:    "validators in same column should be neighbors",
		},
		{
			name:      "same epoch - different row and column",
			key1:      key1,
			key2:      key4,
			sameEpoch: true,
			want:      false,
			reason:    "validators in different rows and columns should not be neighbors",
		},
		{
			name:      "same epoch - self connection",
			key1:      key1,
			key2:      key1,
			sameEpoch: true,
			want:      false,
			reason:    "validator should not be neighbor with itself",
		},
		{
			name:      "different epochs - same index",
			key1:      key1,
			key2:      key2,
			sameEpoch: false,
			want:      true,
			reason:    "validators with same index in different epochs should be neighbors",
		},
		{
			name:      "different epochs - self connection",
			key1:      key1,
			key2:      key1,
			sameEpoch: false,
			want:      false,
			reason:    "validator should not be neighbor with itself across epochs",
		},
		{
			name:      "non-validator key",
			key1:      key1,
			key2:      keyNotValidator,
			sameEpoch: true,
			want:      false,
			reason:    "non-validator key should not be neighbor with any validator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapper.IsNeighbor(tt.key1, tt.key2, tt.sameEpoch)
			assert.Equal(t, tt.want, got, tt.reason)
		})
	}
}
