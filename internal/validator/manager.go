package validator

import (
	"encoding/binary"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
)

// ValidatorManager handles all validator-related operations including grid neighbor
// management, validator identity, and slot leadership checks. It implements the
// connectivity rules defined in the JAMNP-S.
type ValidatorManager struct {
	GridMapper GridMapper
	Index      uint16
	Keys       ValidatorKeys
	State      ValidatorState
}

// ValidatorKeys holds the cryptographic keys required for a validator node.
// These keys are used for signing messages, participating in consensus,
// and establishing secure connections with other nodes.
type ValidatorKeys struct {
	EdPrv     ed25519.PrivateKey
	EdPub     ed25519.PublicKey
	BanderPrv crypto.BandersnatchPrivateKey
	BanderPub crypto.BandersnatchPublicKey
	Bls       crypto.BlsKey
}

// NewValidatorManager creates a new validator manager with the given keys, state,
// and validator index. It initializes the grid mapper to manage neighbor connections
// according to the JAM protocol grid structure.
func NewValidatorManager(keys ValidatorKeys, state ValidatorState, validatorIdx uint16) *ValidatorManager {
	return &ValidatorManager{
		GridMapper: NewGridMapper(state),
		Index:      validatorIdx,
		Keys:       keys,
		State:      state,
	}
}

// GetNeighbors returns the list of validators that this validator should connect to
// according to the JAM protocol grid structure. This includes:
// - Validators in the same row or column in the current epoch
// - Validators with the same index in the previous and next epochs
// The function filters out this validator's own key from the returned list.
func (vm *ValidatorManager) GetNeighbors() ([]crypto.ValidatorKey, error) {
	all, err := vm.GridMapper.GetAllEpochsNeighborValidators(vm.Index)
	if err != nil {
		return nil, err
	}
	// With full ValidatorState, this is probably not necessary
	return filterOutSelfFromValidators(all, vm.Keys.EdPub), nil
}

// IsNeighbor checks if the given validator key represents a neighbor in the grid structure.
// The third parameter 'true' indicates we're checking within the same epoch, where
// validators are considered neighbors if they share the same row or column in the grid.
func (vm *ValidatorManager) IsNeighbor(key ed25519.PublicKey) bool {
	return vm.GridMapper.IsNeighbor(vm.Keys.EdPub, key, true)
}

// IsSlotLeader determines if this validator is the designated leader for the current time slot.
// It compares the validator's Bandersnatch public key with the key assigned to the current slot.
// The fallbackKeys parameter provides the mapping of time slots to designated leader keys.
// TODO: Probably need to have a way to termine the slot leader without the fallbackKeys.
func (vm *ValidatorManager) IsSlotLeader(fallbackKeys crypto.EpochKeys) bool {
	currentSlot := jamtime.CurrentTimeslot()
	slotInEpoch := currentSlot.TimeslotInEpoch()

	// Ensure the fallbackKeys array has enough elements for the current slot
	if int(slotInEpoch) >= len(fallbackKeys) {
		return false
	}

	slotKey := fallbackKeys[slotInEpoch]
	return slotKey == vm.Keys.BanderPub
}

func (vm *ValidatorManager) IsProxyValidatorFor(hash crypto.BandersnatchOutputHash) bool {
	// TODO: Deal with epoch change.
	proxyIndex := vm.DetermineProxyValidatorIndex(hash)
	return vm.State.SafroleState.NextValidators[proxyIndex].Bandersnatch == vm.Keys.BanderPub
}

// DetermineProxyValidatorIndex calculates which validator will serve as the proxy
// for distributing a Safrole ticket based on the VRF output
func (vm *ValidatorManager) DetermineProxyValidatorIndex(hash crypto.BandersnatchOutputHash) uint32 {
	// Take the last 4 bytes of the VRF output
	lastFourBytes := hash[len(hash)-4:]

	// Convert the last 4 bytes to a big-endian uint32 using the binary package
	proxyIndex := binary.BigEndian.Uint32(lastFourBytes)
	// Convert the uint32 to an int

	// Modulo the number of validators to get the final index
	return proxyIndex % uint32(constants.NumberOfValidators)
}

// filterOutSelfFromValidators removes the validator's own key from the list of validators.
// This is used when determining which validators to connect to, as a validator doesn't
// need to establish a connection with itself.
func filterOutSelfFromValidators(validators []crypto.ValidatorKey, selfKey ed25519.PublicKey) []crypto.ValidatorKey {
	j := 0
	for i := 0; i < len(validators); i++ {
		if !validators[i].Ed25519.Equal(selfKey) {
			validators[j] = validators[i]
			j++
		}
	}
	return validators[:j]
}
