package validator

import (
	"crypto/ed25519"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
)

// ValidatorManager handles all validator-related operations
type ValidatorManager struct {
	GridMapper GridMapper
	Index      uint16
	Keys       ValidatorKeys
	state      ValidatorState
}

type ValidatorKeys struct {
	EdPrv     ed25519.PrivateKey
	EdPub     ed25519.PublicKey
	BanderPrv crypto.BandersnatchPrivateKey
	BanderPub crypto.BandersnatchPublicKey
	Bls       crypto.BlsKey
}

func NewValidatorManager(keys ValidatorKeys, state ValidatorState, validatorIdx uint16) *ValidatorManager {
	return &ValidatorManager{
		GridMapper: NewGridMapper(state),
		Index:      validatorIdx,
		Keys:       keys,
		state:      state,
	}
}

func (vm *ValidatorManager) GetNeighbors() ([]*crypto.ValidatorKey, error) {
	all, err := vm.GridMapper.GetAllEpochsNeighborValidators(vm.Index)
	if err != nil {
		return nil, err
	}
	// With full ValidatorState, this is probably not necessary
	return filterOutSelfFromValidators(all, vm.Keys.EdPub), nil
}

func (vm *ValidatorManager) IsNeighbor(key ed25519.PublicKey) bool {
	return vm.GridMapper.IsNeighbor(vm.Keys.EdPub, key, true)
}

func (vm *ValidatorManager) IsSlotLeader(fallbackKeys crypto.EpochKeys) bool {
	currentSlot := jamtime.CurrentTimeslot()
	slotInEpoch := currentSlot.TimeslotInEpoch()
	slotKey := fallbackKeys[slotInEpoch]
	return slotKey == vm.Keys.BanderPub
}

// filterOutSelfFromValidators removes the validator's own key from the list.
func filterOutSelfFromValidators(validators []*crypto.ValidatorKey, selfKey ed25519.PublicKey) []*crypto.ValidatorKey {
	j := 0
	for i := 0; i < len(validators); i++ {
		if !validators[i].Ed25519.Equal(selfKey) {
			validators[j] = validators[i]
			j++
		}
	}
	return validators[:j]
}
