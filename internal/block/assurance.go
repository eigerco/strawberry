package block

import (
	"io"

	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const AvailBitfieldBytes = (constants.TotalNumberOfCores + 7) / 8 // (cores-count + 7) / 8

// Assurance represents a single validator's attestation of data availability
// for work reports on specific cores. It is part of the Assurances Extrinsic (E_A).
// Each Assurance contains:
// - An anchor to the parent block
// - A bitstring flag indicating availability for each core
// - The index of the attesting validator (0 to 1023)
// - A signature validating the assurance
// Assurances must be ordered by validator index in the extrinsic.
// EA ∈ ⟦{a ∈ H, f ∈ bC, v ∈ NV, s ∈ V̄}⟧:V (eq. 11.10 v 0.7.0)
type Assurance struct {
	Anchor         crypto.Hash              // Parent block hash (a ∈ H)
	Bitfield       [AvailBitfieldBytes]byte // Bitstring of assurances, one bit per core (f ∈ B_C)
	ValidatorIndex uint16                   // Index of the attesting validator (v ∈ N_V)
	Signature      crypto.Ed25519Signature  // Ed25519 signature (s ∈ V̄)
}

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (a *Assurance) UnmarshalJAM(r io.Reader) error {
	if _, err := io.ReadFull(r, a.Anchor[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, a.Bitfield[:]); err != nil {
		return err
	}
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return err
	}
	a.ValidatorIndex = jam.DecodeUint16(buf[:])
	_, err := io.ReadFull(r, a.Signature[:])
	return err
}

type AssurancesExtrinsic []Assurance

// IsForCore checks if the validator has assured availability for a specific core.
// The bitfield uses LSB-first ordering within each byte:
//   - 1 byte: 00000011 means core indexes 0 and 1 are assured
//   - Multiple bytes: byte[0] contains core indexes 0-7, byte[1] contains core indexes 8-15, etc.
//
// Example: [00000011, 00000001] means core indexes 0,1,8 are assured
func (a Assurance) IsForCore(coreIndex uint16) bool {
	byteIndex := coreIndex / 8
	bitIndex := coreIndex % 8
	return (a.Bitfield[byteIndex] & (1 << bitIndex)) != 0
}

func (a Assurance) SetCoreIndexes() []uint16 {
	indexes := []uint16{}

	// TODO make this more efficient, but this is fine for now.
	for i := uint16(0); i < constants.TotalNumberOfCores; i++ {
		if a.IsForCore(i) {
			indexes = append(indexes, i)
		}
	}

	return indexes
}
