package block

import (
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
)

const AvailBitfieldBytes = (common.TotalNumberOfCores + 7) / 8 // (cores-count + 7) / 8

// Assurance represents a single validator's attestation of data availability
// for work reports on specific cores. It is part of the Assurances Extrinsic (E_A).
// Each Assurance contains:
// - An anchor to the parent block
// - A bitstring flag indicating availability for each core
// - The index of the attesting validator (0 to 1023)
// - A signature validating the assurance
// Assurances must be ordered by validator index in the extrinsic.
type Assurance struct {
	Anchor         crypto.Hash              // Parent block hash (a ∈ H)
	Bitfield       [AvailBitfieldBytes]byte // Bitstring of assurances, one bit per core (f ∈ B_C)
	ValidatorIndex uint16                   // Index of the attesting validator (v ∈ N_V)
	Signature      crypto.Ed25519Signature  // Ed25519 signature (s ∈ E)
}

type AssurancesExtrinsic []Assurance
