package block

import "github.com/eigerco/strawberry/internal/crypto"

// Assurance represents a single validator's attestation of data availability
// for work reports on specific cores. It is part of the Assurances Extrinsic (E_A).
// Each Assurance contains:
// - An anchor to the parent block
// - A bitstring flag indicating availability for each core
// - The index of the attesting validator (0 to 1023)
// - A signature validating the assurance
// Assurances must be ordered by validator index in the extrinsic.
type Assurance struct {
	Anchor         crypto.Hash                       // Parent block hash (a ∈ H)
	Flag           bool                              // Bitstring of assurances, one bit per core (f ∈ B_C)
	ValidatorIndex uint16                            // Index of the attesting validator (v ∈ N_V)
	Signature      [crypto.Ed25519SignatureSize]byte // Ed25519 signature (s ∈ E)
}

type AssurancesExtrinsic []Assurance
