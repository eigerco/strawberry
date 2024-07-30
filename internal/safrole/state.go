package safrole

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
)

// State relevant to Safrole protocol
type State struct {
	Tau    uint32         `json:"tau"`     // Most recent block's timeslot.
	Eta    [4]crypto.Hash `json:"eta"`     // Entropy accumulator and epochal randomness.
	Lambda ValidatorsData `json:"lambda"`  // Validator keys and metadata which were active in the prior epoch.
	Kappa  ValidatorsData `json:"kappa"`   // Validator keys and metadata currently active.
	GammaK ValidatorsData `json:"gamma_k"` // Validator keys for the following epoch.
	Iota   ValidatorsData `json:"iota"`    // Validator keys and metadata to be drawn from next.
	GammaA []block.Ticket `json:"gamma_a"` // Sealing-key contest ticket accumulator.
	GammaS TicketsOrKeys  `json:"gamma_s"` // Sealing-key series of the current epoch.
	GammaZ GammaZ         `json:"gamma_z"` // Bandersnatch ring commitment.
}

type ValidatorData struct {
	Bandersnatch BandersnatchKey `json:"bandersnatch"`
	Ed25519      Ed25519Key      `json:"ed25519"`
	Bls          BlsKey          `json:"bls"`
	Metadata     MetadataKey     `json:"metadata"`
}
type ValidatorsData [block.NumberOfValidators]ValidatorData
