package safrole

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
)

// State relevant to Safrole protocol
type State struct {
	MostRecentTimeslot uint32                `json:"tau"`     // Most recent block's timeslot.
	EntropyAccumulator [4]crypto.Hash        `json:"eta"`     // Entropy accumulator and epochal randomness.
	PreviousValidators ValidatorsData        `json:"lambda"`  // Validator keys and metadata which were active in the prior epoch.
	CurrentValidators  ValidatorsData        `json:"kappa"`   // Validator keys and metadata currently active.
	NextValidators     ValidatorsData        `json:"gamma_k"` // Validator keys for the following epoch.
	FutureValidators   ValidatorsData        `json:"iota"`    // Validator keys and metadata to be drawn from next.
	TicketAccumulator  []block.Ticket        `json:"gamma_a"` // Sealing-key contest ticket accumulator.
	SealingKeySeries   TicketsOrKeys         `json:"gamma_s"` // Sealing-key series of the current epoch.
	RingCommitment     crypto.RingCommitment `json:"gamma_z"` // Bandersnatch ring commitment.
}

type ValidatorData struct {
	Bandersnatch crypto.BandersnatchKey  `json:"bandersnatch"`
	Ed25519      crypto.Ed25519PublicKey `json:"ed25519"`
	Bls          crypto.BlsKey           `json:"bls"`
	Metadata     crypto.MetadataKey      `json:"metadata"`
}
type ValidatorsData [block.NumberOfValidators]ValidatorData
