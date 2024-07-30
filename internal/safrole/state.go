package safrole

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
)

// State relevant to Safrole protocol
type State struct {
	MostRecentTimeslot uint32                // (τ) Most recent block's timeslot.
	EntropyAccumulator [4]crypto.Hash        // (η) Entropy accumulator and epochal randomness.
	PreviousValidators ValidatorsData        // (λ) Validator keys and metadata which were active in the prior epoch.
	CurrentValidators  ValidatorsData        // (κ) Validator keys and metadata currently active.
	NextValidators     ValidatorsData        // (γk) Validator keys for the following epoch.
	FutureValidators   ValidatorsData        // (ι) Validator keys and metadata to be drawn from next.
	TicketAccumulator  []block.Ticket        // (γa) Sealing-key contest ticket accumulator.
	SealingKeySeries   TicketsOrKeys         // (γs) Sealing-key series of the current epoch.
	RingCommitment     crypto.RingCommitment // (γz) Bandersnatch ring commitment.
}

type ValidatorData struct {
	Bandersnatch crypto.BandersnatchKey
	Ed25519      crypto.Ed25519PublicKey
	Bls          crypto.BlsKey
	Metadata     crypto.MetadataKey
}
type ValidatorsData [block.NumberOfValidators]ValidatorData
