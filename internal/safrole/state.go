package safrole

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
)

// State relevant to Safrole protocol
type State struct {
	NextValidators    ValidatorsData        // (γk) Validator keys for the following epoch.
	TicketAccumulator []block.Ticket        // (γa) Sealing-key contest ticket accumulator.
	SealingKeySeries  TicketsOrKeys         // (γs) Sealing-key series of the current epoch.
	RingCommitment    crypto.RingCommitment // (γz) Bandersnatch ring commitment.
}

type ValidatorData struct {
	Bandersnatch crypto.BandersnatchKey
	Ed25519      crypto.Ed25519PublicKey
	Bls          crypto.BlsKey
	Metadata     crypto.MetadataKey
}
type ValidatorsData [block.NumberOfValidators]ValidatorData
