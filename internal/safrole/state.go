package safrole

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
)

// State relevant to Safrole protocol
type State struct {
	NextValidators    ValidatorsData        // (γk) Validator keys for the following epoch.
	TicketAccumulator []block.Ticket        // (γa) Sealing-key contest ticket accumulator.
	SealingKeySeries  TicketsOrKeys         // (γs) Sealing-key series of the current epoch.
	RingCommitment    crypto.RingCommitment // (γz) Bandersnatch ring commitment.
}

type ValidatorsData [common.NumberOfValidators]crypto.ValidatorKey

// Returns the RingCommitment for this state i.e. γz.
func (state State) CalculateRingCommitment() (crypto.RingCommitment, error) {
	ringVerifier, err := state.RingVerifier()
	if err != nil {
		return crypto.RingCommitment{}, err
	}
	return ringVerifier.Commitment()
}

// Returns a new RingVrfVerifier for this state.
func (state State) RingVerifier() (*bandersnatch.RingVrfVerifier, error) {
	ring := make([]crypto.BandersnatchPublicKey, len(state.NextValidators))
	for i, vd := range state.NextValidators {
		ring[i] = vd.Bandersnatch
	}
	ringVerifier, err := bandersnatch.NewRingVerifier(ring)
	if err != nil {
		return nil, err
	}
	return ringVerifier, nil
}

// SelectFallbackKeys selects the fallback keys for the sealing key series.
// Implements the F function from the graypaper. Equation 71.
func SelectFallbackKeys(entropy crypto.Hash, currentValidators ValidatorsData) (crypto.EpochKeys, error) {
	var fallbackKeys crypto.EpochKeys
	serializer := serialization.NewSerializer(&codec.JAMCodec{})
	for i := uint32(0); i < jamtime.TimeslotsPerEpoch; i++ {
		// E₄(i): Encode i as a 4-byte sequence
		iBytes, err := serializer.Encode(i)
		if err != nil {
			return crypto.EpochKeys{}, err
		}
		// r ⌢ E₄(i): Concatenate entropy with encoded i
		data := append(entropy[:], iBytes...)
		// H₄(r ⌢ E₄(i)): Take first 4 bytes of Blake2 hash
		hash := crypto.HashData(data)
		// E⁻¹(...): Decode back to a number
		var index uint32
		err = serializer.Decode(hash[:], &index)
		if err != nil {
			return crypto.EpochKeys{}, err
		}
		// k[...]↺b: Select validator key and wrap around if needed
		fallbackKeys[i] = currentValidators[index%uint32(len(currentValidators))].Bandersnatch
	}
	return fallbackKeys, nil
}

// OutsideInSequence implements the Z function from the graypaper. Equation 70.
func OutsideInSequence(tickets []block.Ticket) []block.Ticket {
	n := len(tickets)
	result := make([]block.Ticket, n)
	left, right := 0, n-1
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			// Even indices: take from the left of the original sequence
			result[i] = tickets[left]
			left++
		} else {
			// Odd indices: take from the right of the original sequence
			result[i] = tickets[right]
			right--
		}
	}
	return result
}
