package safrole

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
	"golang.org/x/crypto/blake2b"
)

// State relevant to Safrole protocol
type State struct {
	NextValidators    ValidatorsData        // (γk) Validator keys for the following epoch.
	TicketAccumulator []block.Ticket        // (γa) Sealing-key contest ticket accumulator.
	SealingKeySeries  TicketsOrKeys         // (γs) Sealing-key series of the current epoch.
	RingCommitment    crypto.RingCommitment // (γz) Bandersnatch ring commitment.
}

type ValidatorsData [block.NumberOfValidators]crypto.ValidatorKey

// DetermineNewSealingKeys determines the new sealing keys for an epoch
func DetermineNewSealingKeys(currentTimeslot jamtime.Timeslot, ticketAccumulator []block.Ticket, currentSealingKeys TicketsOrKeys, epochMarker *block.EpochMarker) (TicketsOrKeys, error) {
	// If this is not the first timeslot in the epoch, return current keys
	if !currentTimeslot.IsFirstTimeslotInEpoch() {
		return currentSealingKeys, nil
	}
	var ticketsOrKeys TicketsOrKeys
	// If we don't have the correct number of tickets, proceed with the F function
	if len(ticketAccumulator) != int(jamtime.TimeslotsPerEpoch) {
		fallbackKeys, err := SelectFallbackKeys(epochMarker)
		if err != nil {
			return TicketsOrKeys{}, err
		}
		err = ticketsOrKeys.SetValue(fallbackKeys)
		if err != nil {
			return TicketsOrKeys{}, err
		}
	} else {
		// Everything is in order, proceed with the outside-in sequencer function Z
		orderedTickets := OutsideInSequence(ticketAccumulator)
		err := ticketsOrKeys.SetValue(TicketsBodies(orderedTickets))
		if err != nil {
			return TicketsOrKeys{}, err
		}
	}
	return ticketsOrKeys, nil
}

// SelectFallbackKeys selects the fallback keys for the sealing key series. Implements the F function from the graypaper
func SelectFallbackKeys(em *block.EpochMarker) (crypto.EpochKeys, error) {
	var fallbackKeys crypto.EpochKeys
	serializer := serialization.NewSerializer(&codec.JAMCodec{})
	for i := uint32(0); i < jamtime.TimeslotsPerEpoch; i++ {
		// E₄(i): Encode i as a 4-byte sequence
		iBytes, err := serializer.Encode(i)
		if err != nil {
			return crypto.EpochKeys{}, err
		}
		// r ⌢ E₄(i): Concatenate entropy with encoded i
		data := append(em.Entropy[:], iBytes...)
		// H₄(r ⌢ E₄(i)): Take first 4 bytes of Blake2 hash
		hash := blake2b.Sum256(data)
		// E⁻¹(...): Decode back to a number
		var index uint32
		err = serializer.Decode(hash[:], &index)
		if err != nil {
			return crypto.EpochKeys{}, err
		}
		// k[...]↺b: Select validator key and wrap around if needed
		fallbackKeys[i] = em.Keys[index%uint32(len(em.Keys))]
	}
	return fallbackKeys, nil
}

// OutsideInSequence implements the Z function from the graypaper
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
