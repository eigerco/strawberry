package safrole

import (
	"fmt"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// State relevant to Safrole protocol
type State struct {
	NextValidators    ValidatorsData        // (γk) Validator keys for the following epoch.
	TicketAccumulator []block.Ticket        // (γa) Sealing-key contest ticket accumulator.
	SealingKeySeries  TicketAccumulator     // (γs) Sealing-key series of the current epoch.
	RingCommitment    crypto.RingCommitment // (γz) Bandersnatch ring commitment.
}

type ValidatorsData [common.NumberOfValidators]*crypto.ValidatorKey

// Returns the RingCommitment for this state i.e. γz.
func (state State) CalculateRingCommitment() (crypto.RingCommitment, error) {
	ringVerifier, err := state.RingVerifier()
	defer ringVerifier.Free()
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

// Takes a private bandersnatch key and returns a new RingVrfProver for this state.
func (state State) RingProver(privateKey crypto.BandersnatchPrivateKey) (*bandersnatch.RingVrfProver, error) {
	publicKey, err := bandersnatch.Public(privateKey)
	if err != nil {
		return nil, err
	}

	ring := make([]crypto.BandersnatchPublicKey, len(state.NextValidators))
	for i, vd := range state.NextValidators {
		ring[i] = vd.Bandersnatch
	}

	// Find the prover index in the ring, if we don't find a match we return an
	// error.
	proverIdx := 0
	found := false
	for i, pk := range ring {
		if pk == publicKey {
			proverIdx = i
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("private key is not a ring member")
	}

	return bandersnatch.NewRingProver(privateKey, ring, uint(proverIdx))
	if err != nil {
		return nil, err
	}
	return ringProver, nil
}

// SelectFallbackKeys selects the fallback keys for the sealing key series.
// Implements the F function from the graypaper. Equation 71.
func SelectFallbackKeys(entropy crypto.Hash, currentValidators ValidatorsData) (crypto.EpochKeys, error) {
	var fallbackKeys crypto.EpochKeys
	for i := uint32(0); i < jamtime.TimeslotsPerEpoch; i++ {
		// E₄(i): Encode i as a 4-byte sequence
		iBytes, err := jam.Marshal(i)
		if err != nil {
			return crypto.EpochKeys{}, err
		}
		// r ⌢ E₄(i): Concatenate entropy with encoded i
		data := append(entropy[:], iBytes...)
		// H₄(r ⌢ E₄(i)): Take first 4 bytes of Blake2 hash
		hash := crypto.HashData(data)
		// E⁻¹(...): Decode back to a number
		var index uint32
		err = jam.Unmarshal(hash[:], &index)
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
