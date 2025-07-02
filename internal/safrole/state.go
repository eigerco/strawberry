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
// GP v0.7.0
type State struct {
	NextValidators    ValidatorsData        // (γP) Validator keys for the following epoch.
	RingCommitment    crypto.RingCommitment // (γZ) Bandersnatch ring commitment.
	SealingKeySeries  SealingKeys           // (γS) Sealing-key series of the current epoch.
	TicketAccumulator []block.Ticket        // (γA) Sealing-key contest ticket accumulator.
}

type ValidatorsData [common.NumberOfValidators]crypto.ValidatorKey

// Returns a new RingVrfVerifier for this these validators.
func (vsd ValidatorsData) RingVerifier() (*bandersnatch.RingVrfVerifier, error) {
	ring := make([]crypto.BandersnatchPublicKey, len(vsd))
	for i, vd := range vsd {
		ring[i] = vd.Bandersnatch
	}
	return bandersnatch.NewRingVerifier(ring)
}

// Returns the RingCommitment for this validator set.
func (vsd ValidatorsData) RingCommitment() (crypto.RingCommitment, error) {
	ringVerifier, err := vsd.RingVerifier()
	defer ringVerifier.Free()
	if err != nil {
		return crypto.RingCommitment{}, err
	}
	return ringVerifier.Commitment()
}

// Takes a private bandersnatch key and returns a new RingVrfProver for this validator set.
func (vsd ValidatorsData) RingProver(privateKey crypto.BandersnatchPrivateKey) (*bandersnatch.RingVrfProver, error) {
	publicKey, err := bandersnatch.Public(privateKey)
	if err != nil {
		return nil, err
	}

	ring := make([]crypto.BandersnatchPublicKey, len(vsd))
	for i, vd := range vsd {
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
}

// SelectFallbackKeys selects the fallback keys for the sealing key series.
// Implements the F function from the graypaper.
// Equation 6.26:
// (r, k) -> [k_E4^-1 (H(r~E4(i))...4)_b^↺ | ∈ N_E]
// GP v0.7.0
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

// OutsideInSequence implements the Z function from the graypaper.
// Equation 6.25
// s ↦ [s0, s_|s|-1, s1, s_|s|-2, ...]
// GP v0.7.0
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
