package mountain_ranges

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type MMR struct{}

func New() *MMR {
	return &MMR{}
}

// Append (A function): A(r, l, H) ↦ P(r, l, 0, H) from equation (327)
func (m *MMR) Append(r []*crypto.Hash, l crypto.Hash, hashFunc func([]byte) crypto.Hash) []*crypto.Hash {
	return placePeak(r, &l, 0, hashFunc)
}

// placePeak implements P function from equation (327):
// P(r, l, n, H) ↦ { r ++ l    if n ≥ |r|
//
//	{ R(r, n, l)               if n < |r| ∧ rₙ = Ø
//	{ P(R(r, n, Ø), H(rₙ ~ l), n + 1, H)      otherwise
func placePeak(peaks []*crypto.Hash, item *crypto.Hash, position int, hashFunc func([]byte) crypto.Hash) []*crypto.Hash {
	if position >= len(peaks) {
		// r ++ l case
		return append(peaks, item)
	}

	if peaks[position] == nil {
		// R(r, n, l) case
		return replacePeakAt(peaks, position, item)
	}

	// P(R(r, n, Ø), H(rₙ ~ l), n + 1, H) case
	combined := append((*peaks[position])[:], (*item)[:]...)
	hash := hashFunc(combined)
	return placePeak(replacePeakAt(peaks, position, nil), &hash, position+1, hashFunc)
}

// replacePeakAt implements R function from equation (327):
// R: ([T], N, T) → [T]
//
//	(s, i, v) ↦ s' where s'ᵢ = v and s'ⱼ = sⱼ for j ≠ i
func replacePeakAt(peaks []*crypto.Hash, index int, value *crypto.Hash) []*crypto.Hash {
	result := make([]*crypto.Hash, len(peaks))
	copy(result, peaks)
	result[index] = value
	return result
}

// Encode implements E_M function from equation (328):
func (m *MMR) Encode(peaks []*crypto.Hash) ([]byte, error) {
	encoded, err := jam.Marshal(peaks)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

// SuperPeak implements M_R function from equation (E.10) Graypaper 0.5.3
func (m *MMR) SuperPeak(peaks []*crypto.Hash, hashFunc func([]byte) crypto.Hash) crypto.Hash {
	// Filter out nil peaks while preserving order
	validPeaks := make([]*crypto.Hash, 0, len(peaks))
	for _, peak := range peaks {
		if peak != nil {
			validPeaks = append(validPeaks, peak)
		}
	}

	// Empty case: |h| = 0
	if len(validPeaks) == 0 {
		return crypto.Hash{}
	}

	// Single peak case: |h| = 1
	if len(validPeaks) == 1 {
		return *validPeaks[0]
	}

	// H_K($peak ~ M_R(h...|h|-1) ~ h|h|-1).
	lastHash := *validPeaks[len(validPeaks)-1]

	subPeak := m.SuperPeak(validPeaks[:len(validPeaks)-1], hashFunc)

	combined := append([]byte("peak"), subPeak[:]...) // Graypaper 0.5.4
	combined = append(combined, lastHash[:]...)
	result := hashFunc(combined)

	return result
}
