package mountain_ranges

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type MMR struct{}

func New() *MMR {
	return &MMR{}
}

// Append implements A function (equation E.8, Graypaper v0.7.2):
//
//	A(r, l, H) ↦ P(r, l, 0, H)
//
// Parameters map to spec as: r=peaks, l=leaf, H=hashFunc
func (m *MMR) Append(r []*crypto.Hash, l crypto.Hash, hashFunc func([]byte) crypto.Hash) []*crypto.Hash {
	return placePeak(r, &l, 0, hashFunc)
}

// placePeak implements P function (equation E.8, Graypaper v0.7.2):
//
//	P(r, l, n, H) ↦ { r ++ l                              if n ≥ |r|
//	               { R(r, n, l)                           if n < |r| ∧ rₙ = ∅
//	               { P(R(r, n, ∅), H(rₙ ⌢ l), n + 1, H)   otherwise
func placePeak(peaks []*crypto.Hash, item *crypto.Hash, position int, hashFunc func([]byte) crypto.Hash) []*crypto.Hash {
	if position >= len(peaks) {
		// r ++ l case
		return append(peaks, item)
	}

	if peaks[position] == nil {
		// R(r, n, l) case
		return replacePeakAt(peaks, position, item)
	}

	// P(R(r, n, ∅), H(rₙ ⌢ l), n + 1, H) case
	combined := append((*peaks[position])[:], (*item)[:]...)
	hash := hashFunc(combined)
	return placePeak(replacePeakAt(peaks, position, nil), &hash, position+1, hashFunc)
}

// replacePeakAt implements R function (equation E.8, Graypaper v0.7.2):
//
//	R: ([T], N, T) → [T]
//	   (s, i, v) ↦ s' where s'ᵢ = v and s'ⱼ = sⱼ for j ≠ i
func replacePeakAt(peaks []*crypto.Hash, index int, value *crypto.Hash) []*crypto.Hash {
	result := make([]*crypto.Hash, len(peaks))
	copy(result, peaks)
	result[index] = value
	return result
}

// Encode implements E_M function (equation E.9, Graypaper v0.7.2):
//
//	E_M(b) ↦ E(↕[¿x | x ← b])
func (m *MMR) Encode(peaks []*crypto.Hash) ([]byte, error) {
	encoded, err := jam.Marshal(peaks)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

// SuperPeak implements M_R function (equation E.10, Graypaper v0.7.2):
//
//	M_R(b) ↦ { H₀                                        if |h| = 0
//	        { h₀                                        if |h| = 1
//	        { H_K($peak ⌢ M_R(h...|h|−1) ⌢ h|h|−1)      otherwise
//	        where h = [h | h ← b, h ≠ ∅]
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

	// H_K($peak ⌢ M_R(h...|h|-1) ⌢ h|h|-1)
	lastHash := *validPeaks[len(validPeaks)-1]

	subPeak := m.SuperPeak(validPeaks[:len(validPeaks)-1], hashFunc)

	combined := append([]byte("peak"), subPeak[:]...)
	combined = append(combined, lastHash[:]...)
	result := hashFunc(combined)

	return result
}
