package mountain_ranges

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
)

type MMR struct{}

func New() *MMR {
	return &MMR{}
}

// Append (A function): A(r, l, H) ↦ P(r, l, 0, H) from equation (327)
func (m *MMR) Append(r []*crypto.Hash, l crypto.Hash, hashFunc func([]byte) crypto.Hash) []*crypto.Hash {
	hash := hashFunc(l[:])
	return placePeak(r, &hash, 0, hashFunc)
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
	jamCodec := codec.NewJamCodec()
	serializer := serialization.NewSerializer(jamCodec)

	encoded, err := serializer.Encode(peaks)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
