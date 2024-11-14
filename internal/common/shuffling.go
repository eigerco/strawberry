package common

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
	"golang.org/x/crypto/blake2b"
)

var serializer = serialization.NewSerializer(codec.NewJamCodec())

// DeterministicShuffle performs a deterministic shuffle of the sequence s based on the hash h (appendix F)
func DeterministicShuffle(length uint32, h crypto.Hash) ([]uint32, error) {
	s := make([]uint32, length)
	for i := uint32(0); i < length; i++ {
		s[i] = i
	}

	r, err := generateRandomNumbers(h, length)
	if err != nil {
		return nil, err
	}
	return recursiveShuffle(s, r), nil
}

// recursiveShuffle recursively shuffles the sequence s using the random numbers r
func recursiveShuffle(s []uint32, r []uint32) []uint32 {
	l := len(s)
	if l == 0 {
		return []uint32{}
	}

	index := r[0] % uint32(l)
	head := s[index]

	sPost := make([]uint32, l)
	copy(sPost, s)

	sPost[index] = sPost[l-1]
	sPost = sPost[:l-1]

	return append([]uint32{head}, recursiveShuffle(sPost, r[1:])...)
}

// generateRandomNumbers (Q_l(h)) generates a sequence of l uint32 numbers from the hash h
func generateRandomNumbers(h crypto.Hash, l uint32) ([]uint32, error) {
	r := make([]uint32, l)
	for i := uint32(0); i < l; i++ {
		k := i / 8
		kBytes, err := serializer.Encode(k)
		if err != nil {
			return nil, err
		}

		input := append(h[:], kBytes...)
		hash := blake2b.Sum256(input)

		p := (4 * i) % 32
		var b [4]byte
		for j := uint32(0); j < 4; j++ {
			b[j] = hash[(p+j)%32]
		}

		var rI uint32
		err = serializer.Decode(b[:], &rI)
		if err != nil {
			return nil, err
		}
		r[i] = rI
	}
	return r, nil
}
