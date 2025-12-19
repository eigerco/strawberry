package pvm

import (
	"bytes"
	"fmt"

	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const BitmaskMax = 24

type ProgramMemorySizes struct {
	RODataSize       uint32 `jam:"length=3"`
	RWDataSize       uint32 `jam:"length=3"`
	InitialHeapPages uint16 `jam:"length=2"`
	StackSize        uint32 `jam:"length=3"`
}

// Program let E3(|o|) ⌢ E3(|w|) ⌢ E2(z) ⌢ E3(s) ⌢ o ⌢ w ⌢ E4(|c|) ⌢ c = p (eq. A.38 v0.7.2)
type Program struct {
	ProgramMemorySizes ProgramMemorySizes
	ROData             []byte
	RWData             []byte
	CodeAndJumpTable   []byte
}

// ParseBlob let E3(|o|) ⌢ E3(|w|) ⌢ E2(z) ⌢ E3(s) ⌢ o ⌢ w ⌢ E4(|c|) ⌢ c = p (eq. A.38 v0.7.2)
func ParseBlob(data []byte) (program *Program, err error) {
	program = &Program{ProgramMemorySizes: ProgramMemorySizes{}}
	buff := bytes.NewBuffer(data)
	dec := jam.NewDecoder(buff)
	if err := dec.Decode(&program.ProgramMemorySizes); err != nil {
		return nil, err
	}
	if err := dec.DecodeFixedLength(&program.ROData, uint(program.ProgramMemorySizes.RODataSize)); err != nil {
		return nil, err
	}
	if int(program.ProgramMemorySizes.RODataSize) != len(program.ROData) {
		return nil, fmt.Errorf("ro data size mismatch")
	}
	if err := dec.DecodeFixedLength(&program.RWData, uint(program.ProgramMemorySizes.RWDataSize)); err != nil {
		return nil, err
	}
	if int(program.ProgramMemorySizes.RWDataSize) != len(program.RWData) {
		return nil, fmt.Errorf("rw data size mismatch")
	}

	var codeSize uint32
	if err := dec.Decode(&codeSize); err != nil {
		return nil, err
	}
	if len(buff.Bytes()) != int(codeSize) {
		return nil, fmt.Errorf("code size mismatch")
	}

	program.CodeAndJumpTable = buff.Bytes()
	return program, nil
}

type CodeAndJumpTableLengths struct {
	JumpTableEntryCount uint
	JumpTableEntrySize  byte
	CodeLength          uint
}

// Deblob deblob(p B) → (B, b, ⟦NR⟧) ∪ ∇ ↦ p = Ε(|j|) ⌢ E1(z) ⌢ E(|c|) ⌢ E_z(j) ⌢ E(c) ⌢ E(k), |k| = |c| (eq. A.2 v0.7.2)
func Deblob(bytecode []byte) ([]byte, jam.BitSequence, []uint64, error) {
	sizes := &CodeAndJumpTableLengths{}

	buff := bytes.NewBuffer(bytecode)
	dec := jam.NewDecoder(buff)
	// Ε(|j|) ⌢ E1(z) ⌢ E(|c|)
	if err := dec.Decode(sizes); err != nil {
		return nil, nil, nil, err
	}

	// E_z(j)
	jumpTable := make([]uint64, sizes.JumpTableEntryCount)
	for i := range jumpTable {
		if err := dec.DecodeFixedLength(&jumpTable[i], uint(sizes.JumpTableEntrySize)); err != nil {
			return nil, nil, nil, err
		}
	}
	// E(c)
	code := make([]byte, sizes.CodeLength)
	if err := dec.DecodeFixedLength(&code, sizes.CodeLength); err != nil {
		return nil, nil, nil, err
	}

	var bitmask = jam.BitSequence{}
	// E(k)
	if err := dec.DecodeFixedLength(&bitmask, sizes.CodeLength); err != nil {
		return nil, nil, nil, err
	}

	return code, bitmask, jumpTable, nil
}

// PrecomputeSkipLengths precomputes skip(i N) → N (eq. A.3 v0.7.2) for all positions.
func PrecomputeSkipLengths(bitmask []bool) []uint8 {
	n := len(bitmask)
	skipLengths := make([]uint8, n)

	distanceToNext := 0
	for i := n - 1; i >= 0; i-- {
		if distanceToNext > BitmaskMax {
			skipLengths[i] = BitmaskMax
		} else {
			skipLengths[i] = uint8(distanceToNext)
		}

		// Update distance for next iteration
		if bitmask[i] {
			distanceToNext = 0
		} else {
			distanceToNext++
		}
	}

	return skipLengths
}
