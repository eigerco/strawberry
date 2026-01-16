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

// ProgramBlob let E3(|o|) ⌢ E3(|w|) ⌢ E2(z) ⌢ E3(s) ⌢ o ⌢ w ⌢ E4(|c|) ⌢ c = p (eq. A.38 v0.7.2)
type ProgramBlob struct {
	ProgramMemorySizes ProgramMemorySizes
	ROData             []byte
	RWData             []byte
	CodeAndJumpTable   []byte
}

// ParseBlob let E3(|o|) ⌢ E3(|w|) ⌢ E2(z) ⌢ E3(s) ⌢ o ⌢ w ⌢ E4(|c|) ⌢ c = p (eq. A.38 v0.7.2)
func ParseBlob(data []byte) (program *ProgramBlob, err error) {
	program = &ProgramBlob{ProgramMemorySizes: ProgramMemorySizes{}}
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
func precomputeSkipLengths(bitmask []bool) []uint8 {
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

func initProgram(code []byte, bitmask jam.BitSequence, jumpTable []uint64) *program {
	// Precompute skip lengths for all positions
	bitmaskWithSentinel := append(bitmask, true) // k ⌢ [1, 1, ... ]
	skipLengths := precomputeSkipLengths(bitmaskWithSentinel)

	return &program{
		code:              code,
		jumpTable:         jumpTable,
		bitmask:           bitmaskWithSentinel,
		skipLengths:       skipLengths,
		instructionsCache: make([]*instructionCache, len(code)),
	}
}

// program is the tuple of c,k,j i.e. the code, bitmask and jump table for convenience as well as some caching and
// utility functions required for instance as well as gas simulation
type program struct {
	code      []byte          // ζ
	jumpTable []uint64        // j
	bitmask   jam.BitSequence // k

	skipLengths       []uint8 // precomputed skip lengths for each position
	instructionsCache []*instructionCache
}

type instructionCache struct {
	reg [3]Reg
	val [2]uint64
}

// skip gets the precomputed skip length
func (p *program) skip(instructionCounter uint64) uint8 {
	if instructionCounter >= uint64(len(p.skipLengths)) {
		return 0
	}
	return p.skipLengths[instructionCounter]
}

// opcode gets the opcode for the current instruction counter (eq. A.23 v0.7.2)
func (p *program) opcode(instructionCounter uint64) Opcode {
	op := Opcode(p.code[instructionCounter])
	if !opcodeValid(op) {
		return Trap
	}
	if !p.bitmask[instructionCounter] {
		return Trap
	}
	return op
}

func (p *program) decodeArgsImm(instructionCounter uint64, skipLen uint8) (valueX uint64) {
	if instr := p.instructionsCache[instructionCounter]; instr != nil {
		return instr.val[0]
	}
	// let lX = min(4, ℓ)
	lenX := uint64(min(4, skipLen))

	// νX ≡ X_lX(E−1lX (ζı+1⋅⋅⋅+lX))
	valueX = sext(jam.DecodeUint64(p.code[instructionCounter+1:instructionCounter+1+lenX]), lenX)
	p.instructionsCache[instructionCounter] = &instructionCache{val: [2]uint64{valueX}}
	return valueX
}

func (p *program) decodeArgsRegImmExt(instructionCounter uint64, skipLen uint8) (regA Reg, valueX uint64) {
	if instr := p.instructionsCache[instructionCounter]; instr != nil {
		return instr.reg[0], instr.val[0]
	}
	// let rA = min(12, ζı+1 mod 16), φ′A ≡ φ′rA
	regA = Reg(min(12, p.code[instructionCounter+1]%16))
	// νX ≡ E−1_8(ζı+2⋅⋅⋅+8)
	valueX = jam.DecodeUint64(p.code[instructionCounter+2 : instructionCounter+10])
	p.instructionsCache[instructionCounter] = &instructionCache{reg: [3]Reg{regA}, val: [2]uint64{valueX}}
	return regA, valueX
}

func (p *program) decodeArgsImm2(instructionCounter uint64, skipLen uint8) (valueX, valueY uint64) {
	if instr := p.instructionsCache[instructionCounter]; instr != nil {
		return instr.val[0], instr.val[1]
	}
	// let lX = min(4, ζı+1 mod 8)
	lenX := uint64(min(4, p.code[instructionCounter+1]%8))

	// let lY = min(4, max(0, ℓ − lX − 1))
	lenY := uint64(min(4, max(0, int(skipLen)-int(lenX)-1)))

	// νX ≡ X_lX (E−1lX (ζı+2⋅⋅⋅+lX))
	valueX = sext(jam.DecodeUint64(p.code[instructionCounter+2:instructionCounter+2+lenX]), lenX)

	// νY ≡ XlY (E−1lY (ζı+2+lX ⋅⋅⋅+lY))
	valueY = sext(jam.DecodeUint64(p.code[instructionCounter+2+lenX:instructionCounter+2+lenX+lenY]), lenY)
	p.instructionsCache[instructionCounter] = &instructionCache{val: [2]uint64{valueX, valueY}}
	return valueX, valueY
}

func (p *program) decodeArgsOffset(instructionCounter uint64, skipLen uint8) (valueX uint64) {
	if instr := p.instructionsCache[instructionCounter]; instr != nil {
		return instr.val[0]
	}
	// let lX = min(4, ℓ)
	lenX := uint64(min(4, skipLen))

	// νX ≡ ı + Z_lX (E−1_lX(ζı+1⋅⋅⋅+lX))
	valueX = uint64(int64(instructionCounter) + signed(jam.DecodeUint64(p.code[instructionCounter+1:instructionCounter+1+lenX]), lenX))
	p.instructionsCache[instructionCounter] = &instructionCache{val: [2]uint64{valueX}}
	return valueX
}

func (p *program) decodeArgsRegImm(instructionCounter uint64, skipLen uint8) (regA Reg, valueX uint64) {
	if instr := p.instructionsCache[instructionCounter]; instr != nil {
		return instr.reg[0], instr.val[0]
	}
	// let lX = min(4, max(0, ℓ − 1))
	lenX := uint64(min(4, max(0, int(skipLen)-1)))
	// let rA = min(12, ζı+1 mod 16), φ′A ≡ φ′rA
	regA = Reg(min(12, p.code[instructionCounter+1]%16))

	// νX ≡ X_lX(E−1_lX(ζı+2...+lX))
	valueX = sext(jam.DecodeUint64(p.code[instructionCounter+2:instructionCounter+2+lenX]), lenX)
	p.instructionsCache[instructionCounter] = &instructionCache{reg: [3]Reg{regA}, val: [2]uint64{valueX}}
	return regA, valueX
}

func (p *program) decodeArgsRegImm2(instructionCounter uint64, skipLen uint8) (regA Reg, valueX, valueY uint64) {
	if instr := p.instructionsCache[instructionCounter]; instr != nil {
		return instr.reg[0], instr.val[0], instr.val[1]
	}
	// let rA = min(12, ζı+1 mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = Reg(min(12, p.code[instructionCounter+1]%16))
	// let lX = min(4, ⌊ ζı+1 / 16 ⌋ mod 8)
	lenX := uint64(min(4, (p.code[instructionCounter+1]/16)%8))

	// let lY = min(4, max(0, ℓ − lX − 1))
	lenY := uint64(min(4, max(0, int(skipLen)-int(lenX)-1)))

	// νX = X_lX (E−1lX (ζı+2⋅⋅⋅+lX))
	valueX = sext(jam.DecodeUint64(p.code[instructionCounter+2:instructionCounter+2+lenX]), lenX)

	// νY = X_lY(E−1lY (ζı+2+lX ⋅⋅⋅+lY))
	valueY = sext(jam.DecodeUint64(p.code[instructionCounter+2+lenX:instructionCounter+2+lenX+lenY]), lenY)
	p.instructionsCache[instructionCounter] = &instructionCache{reg: [3]Reg{regA}, val: [2]uint64{valueX, valueY}}
	return regA, valueX, valueY
}

func (p *program) decodeArgsRegImmOffset(instructionCounter uint64, skipLen uint8) (regA Reg, valueX, valueY uint64) {
	if instr := p.instructionsCache[instructionCounter]; instr != nil {
		return instr.reg[0], instr.val[0], instr.val[1]
	}
	// let rA = min(12, ζı+1 mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = Reg(min(12, p.code[instructionCounter+1]%16))
	// let lX = min(4, ⌊ ζı+1 / 16 ⌋ mod 8)
	lenX := uint64(min(4, (p.code[instructionCounter+1]/16)%8))
	// let lY = min(4, max(0, ℓ − lX − 1))
	lenY := uint64(min(4, max(0, int(skipLen)-int(lenX)-1)))

	// νX = X_lX(E−1lX (ζı+2...+lX))
	valueX = sext(jam.DecodeUint64(p.code[instructionCounter+2:instructionCounter+2+lenX]), lenX)
	// νY = ı + ZlY(E−1lY (ζı+2+lX⋅⋅⋅+lY))
	valueY = uint64(int64(instructionCounter) + signed(jam.DecodeUint64(p.code[instructionCounter+2+lenX:instructionCounter+2+lenX+lenY]), lenY))
	p.instructionsCache[instructionCounter] = &instructionCache{reg: [3]Reg{regA}, val: [2]uint64{valueX, valueY}}
	return regA, valueX, valueY
}

func (p *program) decodeArgsReg2(instructionCounter uint64) (regDst, regA Reg) {
	if instr := p.instructionsCache[instructionCounter]; instr != nil {
		return instr.reg[0], instr.reg[1]
	}
	// let rD = min(12, (ζı+1) mod 16) , φD ≡ φrD , φ′D ≡ φ′rD
	regDst = Reg(min(12, p.code[instructionCounter+1]%16))

	// let rA = min(12, ⌊ ζı+1 / 16 ⌋) , φA ≡ φrA , φ′A ≡ φ′rA
	regA = Reg(min(12, p.code[instructionCounter+1]/16))
	p.instructionsCache[instructionCounter] = &instructionCache{reg: [3]Reg{regDst, regA}}
	return regDst, regA
}

func (p *program) decodeArgsReg2Imm(instructionCounter uint64, skipLen uint8) (regA, regB Reg, valueX uint64) {
	if instr := p.instructionsCache[instructionCounter]; instr != nil {
		return instr.reg[0], instr.reg[1], instr.val[0]
	}
	// let lX = min(4, max(0, ℓ − 1))
	lenX := uint64(min(4, max(0, int(skipLen)-1)))
	// let rA = min(12, (ζı+1) mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = Reg(min(12, p.code[instructionCounter+1]%16))
	// let rB = min(12, ⌊ ζı+1 / 16 ⌋), φB ≡ φrB, φ′B ≡ φ′rB
	regB = Reg(min(12, p.code[instructionCounter+1]/16))

	// νX ≡ X_lX(E−1lX(ζı+2...+lX))
	valueX = sext(jam.DecodeUint64(p.code[instructionCounter+2:instructionCounter+2+lenX]), lenX)
	p.instructionsCache[instructionCounter] = &instructionCache{reg: [3]Reg{regA, regB}, val: [2]uint64{valueX}}
	return regA, regB, valueX
}

func (p *program) decodeArgsReg2Offset(instructionCounter uint64, skipLen uint8) (regA, regB Reg, valueX uint64) {
	if instr := p.instructionsCache[instructionCounter]; instr != nil {
		return instr.reg[0], instr.reg[1], instr.val[0]
	}
	// let lX = min(4, max(0, ℓ − 1))
	lenX := uint64(min(4, max(0, int(skipLen)-1)))
	// let rA = min(12, (ζı+1) mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = Reg(min(12, p.code[instructionCounter+1]%16))
	// let rB = min(12, ⌊ ζı+1 / 16 ⌋), φB ≡ φrB, φ′B ≡ φ′rB
	regB = Reg(min(12, p.code[instructionCounter+1]/16))

	// νX ≡ ı + Z_lX(E−1lX(ζı+2...+lX))
	valueX = uint64(int64(instructionCounter) + signed(jam.DecodeUint64(p.code[instructionCounter+2:instructionCounter+2+lenX]), lenX))
	p.instructionsCache[instructionCounter] = &instructionCache{reg: [3]Reg{regA, regB}, val: [2]uint64{valueX}}
	return regA, regB, valueX
}

func (p *program) decodeArgsReg2Imm2(instructionCounter uint64, skipLen uint8) (regA, regB Reg, valueX, valueY uint64) {
	if instr := p.instructionsCache[instructionCounter]; instr != nil {
		return instr.reg[0], instr.reg[1], instr.val[0], instr.val[1]
	}
	// let rA = min(12, (ζı+1) mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = Reg(min(12, p.code[instructionCounter+1]%16))
	// let rB = min(12, ⌊ ζı+1 / 16 ⌋), φB ≡ φrB, φ′B ≡ φ′rB
	regB = Reg(min(12, p.code[instructionCounter+1]/16))
	// let lX = min(4, ζı+2 mod 8)
	lenX := uint64(min(4, p.code[instructionCounter+2]%8))
	// let lY = min(4, max(0, ℓ − lX − 2))
	lenY := uint64(min(4, max(0, int(skipLen)-int(lenX)-2)))

	// νX = X_lX(E−1lX (ζı+3⋅⋅⋅+lX))
	valueX = jam.DecodeUint64(p.code[instructionCounter+3 : instructionCounter+3+lenX])
	// vY = X_lY(E−1lY (ζı+3+lX ⋅⋅⋅+lY))
	valueY = sext(jam.DecodeUint64(p.code[instructionCounter+3+lenX:instructionCounter+3+lenX+lenY]), lenY)

	p.instructionsCache[instructionCounter] = &instructionCache{reg: [3]Reg{regA, regB}, val: [2]uint64{valueX, valueY}}
	return regA, regB, valueX, valueY
}

func (p *program) decodeArgsReg3(instructionCounter uint64) (regDst, regA, regB Reg) {
	if instr := p.instructionsCache[instructionCounter]; instr != nil {
		return instr.reg[0], instr.reg[1], instr.reg[2]
	}
	// let rA = min(12, (ζı+1) mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = Reg(min(12, p.code[instructionCounter+1]%16))
	// let rB = min(12, ⌊ ζı+1 / 16 ⌋), φB ≡ φrB, φ′B ≡ φ′rB
	regB = Reg(min(12, p.code[instructionCounter+1]/16))
	// let rD = min(12, ζı+2), φD ≡ φrD, φ′D ≡ φ′rD
	regDst = Reg(min(12, p.code[instructionCounter+2]))

	p.instructionsCache[instructionCounter] = &instructionCache{reg: [3]Reg{regDst, regA, regB}}
	return regDst, regA, regB
}
