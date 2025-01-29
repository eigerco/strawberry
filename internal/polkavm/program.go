package polkavm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/bits"

	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const BitmaskMax = 24

type ProgramMemorySizes struct {
	RODataSize       uint32 `jam:"length=3"`
	RWDataSize       uint32 `jam:"length=3"`
	InitialHeapPages uint16 `jam:"length=2"`
	StackSize        uint32 `jam:"length=3"`
}
type CodeAndJumpTable struct {
	JumpTable    []uint32
	Instructions []Instruction
}

type Program struct {
	ProgramMemorySizes ProgramMemorySizes
	ROData             []byte
	RWData             []byte
	CodeAndJumpTable   CodeAndJumpTable
}

func (p *Program) JumpTableGetByAddress(address uint32) *uint32 {
	if address&(DynamicAddressAlignment-1) != 0 || address == 0 {
		return nil
	}

	instructionOffset := p.CodeAndJumpTable.JumpTable[((address - DynamicAddressAlignment) / DynamicAddressAlignment)]
	return &instructionOffset
}

// ParseBlob let E3(|o|) ⌢ E3(|w|) ⌢ E2(z) ⌢ E3(s) ⌢ o ⌢ w ⌢ E4(|c|) ⌢ c = p (eq. A.32)
func ParseBlob(data []byte) (*Program, error) {
	memorySizes := ProgramMemorySizes{}
	if err := jam.Unmarshal(data[:11], &memorySizes); err != nil {
		return nil, err
	}
	program := &Program{ProgramMemorySizes: memorySizes}
	if err := jam.Unmarshal(data[11:memorySizes.RODataSize], program.ROData); err != nil {
		return nil, err
	}
	if int(memorySizes.RODataSize) != len(program.ROData) {
		return nil, fmt.Errorf("ro data size mismatch")
	}
	if int(memorySizes.RWDataSize) != len(program.RWData) {
		return nil, fmt.Errorf("rw data size mismatch")
	}
	if err := jam.Unmarshal(data[memorySizes.RODataSize:memorySizes.RWDataSize], program.RWData); err != nil {
		return nil, err
	}
	var codeSize uint32
	if err := jam.Unmarshal(data[memorySizes.RWDataSize:memorySizes.RWDataSize+4], &codeSize); err != nil {
		return nil, err
	}
	if len(data[memorySizes.RWDataSize+4:]) != int(codeSize) {
		return nil, fmt.Errorf("code size mismatch")
	}

	if err := ParseCodeAndJumpTable(
		codeSize,
		NewReader(bytes.NewReader(data[memorySizes.RWDataSize+4:])),
		&program.CodeAndJumpTable); err != nil {
		return nil, err
	}
	return program, nil
}

// ParseCodeAndJumpTable p = E(|j|) ⌢ E1(z) ⌢ E(|c|) ⌢ E_z(j) ⌢ E(c) ⌢ E(k), |k| = |c| (part of eq. A.1)
func ParseCodeAndJumpTable(secLen uint32, r *Reader, codeAndJumpTable *CodeAndJumpTable) error {
	initialPosition := r.Position()
	jumpTableEntryCount, err := r.ReadVarint()
	if err != nil {
		return err
	}
	jumpTableEntrySize, err := r.ReadByte()
	if err != nil {
		return err
	}
	codeLength, err := r.ReadVarint()
	if err != nil {
		return err
	}
	if jumpTableEntrySize > 4 {
		return fmt.Errorf("invalid jump table entry size")
	}

	//TODO check for underflow and overflow?
	jumpTableLength := jumpTableEntryCount * uint32(jumpTableEntrySize)

	jumpTable := make([]byte, jumpTableLength)
	if _, err = r.Read(jumpTable); err != nil {
		return err
	}
	for i := 0; i < len(jumpTable); i += int(jumpTableEntrySize) {
		switch jumpTableEntrySize {
		case 1:
			codeAndJumpTable.JumpTable = append(codeAndJumpTable.JumpTable, uint32(jumpTable[i]))
		case 2:
			codeAndJumpTable.JumpTable = append(codeAndJumpTable.JumpTable, uint32(binary.BigEndian.Uint16(jumpTable[i:i+2])))
		case 3:
			codeAndJumpTable.JumpTable = append(codeAndJumpTable.JumpTable, binary.BigEndian.Uint32(
				[]byte{jumpTable[i], jumpTable[i+1], jumpTable[i+2], 0},
			))
		case 4:
			codeAndJumpTable.JumpTable = append(codeAndJumpTable.JumpTable, binary.BigEndian.Uint32(jumpTable[i:i+int(jumpTableEntrySize)]))
		default:
			panic("unreachable")
		}
	}

	code := make([]byte, codeLength)
	if _, err = r.Read(code); err != nil {
		return err
	}

	bitmaskLength := secLen - uint32(r.Position()-initialPosition)
	bitmask := make([]byte, bitmaskLength)
	if _, err = r.Read(bitmask); err != nil {
		return err
	}
	expectedBitmaskLength := codeLength / 8
	if codeLength%8 != 0 {
		expectedBitmaskLength += 1
	}

	if bitmaskLength != expectedBitmaskLength {
		return fmt.Errorf("the bitmask Length doesn't match the code Length")
	}

	offset := 0
	for offset < len(code) {
		nextOffset, instr, err := parseInstruction(code, bitmask, offset)
		if err != nil {
			return err
		}
		codeAndJumpTable.Instructions = append(codeAndJumpTable.Instructions, instr)
		offset = nextOffset
	}
	return nil
}

func parseInstruction(code, bitmask []byte, instructionOffset int) (int, Instruction, error) {
	if len(bitmask) == 0 {
		return 0, Instruction{}, io.EOF
	}

	nextOffset, skip := parseBitmask(bitmask, instructionOffset)
	chunkLength := min(16, skip+1)
	chunk := code[instructionOffset:min(instructionOffset+chunkLength, len(code))]
	opcode := Opcode(chunk[0])

	// for simplicity because there is only one code for extended immediate we do not include it in the parseArgsTable
	if opcode == LoadImm64 {
		reg1 := min(12, code[0]&0b1111)
		imm := uint64(0)
		if err := jam.Unmarshal(code[1:9], &imm); err != nil {
			return 0, Instruction{}, err
		}
		return nextOffset, Instruction{
			Opcode: opcode,
			Reg:    []Reg{Reg(reg1)},
			ExtImm: imm,
			Offset: uint32(instructionOffset),
			Length: uint32(len(chunk[1:]) + 1),
		}, nil
	}

	log.Println("opcode", opcode)
	regs, imm, err := parseArgsTable[opcode](chunk[1:], uint32(instructionOffset), uint32(len(chunk[1:])))
	if err != nil {
		return 0, Instruction{}, err
	}
	log.Println("opcode, regs, imm", opcode, regs, imm)
	return nextOffset, Instruction{
		Opcode: opcode,
		Reg:    regs,
		Imm:    imm,
		Offset: uint32(instructionOffset),
		Length: uint32(len(chunk[1:]) + 1),
	}, nil
}

func parseBitmask(bitmask []byte, offset int) (int, int) {
	offset += 1
	argsLength := 0
	for offset>>3 < len(bitmask) {
		b := bitmask[offset>>3]
		shift := offset & 7
		mask := b >> shift
		length := 0
		if mask == 0 {
			length = 8 - shift
		} else {
			length = bits.TrailingZeros(uint(mask))
			if length == 0 {
				break
			}
		}

		newArgsLength := argsLength + length
		if newArgsLength >= BitmaskMax {
			offset += BitmaskMax - argsLength
			argsLength = BitmaskMax
			break
		}

		argsLength = newArgsLength
		offset += length
	}

	return offset, argsLength
}

func NewReader(r io.ReadSeeker) *Reader { return &Reader{r} }

type Reader struct{ io.ReadSeeker }

func (r *Reader) ReadWithLength() ([]byte, error) {
	length, err := r.ReadVarint()
	if err != nil {
		return nil, err
	}
	bytes := make([]byte, length)
	if _, err = r.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

func (r *Reader) ReadByte() (byte, error) {
	b := make([]byte, 1)
	_, err := r.Read(b)
	return b[0], err
}

func (r *Reader) ReadVarint() (uint32, error) {
	firstByte, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	length := bits.LeadingZeros8(^firstByte)
	var upperMask uint32 = 0b11111111 >> length
	var upperBits = upperMask & uint32(firstByte) << (length * 8)
	if length == 0 {
		return upperBits, nil
	}
	value := make([]byte, length)
	n, err := r.Read(value)
	if err != nil {
		return 0, err
	}
	switch n {
	case 1:
		return upperBits | uint32(value[0]), nil
	case 2:
		return upperBits | uint32(binary.BigEndian.Uint16(value)), nil
	case 3:
		return upperBits | binary.BigEndian.Uint32([]byte{value[0], value[1], value[2], 0}), nil
	case 4:
		return upperBits | binary.BigEndian.Uint32(value), nil
	default:
		return 0, fmt.Errorf("invalid varint Length: %d", n)
	}
}

func (r *Reader) Position() int64 {
	pos, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		panic(fmt.Sprintf("the current position should always be seekable: %v", err))
	}

	return pos
}

func (r *Reader) Len() int64 {
	pos := r.Position()
	ln, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		panic(fmt.Errorf("failed to get blob length: %w", err))
	}
	if _, err = r.Seek(pos, io.SeekStart); err != nil {
		panic(fmt.Errorf("failed to seek blob position: %w", err))
	}
	return ln
}
