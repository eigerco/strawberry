package polkavm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/bits"
)

// BlobMagic The magic bytes with which every program blob must start with.
var BlobMagic = [4]byte{'P', 'V', 'M', 0}

// program blob sections
const (
	SectionMemoryConfig              byte = 1
	SectionROData                    byte = 2
	SectionRWData                    byte = 3
	SectionImports                   byte = 4
	SectionExports                   byte = 5
	SectionCodeAndJumpTable          byte = 6
	SectionOptDebugStrings           byte = 128
	SectionOptDebugLinePrograms      byte = 129
	SectionOptDebugLineProgramRanges byte = 130
	SectionEndOfFile                 byte = 0

	BlobLenSize           = 8 // for 64 bit blobs
	BlobVersionV1x32 byte = 0
	BlobVersionV1x64 byte = 1

	VersionDebugLineProgramV1 byte = 1

	VmMaximumJumpTableEntries uint32 = 16 * 1024 * 1024
	VmMaximumImportCount      uint32 = 1024 // The maximum number of functions the program can import.
	VmMaximumCodeSize         uint32 = 32 * 1024 * 1024
	VmCodeAddressAlignment    uint32 = 2
	BitmaskMax                       = 24
)

type Program struct {
	Is64Bit                bool
	RODataSize             uint32
	RWDataSize             uint32
	StackSize              uint32
	ROData                 []byte
	RWData                 []byte
	JumpTable              []uint32
	Instructions           []Instruction
	Imports                []string
	Exports                []ProgramExport
	DebugStrings           []byte
	DebugLineProgramRanges []byte
	DebugLinePrograms      []byte
}

func (p *Program) JumpTableGetByAddress(address uint32) *uint32 {
	if address&(VmCodeAddressAlignment-1) != 0 || address == 0 {
		return nil
	}

	instructionOffset := p.JumpTable[((address - VmCodeAddressAlignment) / VmCodeAddressAlignment)]
	return &instructionOffset
}

type ProgramExport struct {
	TargetCodeOffset uint32
	Symbol           string
}

func ParseBlob(r *Reader) (pp *Program, err error) {
	magic := make([]byte, len(BlobMagic))
	if _, err = r.Read(magic); err != nil {
		return nil, err
	}
	if !bytes.Equal(magic, BlobMagic[:]) {
		return pp, fmt.Errorf("blob doesn't start with the expected magic bytes")
	}
	blobVersion, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if blobVersion != BlobVersionV1x32 && blobVersion != BlobVersionV1x64 {
		return pp, fmt.Errorf("unsupported version: %d", blobVersion)
	}

	blobLenBytes := make([]byte, 8)
	_, err = r.Read(blobLenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read blob length: %w", err)
	}
	blobLen := binary.LittleEndian.Uint64(blobLenBytes)

	if blobLen != uint64(r.Len()) {
		return pp, fmt.Errorf("blob size doesn't match the blob length metadata")
	}
	pp = &Program{Is64Bit: blobVersion == BlobVersionV1x64}
	section, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if section == SectionMemoryConfig {
		if section, err = parseMemoryConfig(r, pp); err != nil {
			return nil, err
		}
	}
	if section == SectionROData {
		if pp.ROData, err = r.ReadWithLength(); err != nil {
			return nil, err
		}
		if section, err = r.ReadByte(); err != nil {
			return nil, err
		}
	}
	if section == SectionRWData {
		if pp.RWData, err = r.ReadWithLength(); err != nil {
			return nil, err
		}
		if section, err = r.ReadByte(); err != nil {
			return nil, err
		}
	}
	if section == SectionImports {
		if section, err = parseImports(r, pp); err != nil {
			return nil, err
		}
	}

	if section == SectionExports {
		if section, err = parseExports(r, pp); err != nil {
			return nil, err
		}
	}
	if section == SectionCodeAndJumpTable {
		secLen, err := r.ReadVarint()
		if err != nil {
			return nil, err
		}
		if err = ParseCodeAndJumpTable(secLen, r, pp); err != nil {
			return nil, err
		}
		if section, err = r.ReadByte(); err != nil {
			return nil, err
		}
	}
	if section == SectionOptDebugStrings {
		if pp.DebugStrings, err = r.ReadWithLength(); err != nil {
			return nil, err
		}
		if section, err = r.ReadByte(); err != nil {
			return nil, err
		}
	}
	if section == SectionOptDebugLinePrograms {
		if pp.DebugLinePrograms, err = r.ReadWithLength(); err != nil {
			return nil, err
		}
		if section, err = r.ReadByte(); err != nil {
			return nil, err
		}
	}
	if section == SectionOptDebugLineProgramRanges {
		if pp.DebugLineProgramRanges, err = r.ReadWithLength(); err != nil {
			return nil, err
		}
		if section, err = r.ReadByte(); err != nil {
			return nil, err
		}
	}

	for (section & 0b10000000) != 0 {
		// We don't know this section, but it's optional, so just skip it.
		log.Printf("Skipping unsupported optional section: %v", section)
		sectionLength, err := r.ReadVarint()
		if err != nil {
			return nil, err
		}
		discardBytes := make([]byte, sectionLength)
		_, err = r.Read(discardBytes)
		if err != nil {
			return nil, err
		}
		section, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}
	if section != SectionEndOfFile {
		return nil, fmt.Errorf("unexpected section: %v", section)
	}
	return pp, nil
}

func parseMemoryConfig(r *Reader, p *Program) (byte, error) {
	secLen, err := r.ReadVarint()
	if err != nil {
		return 0, err
	}
	pos := r.Position()

	if p.RODataSize, err = r.ReadVarint(); err != nil {
		return 0, err
	}
	if p.RWDataSize, err = r.ReadVarint(); err != nil {
		return 0, err
	}
	if p.StackSize, err = r.ReadVarint(); err != nil {
		return 0, err
	}
	if pos+int64(secLen) != r.Position() {
		return 0, fmt.Errorf("the memory config section contains more data than expected %v %v", pos+int64(secLen), r.Position())
	}

	return r.ReadByte()
}

func parseImports(r *Reader, p *Program) (byte, error) {
	secLen, err := r.ReadVarint()
	if err != nil {
		return 0, err
	}
	posStart := r.Position()
	importCount, err := r.ReadVarint()
	if err != nil {
		return 0, err
	}
	if importCount > VmMaximumImportCount {
		return 0, fmt.Errorf("too many imports")
	}
	//TODO check for underflow and overflow?
	importOffsetsSize := importCount * 4
	importOffsets := make([]byte, importOffsetsSize)
	_, err = r.Read(importOffsets)
	if err != nil {
		return 0, err
	}

	//TODO check for underflow?
	importSymbolsSize := secLen - uint32(r.Position()-posStart)
	importSymbols := make([]byte, importSymbolsSize)
	_, err = r.Read(importSymbols)
	if err != nil {
		return 0, err
	}

	if len(importOffsets)%4 != 0 {
		return 0, fmt.Errorf("invalid import offsets data: %d", len(importOffsets))
	}
	var offsets []uint32
	for i := 0; i < len(importOffsets); i += 4 {
		offsets = append(offsets, binary.BigEndian.Uint32(importOffsets[i:i+4]))
	}
	for i := 0; i < len(offsets); i += 2 {
		if i+1 == len(offsets) {
			p.Imports = append(p.Imports, string(importSymbols[offsets[i]:]))
			continue
		}
		p.Imports = append(p.Imports, string(importSymbols[offsets[i]:offsets[i+1]]))
	}

	return r.ReadByte()
}

func ParseCodeAndJumpTable(secLen uint32, r *Reader, p *Program) error {
	initialPosition := r.Position()
	jumpTableEntryCount, err := r.ReadVarint()
	if err != nil {
		return err
	}
	if jumpTableEntryCount > VmMaximumJumpTableEntries {
		return fmt.Errorf("the jump table section is too long")
	}
	jumpTableEntrySize, err := r.ReadByte()
	if err != nil {
		return err
	}
	codeLength, err := r.ReadVarint()
	if err != nil {
		return err
	}
	if codeLength > VmMaximumCodeSize {
		return fmt.Errorf("the code section is too long")
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
			p.JumpTable = append(p.JumpTable, uint32(jumpTable[i]))
		case 2:
			p.JumpTable = append(p.JumpTable, uint32(binary.BigEndian.Uint16(jumpTable[i:i+2])))
		case 3:
			p.JumpTable = append(p.JumpTable, binary.BigEndian.Uint32(
				[]byte{jumpTable[i], jumpTable[i+1], jumpTable[i+2], 0},
			))
		case 4:
			p.JumpTable = append(p.JumpTable, binary.BigEndian.Uint32(jumpTable[i:i+int(jumpTableEntrySize)]))
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
		p.Instructions = append(p.Instructions, instr)
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
	regs, imm := parseArgsTable[opcode](chunk[1:], uint32(instructionOffset), uint32(len(chunk[1:])))
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

func parseExports(r *Reader, p *Program) (byte, error) {
	var secLen uint32
	secLen, err := r.ReadVarint()
	if err != nil {
		return 0, err
	}
	initialPosition := r.Position()
	nr, err := r.ReadVarint()
	if err != nil {
		return 0, err
	}
	for i := 0; i < int(nr); i++ {
		targetCodeOffset, err := r.ReadVarint()
		if err != nil {
			return 0, err
		}
		symbol, err := r.ReadWithLength()
		if err != nil {
			return 0, err
		}

		p.Exports = append(p.Exports, ProgramExport{
			TargetCodeOffset: targetCodeOffset,
			Symbol:           string(symbol),
		})
	}

	if initialPosition+int64(secLen) != r.Position() {
		return 0, fmt.Errorf("invalid exports section Length: %v", secLen)
	}
	return r.ReadByte()
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
