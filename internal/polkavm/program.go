package polkavm

import (
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

	BlobVersionV1             byte = 1
	VersionDebugLineProgramV1 byte = 1

	VmMaximumJumpTableEntries uint32 = 16 * 1024 * 1024
	VmMaximumImportCount      uint32 = 1024 // The maximum number of functions the program can import.
	VmMaximumCodeSize         uint32 = 32 * 1024 * 1024
)

type ProgramParts struct {
	RODataSize             uint32
	RWDataSize             uint32
	StackSize              uint32
	ROData                 []byte
	RWData                 []byte
	JumpTableEntrySize     byte
	JumpTable              []byte
	Code                   []byte
	Bitmask                []byte
	ImportOffsets          []byte
	ImportSymbols          []byte
	Exports                []byte
	DebugStrings           []byte
	DebugLineProgramRanges []byte
	DebugLinePrograms      []byte
}

func ParseBlob(r *Reader) (pp *ProgramParts, err error) {
	magic := make([]byte, len(BlobMagic))
	_, err = r.Read(magic)
	if err != nil {
		return nil, err
	}
	if [len(BlobMagic)]byte(magic) != BlobMagic {
		return pp, fmt.Errorf("blob doesn't start with the expected magic bytes")
	}
	blobVersion, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if blobVersion != BlobVersionV1 {
		return pp, fmt.Errorf("unsupported version: %d", blobVersion)
	}

	pp = &ProgramParts{}
	section, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if section == SectionMemoryConfig {
		secLen, err := r.ReadVarint()
		if err != nil {
			return nil, err
		}
		pos := r.Position()

		if pp.RODataSize, err = r.ReadVarint(); err != nil {
			return nil, err
		}
		if pp.RWDataSize, err = r.ReadVarint(); err != nil {
			return nil, err
		}
		if pp.StackSize, err = r.ReadVarint(); err != nil {
			return nil, err
		}
		if pos+int64(secLen) != r.Position() {
			return pp, fmt.Errorf("the memory config section contains more data than expected %v %v", pos+int64(secLen), r.Position())
		}
		section, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}
	if section == SectionROData {
		if section, pp.ROData, err = r.ReadSection(); err != nil {
			return nil, err
		}
	}
	if section == SectionRWData {
		if section, pp.RWData, err = r.ReadSection(); err != nil {
			return nil, err
		}
	}
	if section == SectionImports {
		secLen, err := r.ReadVarint()
		if err != nil {
			return nil, err
		}
		posStart := r.Position()
		importCount, err := r.ReadVarint()
		if err != nil {
			return nil, err
		}
		if importCount > VmMaximumImportCount {
			return pp, fmt.Errorf("too many imports")
		}
		//TODO check for underflow and overflow?
		importOffsetsSize := importCount * 4
		pp.ImportOffsets = make([]byte, importOffsetsSize)
		_, err = r.Read(pp.ImportOffsets)
		if err != nil {
			return nil, err
		}

		//TODO check for underflow?
		importSymbolsSize := secLen - uint32(r.Position()-posStart)
		pp.ImportSymbols = make([]byte, importSymbolsSize)
		_, err = r.Read(pp.ImportSymbols)
		if err != nil {
			return nil, err
		}
		section, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if section == SectionExports {
		if section, pp.Exports, err = r.ReadSection(); err != nil {
			return nil, err
		}
	}
	if section == SectionCodeAndJumpTable {
		secLen, err := r.ReadVarint()
		if err != nil {
			return nil, err
		}
		initialPosition := r.Position()
		jumpTableEntryCount, err := r.ReadVarint()
		if err != nil {
			return nil, err
		}
		if jumpTableEntryCount > VmMaximumJumpTableEntries {
			return nil, fmt.Errorf("the jump table section is too long")
		}
		jumpTableEntrySize, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		codeLength, err := r.ReadVarint()
		if err != nil {
			return nil, err
		}
		if codeLength > VmMaximumCodeSize {
			return nil, fmt.Errorf("the code section is too long")
		}
		if jumpTableEntrySize > 4 {
			return nil, fmt.Errorf("invalid jump table entry size")
		}

		//TODO check for underflow and overflow?
		jumpTableLength := jumpTableEntryCount * uint32(jumpTableEntrySize)
		pp.JumpTableEntrySize = jumpTableEntrySize

		pp.JumpTable = make([]byte, jumpTableLength)
		if _, err = r.Read(pp.JumpTable); err != nil {
			return nil, err
		}
		pp.Code = make([]byte, codeLength)
		if _, err = r.Read(pp.Code); err != nil {
			return nil, err
		}

		bitmaskLength := secLen - uint32(r.Position()-initialPosition)
		pp.Bitmask = make([]byte, bitmaskLength)
		if _, err = r.Read(pp.Bitmask); err != nil {
			return nil, err
		}
		expectedBitmaskLength := codeLength / 8
		if codeLength%8 != 0 {
			expectedBitmaskLength += 1
		}

		if bitmaskLength != expectedBitmaskLength {
			return nil, fmt.Errorf("the bitmask length doesn't match the code length")
		}
		if section, err = r.ReadByte(); err != nil {
			return nil, err
		}
	}
	if section == SectionOptDebugStrings {
		if section, pp.DebugStrings, err = r.ReadSection(); err != nil {
			return nil, err
		}
	}
	if section == SectionOptDebugLinePrograms {
		if section, pp.DebugLinePrograms, err = r.ReadSection(); err != nil {
			return nil, err
		}
	}
	if section == SectionOptDebugLineProgramRanges {
		if section, pp.DebugLineProgramRanges, err = r.ReadSection(); err != nil {
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

func NewReader(r io.ReadSeeker) *Reader { return &Reader{r} }

type Reader struct{ io.ReadSeeker }

func (r *Reader) ReadSection() (section byte, bytes []byte, err error) {
	var secLen uint32
	secLen, err = r.ReadVarint()
	if err != nil {
		return
	}
	bytes = make([]byte, secLen)
	if _, err = r.Read(bytes); err != nil {
		return
	}
	section, err = r.ReadByte()
	return
}

func (r *Reader) ReadByte() (byte, error) {
	b := make([]byte, 1)
	_, err := r.Read(b)
	if err != nil {
		return 0, err
	}
	return b[0], nil
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
	case 3, 4:
		return upperBits | binary.BigEndian.Uint32(value), nil
	default:
		return 0, fmt.Errorf("invalid variant length: %d", n)
	}
}

func (r *Reader) Position() int64 {
	pos, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		panic(fmt.Sprintf("the current position should always be seekable: %v", err))
	}

	return pos
}
