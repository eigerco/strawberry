package polkavm

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/bits"
)

// BlobMagic The magic bytes with which every program blob must start with.
var BlobMagic = [4]byte{byte('P'), byte('V'), byte('M'), 0}

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

	VmMaximumImportCount uint32 = 1024 // The maximum number of functions the program can import.
)

type ProgramParts struct {
	RODataSize             uint32
	RWDataSize             uint32
	StackSize              uint32
	ROData                 []byte
	RWData                 []byte
	CodeAndJumpTable       []byte
	ImportOffsets          []byte
	ImportSymbols          []byte
	Exports                []byte
	DebugStrings           []byte
	DebugLineProgramRanges []byte
	DebugLinePrograms      []byte
}

type Reader interface {
	io.Reader
	io.Seeker
}

func ParseBlob(reader Reader) (pp *ProgramParts, err error) {
	magic := make([]byte, len(BlobMagic))
	_, err = reader.Read(magic)
	if err != nil {
		return nil, err
	}
	if [len(BlobMagic)]byte(magic) != BlobMagic {
		return pp, fmt.Errorf("blob doesn't start with the expected magic bytes")
	}
	var blobVersion = new(byte)
	err = readByte(reader, blobVersion)
	if err != nil {
		return nil, err
	}
	if *blobVersion != BlobVersionV1 {
		return pp, fmt.Errorf("unsupported version: %d", blobVersion)
	}

	pp = &ProgramParts{}
	section := new(byte)
	err = readByte(reader, section)
	if err != nil {
		return nil, err
	}
	if *section == SectionMemoryConfig {
		secLen, err := readVariant(reader)
		if err != nil {
			return nil, err
		}
		pos, err := reader.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, err
		}

		pp.RODataSize, err = readVariant(reader)
		if err != nil {
			return nil, err
		}
		pp.RWDataSize, err = readVariant(reader)
		if err != nil {
			return nil, err
		}
		pp.StackSize, err = readVariant(reader)
		if err != nil {
			return nil, err
		}
		pos2, err := reader.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, err
		}
		if pos+int64(secLen) != pos2 {
			return pp, fmt.Errorf("the memory config section contains more data than expected %v %v", pos+int64(secLen), pos2)
		}
		err = readByte(reader, section)
		if err != nil {
			return nil, err
		}
	}
	if pp.ROData, err = readSectionAsBytes(reader, section, SectionROData); err != nil {
		return nil, err
	}
	if pp.RWData, err = readSectionAsBytes(reader, section, SectionRWData); err != nil {
		return nil, err
	}
	if *section == SectionImports {
		secLen, err := readVariant(reader)
		if err != nil {
			return nil, err
		}
		posStart, err := reader.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, err
		}
		importCount, err := readVariant(reader)
		if err != nil {
			return nil, err
		}
		if importCount > VmMaximumImportCount {
			return pp, fmt.Errorf("too many imports")
		}
		//TODO check for underflow and overflow?
		importOffsetsSize := importCount * 4
		pp.ImportOffsets = make([]byte, importOffsetsSize)
		_, err = reader.Read(pp.ImportOffsets)
		if err != nil {
			return nil, err
		}

		pos, err := reader.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, err
		}
		//TODO check for underflow?
		importSymbolsSize := secLen - uint32(pos-posStart)
		pp.ImportSymbols = make([]byte, importSymbolsSize)
		_, err = reader.Read(pp.ImportSymbols)
		if err != nil {
			return nil, err
		}
		err = readByte(reader, section)
		if err != nil {
			return nil, err
		}
	}

	if pp.Exports, err = readSectionAsBytes(reader, section, SectionExports); err != nil {
		return nil, err
	}
	if pp.CodeAndJumpTable, err = readSectionAsBytes(reader, section, SectionCodeAndJumpTable); err != nil {
		return nil, err
	}
	if pp.DebugStrings, err = readSectionAsBytes(reader, section, SectionOptDebugStrings); err != nil {
		return nil, err
	}
	if pp.DebugLinePrograms, err = readSectionAsBytes(reader, section, SectionOptDebugLinePrograms); err != nil {
		return nil, err
	}
	if pp.DebugLineProgramRanges, err = readSectionAsBytes(reader, section, SectionOptDebugLineProgramRanges); err != nil {
		return nil, err
	}

	for (*section & 0b10000000) != 0 {
		// We don't know this section, but it's optional, so just skip it.
		log.Printf("Skipping unsupported optional section: %v", section)
		sectionLength, err := readVariant(reader)
		if err != nil {
			return nil, err
		}
		discardBytes := make([]byte, sectionLength)
		_, err = reader.Read(discardBytes)
		if err != nil {
			return nil, err
		}
		err = readByte(reader, section)
		if err != nil {
			return nil, err
		}
	}
	if *section != SectionEndOfFile {
		return nil, fmt.Errorf("unexpected section: %v", *section)
	}
	return pp, nil
}

func readSectionAsBytes(reader Reader, outSection *byte, expected byte) ([]byte, error) {
	if *outSection != expected {
		return nil, nil
	}

	secLen, err := readVariant(reader)
	if err != nil {
		return nil, err
	}
	bb := make([]byte, secLen)
	_, err = reader.Read(bb)
	if err != nil {
		return nil, err
	}
	err = readByte(reader, outSection)
	if err != nil {
		return nil, err
	}
	return bb, nil
}

func readByte(reader Reader, section *byte) error {
	b := make([]byte, 1)
	_, err := reader.Read(b)
	if err != nil {
		return err
	}
	*section = b[0]
	return nil
}

func readVariant(reader Reader) (uint32, error) {
	firstByte := new(byte)
	err := readByte(reader, firstByte)
	if err != nil {
		return 0, err
	}
	length := bits.LeadingZeros8(^*firstByte)
	var upperMask uint32 = 0b11111111 >> length
	var upperBits = upperMask & uint32(*firstByte) << (length * 8)
	if length == 0 {
		return upperBits, nil
	}
	value := make([]byte, length)
	n, err := reader.Read(value)
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
