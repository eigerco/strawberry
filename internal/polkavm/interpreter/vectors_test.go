package interpreter

import (
	"bytes"
	"embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/eigerco/strawberry/internal/polkavm"
)

//go:embed testvectors
var testvectors embed.FS

type TestCase struct {
	Name           string        `json:"name"`
	InitialRegs    [13]uint32    `json:"initial-regs"`
	InitialPc      uint32        `json:"initial-pc"`
	InitialPageMap []Page        `json:"initial-page-map"`
	InitialMemory  []MemoryChunk `json:"initial-memory"`
	InitialGas     int64         `json:"initial-gas"`
	Program        []byte        `json:"program"`
	ExpectedStatus string        `json:"expected-status"`
	ExpectedRegs   [13]uint32    `json:"expected-regs"`
	ExpectedPc     uint32        `json:"expected-pc"`
	ExpectedMemory []MemoryChunk `json:"expected-memory"`
	ExpectedGas    int64         `json:"expected-gas"`
}

type Page struct {
	Address    uint32 `json:"address"`
	Length     uint32 `json:"length"`
	IsWritable bool   `json:"is-writable"`
}

type MemoryChunk struct {
	Address  uint32 `json:"address"`
	Contents []byte `json:"contents"`
}

func Test_Vectors(t *testing.T) {
	rootPath := "testvectors"
	ff, err := testvectors.ReadDir(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range ff {
		t.Run(file.Name(), func(t *testing.T) {
			f, err := testvectors.Open(filepath.Join(rootPath, file.Name()))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			tc := &TestCase{}
			if err := json.NewDecoder(f).Decode(tc); err != nil {
				t.Fatal(file.Name(), err)
			}

			pp := &polkavm.Program{}
			r := polkavm.NewReader(bytes.NewReader(tc.Program))
			if err := parseCodeAndJumpTable(r, pp); err != nil {
				t.Fatal(err)
			}
			log.Printf(":: %s %+v %+v", tc.Name, pp.Instructions, pp.JumpTable)

			m, err := NewModule(pp)
			if err != nil {
				t.Fatal(err)
			}
			mm := getMemoryMap(tc.InitialPageMap)
			i := &instance{
				memory:              newBasicMemory(*mm, pp.RWData),
				regs:                reg2map(tc.InitialRegs),
				instructionOffset:   tc.InitialPc,
				instructionCounter:  m.instructionOffsetToIndex[tc.InitialPc],
				offsetForBasicBlock: make(map[uint32]int),
				gasRemaining:        tc.InitialGas,
			}
			for _, mem := range tc.InitialMemory {
				slice, err := i.memory.getMemorySlicePointer(*mm, mem.Address, len(mem.Contents))
				if err != nil {
					t.Fatal(err)
				}
				copy(*slice, mem.Contents)
			}
			mutator := newMutator(i, m, *mm)
			err = mutator.execute()
			assert.Equal(t, tc.ExpectedPc, i.instructionOffset)
			assert.Equal(t, tc.ExpectedRegs, map2reg(i.regs))
			assert.Equal(t, tc.ExpectedStatus, error2status(err))
			for _, mem := range tc.ExpectedMemory {
				data, err := i.memory.getMemorySlice(pp.ROData, *mm, mem.Address, len(mem.Contents))
				if err != nil {
					t.Fatal(err)
				}
				assert.Equal(t, mem.Contents, data)
			}
			//assert.Equal(t, tc.ExpectedGas, i.gasRemaining)
		})
	}
}

func map2reg(regMap map[polkavm.Reg]uint32) (regs [13]uint32) {
	for reg, val := range regMap {
		regs[reg] = val
	}
	return regs
}

func reg2map(regs [13]uint32) map[polkavm.Reg]uint32 {
	rm := make(map[polkavm.Reg]uint32)
	for reg, val := range regs {
		rm[polkavm.Reg(reg)] = val
	}
	return rm
}

func parseCodeAndJumpTable(r *polkavm.Reader, p *polkavm.Program) error {
	jumpTableEntryCount, err := r.ReadVarint()
	if err != nil {
		return err
	}
	if jumpTableEntryCount > polkavm.VmMaximumJumpTableEntries {
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
	if codeLength > polkavm.VmMaximumCodeSize {
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

	bitmask, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	offset := 0
	for offset < len(code) {
		nextOffset, instr, err := polkavm.ParseInstruction(code, bitmask, offset)
		if err != nil {
			return err
		}
		p.Instructions = append(p.Instructions, instr)
		offset = nextOffset
	}
	return nil
}

func getMemoryMap(pageMap []Page) *memoryMap {
	mm := &memoryMap{pageSize: VmMinPageSize}
	for _, page := range pageMap {
		if !page.IsWritable {
			mm.roDataAddress = page.Address
			mm.roDataSize = page.Length
		} else if page.IsWritable && mm.stackAddressLow == 0 {
			mm.stackAddressLow = page.Address
			mm.stackSize = page.Length

		} else {
			mm.rwDataAddress = page.Address
			mm.rwDataSize = page.Length
		}
	}
	return mm
}

func error2status(err error) string {
	if err == nil {
		return "halt"
	}
	switch err.(type) {
	case *TrapError:
		return "trap"
	case *ExecutionError:
		return "exec"
	default:
		return fmt.Sprintf("unknown: %s", err)
	}
}
