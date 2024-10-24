///go:build integration

package integration_test

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
)

//go:embed vectors/pvm
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
	rootPath := "vectors/pvm"
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
			if err := polkavm.ParseCodeAndJumpTable(uint32(len(tc.Program)), polkavm.NewReader(bytes.NewReader(tc.Program)), pp); err != nil {
				t.Fatal(err)
			}

			mm := getMemoryMap(tc.InitialPageMap)
			mem := interpreter.NewMemory(mm, nil, nil, nil)

			i := interpreter.Instantiate(mem, tc.InitialPc, tc.InitialGas)
			// instantiate memory
			for _, mem := range tc.InitialMemory {
				err := i.SetMemory(mm, mem.Address, mem.Contents)
				if err != nil {
					t.Fatal(err)
				}
			}

			for reg, val := range tc.InitialRegs {
				i.SetReg(polkavm.Reg(reg), val)
			}
			err = interpreter.NewMutator(i, pp, mm).Execute()
			assert.Equal(t, int(tc.ExpectedPc), int(i.GetInstructionOffset()))
			assert.Equal(t, tc.ExpectedRegs, getRegs(i))
			assert.Equal(t, tc.ExpectedStatus, error2status(err))
			for _, mem := range tc.ExpectedMemory {
				data, err := i.GetMemory(mm, mem.Address, len(mem.Contents))
				if err != nil {
					t.Fatal(err)
				}
				assert.Equal(t, mem.Contents, data)
			}
			assert.Equal(t, tc.ExpectedGas, i.GasRemaining())
		})
	}
}

func getRegs(instance polkavm.Instance) (regs [13]uint32) {
	for i := 0; i < 13; i++ {
		regs[i] = instance.GetReg(polkavm.Reg(i))
	}
	return regs
}

func getMemoryMap(pageMap []Page) *polkavm.MemoryMap {
	mm := &polkavm.MemoryMap{PageSize: polkavm.VmMinPageSize, ArgsDataAddress: 1<<32 - 1}
	for _, page := range pageMap {
		if !page.IsWritable {
			mm.RODataAddress = page.Address
			mm.RODataSize = page.Length
		} else if page.IsWritable && mm.StackAddressLow == 0 {
			mm.StackAddressLow = page.Address
			mm.StackSize = page.Length
		} else {
			mm.RWDataAddress = page.Address
			mm.RWDataSize = page.Length
		}
	}
	return mm
}

func error2status(err error) string {
	if err == nil {
		return "halt"
	}
	switch err.(type) {
	case *interpreter.TrapError:
		return "trap"
	default:
		return fmt.Sprintf("unknown: %s", err)
	}
}
