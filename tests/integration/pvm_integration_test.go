//go:build integration

package integration_test

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
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
	Name           string            `json:"name"`
	InitialRegs    polkavm.Registers `json:"initial-regs"`
	InitialPc      uint32            `json:"initial-pc"`
	InitialPageMap []Page            `json:"initial-page-map"`
	InitialMemory  []MemoryChunk     `json:"initial-memory"`
	InitialGas     polkavm.Gas       `json:"initial-gas"`
	Program        []byte            `json:"program"`
	ExpectedStatus string            `json:"expected-status"`
	ExpectedRegs   polkavm.Registers `json:"expected-regs"`
	ExpectedPc     uint32            `json:"expected-pc"`
	ExpectedMemory []MemoryChunk     `json:"expected-memory"`
	ExpectedGas    polkavm.Gas       `json:"expected-gas"`
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
			mem := mm.NewMemory(nil, nil, nil)

			for _, initialMem := range tc.InitialMemory {
				err := mem.Write(initialMem.Address, initialMem.Contents)
				if err != nil {
					t.Fatal(err)
				}
			}
			instructionCounter, gas, regs, mem, _, err := interpreter.Invoke(pp, mm, tc.InitialPc, tc.InitialGas, tc.InitialRegs, mem)
			assert.Equal(t, int(tc.ExpectedPc), int(instructionCounter))
			assert.Equal(t, tc.ExpectedRegs, regs)
			assert.Equal(t, tc.ExpectedStatus, error2status(err))
			for _, expectedMem := range tc.ExpectedMemory {
				data := make([]byte, len(expectedMem.Contents))
				err := mem.Read(expectedMem.Address, data)
				if err != nil {
					t.Fatal(err)
				}
				assert.Equal(t, expectedMem.Contents, data)
			}
			assert.Equal(t, tc.ExpectedGas, gas)
		})
	}
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
	if errors.Is(err, polkavm.ErrHalt) {
		return "halt"
	}
	if errors.Is(err, polkavm.ErrHostCall) {
		return "host_call"
	}
	switch err.(type) {
	case *polkavm.ErrPanic:
		return "trap"
	default:
		return fmt.Sprintf("unknown: %s", err)
	}
}
