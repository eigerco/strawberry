//go:build integration

package integration_test

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/stretchr/testify/require"
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
	InitialPc      uint64            `json:"initial-pc"`
	InitialPageMap []Page            `json:"initial-page-map"`
	InitialMemory  []MemoryChunk     `json:"initial-memory"`
	InitialGas     polkavm.Gas       `json:"initial-gas"`
	Program        []byte            `json:"program"`
	ExpectedStatus string            `json:"expected-status"`
	ExpectedRegs   polkavm.Registers `json:"expected-regs"`
	ExpectedPc     uint64            `json:"expected-pc"`
	ExpectedMemory []MemoryChunk     `json:"expected-memory"`
	ExpectedGas    polkavm.Gas       `json:"expected-gas"`
}

type Page struct {
	Address    uint64 `json:"address"`
	Length     uint64 `json:"length"`
	IsWritable bool   `json:"is-writable"`
}

type MemoryChunk struct {
	Address  uint64 `json:"address"`
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
			mem := getMemoryMap(tc.InitialPageMap)

			for _, initialMem := range tc.InitialMemory {
				err := mem.Write(initialMem.Address, initialMem.Contents)
				if err != nil {
					t.Fatal(err)
				}
			}
			i, err := interpreter.Instantiate(tc.Program, tc.InitialPc, tc.InitialGas, tc.InitialRegs, mem)
			require.NoError(t, err)

			_, err = interpreter.Invoke(i)
			assert.Equal(t, tc.ExpectedStatus, error2status(err))
			instructionCounter, gas, regs, mem := i.Results()

			assert.Equal(t, int(tc.ExpectedPc), int(instructionCounter))
			for i := range regs {
				assert.Equalf(t, uint32(tc.ExpectedRegs[i]), uint32(regs[i]), "reg: %v", polkavm.Reg(i))
			}
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

func getMemoryMap(pageMap []Page) polkavm.Memory {
	var roAddr, rwAddr, stackAddr, roSize, rwSize, stackSize uint64
	for _, page := range pageMap {
		if !page.IsWritable {
			roAddr = page.Address
			roSize = page.Length
		} else if page.IsWritable && stackAddr == 0 {
			stackAddr = page.Address
			stackSize = page.Length
		} else {
			rwAddr = page.Address
			rwSize = page.Length
		}
	}
	return polkavm.InitializeCustomMemory(roAddr, rwAddr, stackAddr, 1<<32-1, roSize, rwSize, stackSize, 0)
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
