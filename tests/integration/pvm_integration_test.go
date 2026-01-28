//go:build integration

package integration

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"github.com/eigerco/strawberry/internal/pvm"
)

//go:embed vectors/pvm
var testvectors embed.FS

type TestCase struct {
	Name string `json:"name"`
	//InitialRegs pvm.Registers `json:"initial-regs"`
	InitialPc  uint64   `json:"initial-pc"`
	InitialGas pvm.UGas `json:"initial-gas"`
	Program    []byte   `json:"program"`

	Steps []Step `json:"steps"`

	BlockGasCosts []blockGasCosts `json:"block-gas-costs"`
}

type Step struct {
	Run any `json:"run"`

	SetReg *SetReg `json:"set-reg"`

	Assert *Assert `json:"assert"`

	Map *Page `json:"map"`

	Write *MemoryChunk `json:"write"`
}

type Assert struct {
	Status           string        `json:"status"`
	Hostcall         uint64        `json:"hostcall"`
	PageFaultAddress int           `json:"page-fault-address"`
	Gas              pvm.Gas       `json:"gas"`
	Pc               uint64        `json:"pc"`
	Regs             pvm.Registers `json:"regs"`
	Memory           []MemoryChunk `json:"memory"`
}

type SetReg struct {
	Reg   uint64 `json:"reg"`
	Value uint64 `json:"value"`
}

type blockGasCosts struct {
	Pc   uint64  `json:"pc"`
	Cost pvm.Gas `json:"cost"`
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

func Test_PVM_Vectors(t *testing.T) {
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

			gasCostMap := make(map[uint64]pvm.Gas)
			for _, gasCost := range tc.BlockGasCosts {
				gasCostMap[gasCost.Pc] = gasCost.Cost
			}

			i, err := pvm.Instantiate(tc.Program, tc.InitialPc, tc.InitialGas, pvm.Registers{}, pvm.Memory{})
			require.NoError(t, err)
			i.OverwriteGasCostsMap(gasCostMap)

			var (
				rwPageSet    bool
				executionErr error
				hostcall     uint64
			)

			for j, step := range tc.Steps {
				if step.Run != nil {
					if errors.Is(executionErr, pvm.ErrHostCall) {
						// skip the host call to resume execution
						i.OverwriteSkip()
					}
					hostcall, executionErr = pvm.InvokeBasic(i)
				}
				if step.Map != nil {
					if !step.Map.IsWritable {
						i.OverwriteMemoryMapRO(step.Map.Address, step.Map.Length)
					} else if step.Map.IsWritable && rwPageSet {
						i.OverwriteMemoryMapStack(step.Map.Address, step.Map.Length)
					} else {
						i.OverwriteMemoryMapRW(step.Map.Address, step.Map.Length)
						rwPageSet = true
					}
				}
				if step.SetReg != nil {
					i.OverwriteRegister(step.SetReg.Reg, step.SetReg.Value)
				}
				if step.Write != nil {
					err = i.OverwriteMemory(step.Write.Address, step.Write.Contents)
					assert.NoError(t, err)
				}
				if step.Assert != nil {
					assert.Equal(t, step.Assert.Status, error2status(executionErr))
					instructionCounter, gas, regs, mem := i.Results()

					var errPageFault *pvm.ErrPageFault
					if errors.As(err, &errPageFault) {
						assert.Equal(t, step.Assert.PageFaultAddress, uint64(errPageFault.Address))
					}

					assert.Equal(t, int(step.Assert.Hostcall), int(hostcall), "step %d", j)

					assert.Equal(t, step.Assert.Gas, gas)

					assert.Equal(t, int(step.Assert.Pc), int(instructionCounter), "step %d", j)
					assert.Equal(t, step.Assert.Regs, regs, "step %d", j)
					for _, expectedMem := range step.Assert.Memory {
						data := make([]byte, len(expectedMem.Contents))
						err := mem.Read(expectedMem.Address, data)
						if assert.NoError(t, err, "step %d", j) {
							assert.Equal(t, expectedMem.Contents, data, "step %d", j)
						}
					}
				}
			}
		})
	}
}

func error2status(err error) string {
	if err == nil {
		return "halt"
	}
	if errors.Is(err, pvm.ErrHalt) {
		return "halt"
	}
	if errors.Is(err, pvm.ErrHostCall) {
		return "ecalli"
	}
	if errors.Is(err, pvm.ErrOutOfGas) {
		return "out-of-gas"
	}
	var errPanic *pvm.ErrPanic
	var errPageFault *pvm.ErrPageFault
	switch {
	case errors.As(err, &errPanic):
		return "panic"
	case errors.As(err, &errPageFault):
		return "page-fault"
	default:
		return fmt.Sprintf("unknown: %s", err)
	}
}
