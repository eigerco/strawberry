package interpreter

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"

	"github.com/eigerco/strawberry/internal/polkavm"
)

const (
	x8  = 1
	x16 = 2
	x32 = 4
)

const (
	signed   = true
	unsigned = false
)

var _ polkavm.Mutator = &Mutator{}

func NewMutator(i polkavm.Instance, m *Module, memoryMap *polkavm.MemoryMap) *Mutator {
	v := &Mutator{
		instance:      i,
		hostFunctions: []callFunc{},
		memoryMap:     memoryMap,
		program:       m.program,
	}
	for _, imp := range m.program.Imports {
		hostFn, ok := m.hostFunctions[imp]
		if !ok {
			log.Println("host function not defined")
			continue
		}

		v.hostFunctions = append(v.hostFunctions, func(instance polkavm.Instance) error {
			ret, err := hostFn(instance.GetReg(polkavm.A0), instance.GetReg(polkavm.A1),
				instance.GetReg(polkavm.A2), instance.GetReg(polkavm.A3),
				instance.GetReg(polkavm.A4), instance.GetReg(polkavm.A5))
			if err != nil {
				return &TrapError{fmt.Errorf("external function error: %w", err)}
			}
			instance.SetReg(polkavm.A0, ret)
			return err
		})
	}
	return v
}

type Mutator struct {
	instance      polkavm.Instance
	program       *polkavm.Program
	memoryMap     *polkavm.MemoryMap
	hostFunctions []callFunc
}

func (m *Mutator) branch(condition bool, target uint32) {
	if condition {
		m.instance.SetInstructionOffset(target)
	} else {
		m.instance.NextOffsets()
	}
	m.instance.StartBasicBlock(m.program)
}

func (m *Mutator) load(memLen int, signed bool, dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	var address uint32 = 0
	if base != 0 {
		address = m.get(base)
	}
	address += offset
	slice, err := m.instance.GetMemory(m.memoryMap, address, memLen)
	if err != nil {
		return &TrapError{Err: err}
	}
	if slice == nil {
		return &TrapError{fmt.Errorf("unable to load memory slice")}
	}
	value, err := leDecode(memLen, slice)
	if err != nil {
		return &TrapError{Err: err}
	}
	m.setNext(dst, toSigned(value, memLen, signed))
	return nil
}

func (m *Mutator) store(memLen int, signed bool, src uint32, base polkavm.Reg, offset uint32) error {
	var address uint32 = 0
	if base != 0 {
		address = m.get(base)
	}
	address += offset
	data, err := leEncode(memLen, toSigned(src, memLen, signed))
	if err != nil {
		return &TrapError{Err: err}
	}
	if err := m.instance.SetMemory(m.memoryMap, address, data); err != nil {
		return &TrapError{Err: err}
	}

	m.instance.NextOffsets()
	return nil
}
func toSigned(v uint32, memLen int, signed bool) uint32 {
	if signed {
		switch memLen {
		case x8:
			return uint32(int8(v))
		case x16:
			return uint32(int16(v))
		case x32:
			return uint32(int32(v))
		}
	}
	return v
}
func leEncode(memLen int, src uint32) ([]byte, error) {
	slice := make([]byte, memLen)
	switch memLen {
	case x8:
		slice[0] = byte(src)
	case x16:
		binary.LittleEndian.PutUint16(slice, uint16(src))
	case x32:
		binary.LittleEndian.PutUint32(slice, src)
	default:
		return nil, fmt.Errorf("invalid memory slice length: %d", memLen)
	}
	return slice, nil
}
func leDecode(memLen int, src []byte) (uint32, error) {
	switch memLen {
	case x8:
		return uint32(src[0]), nil
	case x16:
		return uint32(binary.LittleEndian.Uint16(src)), nil
	case x32:
		return binary.LittleEndian.Uint32(src), nil
	default:
		return 0, fmt.Errorf("invalid memory slice length: %d", memLen)
	}
}

func (m *Mutator) jumpIndirectImpl(target uint32) error {
	if target == polkavm.VmAddrReturnToHost {
		return io.EOF
	}
	instructionOffset := m.program.JumpTableGetByAddress(target)
	if instructionOffset == nil {
		return &TrapError{Err: fmt.Errorf("indirect jump to address %v: INVALID", target)}
	}
	m.instance.SetInstructionOffset(*instructionOffset)
	m.instance.StartBasicBlock(m.program)
	return nil
}

func (m *Mutator) get(vv polkavm.Reg) uint32 {
	return m.instance.GetReg(vv)
}

func (m *Mutator) set(dst polkavm.Reg, value uint32) {
	m.instance.SetReg(dst, value)
}

func (m *Mutator) setNext(dst polkavm.Reg, value uint32) {
	m.set(dst, value)
	m.instance.NextOffsets()
}
func (m *Mutator) Trap() error {
	return &TrapError{fmt.Errorf("explicit trap")}
}
func (m *Mutator) Fallthrough() {
	m.instance.NextOffsets()
	m.instance.StartBasicBlock(m.program)
}
func (m *Mutator) Sbrk(dst polkavm.Reg, size polkavm.Reg) {
	s := m.get(size)
	result, _ := m.instance.Sbrk(m.memoryMap, s)
	m.setNext(dst, result)
}
func (m *Mutator) MoveReg(d polkavm.Reg, s polkavm.Reg) {
	m.setNext(d, m.get(s))
}
func (m *Mutator) BranchEq(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	m.branch(m.get(s1) == m.get(s2), target)
}
func (m *Mutator) BranchEqImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(m.get(s1) == s2, target)
}
func (m *Mutator) BranchNotEq(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	m.branch(m.get(s1) != m.get(s2), target)
}
func (m *Mutator) BranchNotEqImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(m.get(s1) != s2, target)
}
func (m *Mutator) BranchLessUnsigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	m.branch(m.get(s1) < m.get(s2), target)
}
func (m *Mutator) BranchLessUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(m.get(s1) < s2, target)
}
func (m *Mutator) BranchLessSigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	m.branch(int32(m.get(s1)) < int32(m.get(s2)), target)
}
func (m *Mutator) BranchLessSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(int32(m.get(s1)) < int32(s2), target)
}
func (m *Mutator) BranchGreaterOrEqualUnsigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	m.branch(m.get(s1) >= m.get(s2), target)
}
func (m *Mutator) BranchGreaterOrEqualUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(m.get(s1) >= s2, target)
}
func (m *Mutator) BranchGreaterOrEqualSigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	m.branch(int32(m.get(s1)) >= int32(m.get(s2)), target)
}
func (m *Mutator) BranchGreaterOrEqualSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(int32(m.get(s1)) >= int32(s2), target)
}
func (m *Mutator) BranchLessOrEqualUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(m.get(s1) <= s2, target)
}
func (m *Mutator) BranchLessOrEqualSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(int32(m.get(s1)) <= int32(s2), target)
}
func (m *Mutator) BranchGreaterUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(m.get(s1) > s2, target)
}
func (m *Mutator) BranchGreaterSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(int32(m.get(s1)) > int32(s2), target)
}
func (m *Mutator) SetLessThanUnsignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, bool2uint32(m.get(s1) < s2))
}
func (m *Mutator) SetLessThanSignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, bool2uint32(int32(m.get(s1)) < int32(s2)))
}
func (m *Mutator) ShiftLogicalLeftImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, m.get(s1)<<s2)
}
func (m *Mutator) ShiftArithmeticRightImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, uint32(int32(m.get(s1))>>s2))
}
func (m *Mutator) ShiftArithmeticRightImmAlt(d polkavm.Reg, s2 polkavm.Reg, s1 uint32) {
	m.setNext(d, uint32(int32(s1)>>m.get(s2)))
}
func (m *Mutator) NegateAndAddImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, s2-m.get(s1))
}
func (m *Mutator) SetGreaterThanUnsignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, bool2uint32(m.get(s1) > s2))
}
func (m *Mutator) SetGreaterThanSignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, bool2uint32(int32(m.get(s1)) > int32(s2)))
}
func (m *Mutator) ShiftLogicalRightImmAlt(d polkavm.Reg, s2 polkavm.Reg, s1 uint32) {
	m.setNext(d, s1>>m.get(s2))
}
func (m *Mutator) ShiftLogicalLeftImmAlt(d polkavm.Reg, s2 polkavm.Reg, s1 uint32) {
	m.setNext(d, s1<<m.get(s2))
}
func (m *Mutator) Add(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, m.get(s1)+m.get(s2))
}
func (m *Mutator) AddImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, m.get(s1)+s2)
}
func (m *Mutator) Sub(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, m.get(s1)-m.get(s2))
}
func (m *Mutator) And(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, m.get(s1)&m.get(s2))
}
func (m *Mutator) AndImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, m.get(s1)&s2)
}
func (m *Mutator) Xor(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, m.get(s1)^m.get(s2))
}
func (m *Mutator) XorImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, m.get(s1)^s2)
}
func (m *Mutator) Or(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, m.get(s1)|m.get(s2))
}
func (m *Mutator) OrImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, m.get(s1)|s2)
}
func (m *Mutator) Mul(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, m.get(s1)*m.get(s2))
}
func (m *Mutator) MulImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, m.get(s1)*s2)
}
func (m *Mutator) MulUpperSignedSigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, uint32(int32((int64(m.get(s1))*int64(m.get(s2)))>>32)))
}
func (m *Mutator) MulUpperSignedSignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, uint32(int32((int64(m.get(s1))*int64(s2))>>32)))
}
func (m *Mutator) MulUpperUnsignedUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, uint32(int32((int64(m.get(s1))*int64(m.get(s2)))>>32)))
}
func (m *Mutator) MulUpperUnsignedUnsignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, uint32(int32((int64(m.get(s1))*int64(s2))>>32)))
}
func (m *Mutator) MulUpperSignedUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, uint32((int64(m.get(s1))*int64(m.get(s2)))>>32))
}
func (m *Mutator) SetLessThanUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, bool2uint32(m.get(s1) < m.get(s2)))
}
func (m *Mutator) SetLessThanSigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, bool2uint32(int32(m.get(s1)) < int32(m.get(s2))))
}
func (m *Mutator) ShiftLogicalLeft(d polkavm.Reg, s1, s2 polkavm.Reg) {
	shiftAmount := m.get(s2) % 32
	shiftedValue := m.get(s1) << shiftAmount
	m.setNext(d, shiftedValue)
}
func (m *Mutator) ShiftLogicalRight(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, m.get(s1)>>(m.get(s2)%32))
}
func (m *Mutator) ShiftLogicalRightImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext(d, m.get(s1)>>s2)
}
func (m *Mutator) ShiftArithmeticRight(d polkavm.Reg, s1, s2 polkavm.Reg) {
	shiftAmount := m.get(s2) % 32
	shiftedValue := int32(m.get(s1)) >> shiftAmount
	m.setNext(d, uint32(shiftedValue))
}
func (m *Mutator) DivUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, divUnsigned(m.get(s1), m.get(s2)))
}
func (m *Mutator) DivSigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, uint32(div(int32(m.get(s1)), int32(m.get(s2)))))
}
func (m *Mutator) RemUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, remUnsigned(m.get(s1), m.get(s2)))
}
func (m *Mutator) RemSigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext(d, uint32(rem(int32(m.get(s1)), int32(m.get(s2)))))
}
func (m *Mutator) CmovIfZero(d polkavm.Reg, s, c polkavm.Reg) {
	if m.get(c) == 0 {
		m.set(d, m.get(s))
	}
	m.instance.NextOffsets()
}
func (m *Mutator) CmovIfZeroImm(d polkavm.Reg, c polkavm.Reg, s uint32) {
	if m.get(c) == 0 {
		m.set(d, s)
	}
	m.instance.NextOffsets()
}
func (m *Mutator) CmovIfNotZero(d polkavm.Reg, s, c polkavm.Reg) {
	if m.get(c) != 0 {
		m.set(d, m.get(s))
	}
	m.instance.NextOffsets()
}
func (m *Mutator) CmovIfNotZeroImm(d polkavm.Reg, c polkavm.Reg, s uint32) {
	if m.get(c) != 0 {
		m.set(d, s)
	}

	m.instance.NextOffsets()
}
func (m *Mutator) Ecalli(imm uint32) polkavm.HostCallResult {
	callFn := m.hostFunctions[imm]
	if callFn == nil {
		return polkavm.HostCallResult{Code: polkavm.HostCallResultWho}
	}
	result := func() (result polkavm.HostCallResult) {
		defer func() {
			if e := recover(); e != nil {
				msg := ""
				switch x := e.(type) {
				case error:
					msg = x.Error()
				case fmt.Stringer:
					msg = x.String()
				}
				result = polkavm.HostCallResult{
					Code:      polkavm.HostCallResultOk,
					InnerCode: polkavm.HostCallInnerCodePanic,
					Msg:       msg,
				}
			}
		}()
		if err := callFn(m.instance); err != nil {
			return polkavm.HostCallResult{
				Code:      polkavm.HostCallResultOk,
				InnerCode: polkavm.HostCallInnerCodeFault,
				Msg:       err.Error(),
			}
		}

		return polkavm.HostCallResult{
			Code:      polkavm.HostCallResultOk,
			InnerCode: polkavm.HostCallInnerCodeHalt,
		}
	}()
	m.instance.NextOffsets()
	return result
}
func (m *Mutator) StoreU8(src polkavm.Reg, offset uint32) error {
	return m.store(x8, unsigned, m.get(src), 0, offset)
}
func (m *Mutator) StoreU16(src polkavm.Reg, offset uint32) error {
	return m.store(x16, unsigned, m.get(src), 0, offset)
}
func (m *Mutator) StoreU32(src polkavm.Reg, offset uint32) error {
	return m.store(x32, unsigned, m.get(src), 0, offset)
}
func (m *Mutator) StoreImmU8(offset uint32, value uint32) error {
	return m.store(x8, unsigned, value, 0, offset)
}
func (m *Mutator) StoreImmU16(offset uint32, value uint32) error {
	return m.store(x16, unsigned, value, 0, offset)
}
func (m *Mutator) StoreImmU32(offset uint32, value uint32) error {
	return m.store(x32, unsigned, value, 0, offset)
}
func (m *Mutator) StoreImmIndirectU8(base polkavm.Reg, offset uint32, value uint32) error {
	return m.store(x8, unsigned, value, base, offset)
}
func (m *Mutator) StoreImmIndirectU16(base polkavm.Reg, offset uint32, value uint32) error {
	return m.store(x16, unsigned, value, base, offset)
}
func (m *Mutator) StoreImmIndirectU32(base polkavm.Reg, offset uint32, value uint32) error {
	return m.store(x32, unsigned, value, base, offset)
}
func (m *Mutator) StoreIndirectU8(src polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.store(x8, unsigned, m.get(src), base, offset)
}
func (m *Mutator) StoreIndirectU16(src polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.store(x16, unsigned, m.get(src), base, offset)
}
func (m *Mutator) StoreIndirectU32(src polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.store(x32, unsigned, m.get(src), base, offset)
}
func (m *Mutator) LoadU8(dst polkavm.Reg, offset uint32) error {
	return m.load(x8, unsigned, dst, 0, offset)
}
func (m *Mutator) LoadI8(dst polkavm.Reg, offset uint32) error {
	return m.load(x8, signed, dst, 0, offset)
}
func (m *Mutator) LoadU16(dst polkavm.Reg, offset uint32) error {
	return m.load(x16, unsigned, dst, 0, offset)
}
func (m *Mutator) LoadI16(dst polkavm.Reg, offset uint32) error {
	return m.load(x16, signed, dst, 0, offset)
}
func (m *Mutator) LoadU32(dst polkavm.Reg, offset uint32) error {
	return m.load(x32, unsigned, dst, 0, offset)
}
func (m *Mutator) LoadIndirectU8(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.load(x8, unsigned, dst, base, offset)
}
func (m *Mutator) LoadIndirectI8(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.load(x8, signed, dst, base, offset)
}
func (m *Mutator) LoadIndirectU16(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.load(x16, unsigned, dst, base, offset)
}
func (m *Mutator) LoadIndirectI16(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.load(x16, signed, dst, base, offset)
}
func (m *Mutator) LoadIndirectU32(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.load(x32, unsigned, dst, base, offset)
}
func (m *Mutator) LoadImm(dst polkavm.Reg, imm uint32) {
	m.setNext(dst, imm)
}
func (m *Mutator) LoadImmAndJump(ra polkavm.Reg, value uint32, target uint32) {
	m.LoadImm(ra, value)
	m.Jump(target)
}
func (m *Mutator) LoadImmAndJumpIndirect(ra polkavm.Reg, base polkavm.Reg, value, offset uint32) error {
	target := m.get(base) + offset
	m.set(ra, value)
	return m.jumpIndirectImpl(target)
}
func (m *Mutator) Jump(target uint32) {
	m.instance.SetInstructionOffset(target)
	m.instance.StartBasicBlock(m.program)
}
func (m *Mutator) JumpIndirect(base polkavm.Reg, offset uint32) error {
	return m.jumpIndirectImpl(m.get(base) + offset)
}

func (m *Mutator) Execute(instance polkavm.Instance) error {
	instance.StartBasicBlock(m.program)
	for {
		instruction, err := instance.NextInstruction()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if err := instruction.StepOnce(m); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func divUnsigned(lhs uint32, rhs uint32) uint32 {
	if rhs == 0 {
		return math.MaxUint32
	} else {
		return lhs / rhs
	}
}

func remUnsigned(lhs uint32, rhs uint32) uint32 {
	if rhs == 0 {
		return lhs
	} else {
		return lhs % rhs
	}
}

func div(lhs int32, rhs int32) int32 {
	if rhs == 0 {
		return -1
	} else if lhs == math.MinInt32 && rhs == -1 {
		return lhs
	} else {
		return lhs / rhs
	}
}

func rem(lhs int32, rhs int32) int32 {
	if rhs == 0 {
		return lhs
	} else if lhs == math.MinInt32 && rhs == -1 {
		return 0
	} else {
		return lhs % rhs
	}
}

func bool2uint32(v bool) uint32 {
	if v {
		return 1
	}
	return 0
}
