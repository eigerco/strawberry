package interpreter

import (
	"encoding/binary"
	"math"

	"github.com/eigerco/strawberry/internal/polkavm"
)

const (
	x8  = 1
	x16 = 2
	x32 = 4
	x64 = 8
)

const (
	signed   = true
	unsigned = false
)

var _ polkavm.Mutator = &Mutator{}

func NewMutator(i *instance, program *polkavm.Program, memoryMap *polkavm.MemoryMap) *Mutator {
	v := &Mutator{
		instance:  i,
		memoryMap: memoryMap,
		program:   program,
	}
	return v
}

type Mutator struct {
	instance  *instance
	program   *polkavm.Program
	memoryMap *polkavm.MemoryMap
}

func (m *Mutator) branch(condition bool, target uint32) {
	if condition {
		m.instance.instructionOffset = target
	} else {
		m.instance.NextOffsets()
	}
	m.instance.startBasicBlock(m.program)
}

func (m *Mutator) load(memLen int, signed bool, dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	var address uint32 = 0
	if base != 0 {
		address = m.get32(base)
	}
	address += offset
	slice := make([]byte, memLen)
	err := m.instance.memory.Read(address, slice)
	if err != nil {
		return err
	}

	value, err := leDecode(memLen, slice)
	if err != nil {
		return err
	}
	m.setNext64(dst, toSigned(value, memLen, signed))
	return nil
}

func (m *Mutator) store(memLen int, signed bool, src uint64, base polkavm.Reg, offset uint32) error {
	var address uint32 = 0
	if base != 0 {
		address = m.get32(base)
	}
	address += offset
	data, err := leEncode(memLen, toSigned(src, memLen, signed))
	if err != nil {
		return err
	}
	if err = m.instance.memory.Write(address, data); err != nil {
		return err
	}

	m.instance.NextOffsets()
	return nil
}
func toSigned(v uint64, memLen int, signed bool) uint64 {
	if signed {
		switch memLen {
		case x8:
			return uint64(int8(v))
		case x16:
			return uint64(int16(v))
		case x32:
			return uint64(int32(v))
		case x64:
			return uint64(int64(v))
		}
	}
	return v
}
func leEncode(memLen int, src uint64) ([]byte, error) {
	slice := make([]byte, memLen)
	switch memLen {
	case x8:
		slice[0] = byte(src)
	case x16:
		binary.LittleEndian.PutUint16(slice, uint16(src))
	case x32:
		binary.LittleEndian.PutUint32(slice, uint32(src))
	default:
		return nil, polkavm.ErrPanicf("invalid Memory slice length: %d", memLen)
	}
	return slice, nil
}
func leDecode(memLen int, src []byte) (uint64, error) {
	switch memLen {
	case x8:
		return uint64(src[0]), nil
	case x16:
		return uint64(binary.LittleEndian.Uint16(src)), nil
	case x32:
		return uint64(binary.LittleEndian.Uint32(src)), nil
	case x64:
		return binary.LittleEndian.Uint64(src), nil
	default:
		return 0, polkavm.ErrPanicf("invalid Memory slice length: %d", memLen)
	}
}

// djump Equation 249 v0.4.5
func (m *Mutator) djump(target uint32) error {
	if target == polkavm.VmAddressReturnToHost {
		return polkavm.ErrHalt
	}
	instructionOffset := m.program.JumpTableGetByAddress(target)
	if instructionOffset == nil {
		return polkavm.ErrPanicf("indirect jump to address %v: INVALID", target)
	}
	m.instance.instructionOffset = *instructionOffset
	m.instance.startBasicBlock(m.program)
	return nil
}

func (m *Mutator) get32(vv polkavm.Reg) uint32 {
	return uint32(m.instance.regs[vv])
}

func (m *Mutator) get64(vv polkavm.Reg) uint64 {
	return m.instance.regs[vv]
}

func (m *Mutator) set32(dst polkavm.Reg, value uint32) {
	m.instance.regs[dst] = uint64(value)
}

func (m *Mutator) set64(dst polkavm.Reg, value uint64) {
	m.instance.regs[dst] = value
}

func (m *Mutator) setNext32(dst polkavm.Reg, value uint32) {
	m.set32(dst, value)
	m.instance.NextOffsets()
}
func (m *Mutator) setNext64(dst polkavm.Reg, value uint64) {
	m.set64(dst, value)
	m.instance.NextOffsets()
}
func (m *Mutator) Trap() error {
	return polkavm.ErrPanicf("explicit trap")
}
func (m *Mutator) Fallthrough() {
	m.instance.NextOffsets()
	m.instance.startBasicBlock(m.program)
}
func (m *Mutator) Sbrk(dst polkavm.Reg, sizeReg polkavm.Reg) error {
	size := m.get32(sizeReg)
	if size == 0 {
		// The guest wants to know the current heap pointer.
		m.setNext32(dst, m.instance.heapSize)
		return nil
	}

	newHeapSize := m.instance.heapSize + size
	if newHeapSize > uint32(m.memoryMap.MaxHeapSize) {
		return polkavm.ErrPanicf("max heap size exceeded")
	}

	m.instance.heapSize = newHeapSize
	heapTop := m.memoryMap.HeapBase + newHeapSize
	if err := m.instance.memory.Sbrk(m.memoryMap.PageSize, heapTop); err != nil {
		return polkavm.ErrPanicf(err.Error())
	}

	m.setNext32(dst, uint32(heapTop))
	return nil
}

func (m *Mutator) MoveReg(d polkavm.Reg, s polkavm.Reg) {
	m.setNext32(d, m.get32(s))
}
func (m *Mutator) BranchEq(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	m.branch(m.get32(s1) == m.get32(s2), target)
}
func (m *Mutator) BranchEqImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(m.get32(s1) == s2, target)
}
func (m *Mutator) BranchNotEq(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	m.branch(m.get32(s1) != m.get32(s2), target)
}
func (m *Mutator) BranchNotEqImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(m.get32(s1) != s2, target)
}
func (m *Mutator) BranchLessUnsigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	m.branch(m.get32(s1) < m.get32(s2), target)
}
func (m *Mutator) BranchLessUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(m.get32(s1) < s2, target)
}
func (m *Mutator) BranchLessSigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	m.branch(int32(m.get32(s1)) < int32(m.get32(s2)), target)
}
func (m *Mutator) BranchLessSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(int32(m.get32(s1)) < int32(s2), target)
}
func (m *Mutator) BranchGreaterOrEqualUnsigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	m.branch(m.get32(s1) >= m.get32(s2), target)
}
func (m *Mutator) BranchGreaterOrEqualUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(m.get32(s1) >= s2, target)
}
func (m *Mutator) BranchGreaterOrEqualSigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	m.branch(int32(m.get32(s1)) >= int32(m.get32(s2)), target)
}
func (m *Mutator) BranchGreaterOrEqualSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(int32(m.get32(s1)) >= int32(s2), target)
}
func (m *Mutator) BranchLessOrEqualUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(m.get32(s1) <= s2, target)
}
func (m *Mutator) BranchLessOrEqualSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(int32(m.get32(s1)) <= int32(s2), target)
}
func (m *Mutator) BranchGreaterUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(m.get32(s1) > s2, target)
}
func (m *Mutator) BranchGreaterSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	m.branch(int32(m.get32(s1)) > int32(s2), target)
}
func (m *Mutator) SetLessThanUnsignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, bool2uint32(m.get32(s1) < s2))
}
func (m *Mutator) SetLessThanSignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, bool2uint32(int32(m.get32(s1)) < int32(s2)))
}
func (m *Mutator) ShiftLogicalLeftImm32(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, m.get32(s1)<<s2)
}
func (m *Mutator) ShiftLogicalLeftImm64(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext64(d, m.get64(s1)<<s2)
}
func (m *Mutator) ShiftArithmeticRightImm32(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, uint32(int32(m.get32(s1))>>s2))
}
func (m *Mutator) ShiftArithmeticRightImm64(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext64(d, uint64(int64(m.get64(s1))>>s2))
}
func (m *Mutator) ShiftArithmeticRightImmAlt32(d polkavm.Reg, s2 polkavm.Reg, s1 uint32) {
	m.setNext32(d, uint32(int32(s1)>>m.get32(s2)))
}
func (m *Mutator) ShiftArithmeticRightImmAlt64(d polkavm.Reg, s2 polkavm.Reg, s1 uint32) {
	m.setNext64(d, uint64(int64(s1)>>m.get64(s2)))
}
func (m *Mutator) NegateAndAddImm32(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, s2-m.get32(s1))
}
func (m *Mutator) NegateAndAddImm64(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext64(d, uint64(s2)-m.get64(s1))
}
func (m *Mutator) SetGreaterThanUnsignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, bool2uint32(m.get32(s1) > s2))
}
func (m *Mutator) SetGreaterThanSignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, bool2uint32(int32(m.get32(s1)) > int32(s2)))
}
func (m *Mutator) ShiftLogicalRightImmAlt32(d polkavm.Reg, s2 polkavm.Reg, s1 uint32) {
	m.setNext32(d, s1>>m.get32(s2))
}
func (m *Mutator) ShiftLogicalRightImmAlt64(d polkavm.Reg, s2 polkavm.Reg, s1 uint32) {
	m.setNext32(d, s1>>m.get32(s2))
}
func (m *Mutator) ShiftLogicalLeftImmAlt32(d polkavm.Reg, s2 polkavm.Reg, s1 uint32) {
	m.setNext32(d, s1<<m.get32(s2))
}
func (m *Mutator) ShiftLogicalLeftImmAlt64(d polkavm.Reg, s2 polkavm.Reg, s1 uint32) {
	m.setNext32(d, s1<<m.get32(s2))
}

// Add32 32ω′D = X4((ωA + ωB) mod 2^32)
func (m *Mutator) Add32(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext32(d, m.get32(s1)+m.get32(s2))
}

// Add64 ω′D = (ωA + ωB) mod 2^64
func (m *Mutator) Add64(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext64(d, m.get64(s1)+m.get64(s2))
}
func (m *Mutator) AddImm32(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, m.get32(s1)+s2)
}
func (m *Mutator) AddImm64(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext64(d, m.get64(s1)+uint64(s2))
}
func (m *Mutator) Sub32(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext32(d, m.get32(s1)-m.get32(s2))
}
func (m *Mutator) Sub64(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext64(d, m.get64(s1)-m.get64(s2))
}
func (m *Mutator) And(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext32(d, m.get32(s1)&m.get32(s2))
}
func (m *Mutator) AndImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, m.get32(s1)&s2)
}
func (m *Mutator) Xor(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext32(d, m.get32(s1)^m.get32(s2))
}
func (m *Mutator) XorImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, m.get32(s1)^s2)
}
func (m *Mutator) Or(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext32(d, m.get32(s1)|m.get32(s2))
}
func (m *Mutator) OrImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, m.get32(s1)|s2)
}
func (m *Mutator) Mul32(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext32(d, m.get32(s1)*m.get32(s2))
}
func (m *Mutator) Mul64(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext64(d, m.get64(s1)*m.get64(s2))
}
func (m *Mutator) MulImm32(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, m.get32(s1)*s2)
}
func (m *Mutator) MulImm64(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext64(d, m.get64(s1)*uint64(s2))
}
func (m *Mutator) MulUpperSignedSigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext32(d, uint32(int32((int64(m.get32(s1))*int64(m.get32(s2)))>>32)))
}
func (m *Mutator) MulUpperSignedSignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, uint32(int32((int64(m.get32(s1))*int64(s2))>>32)))
}
func (m *Mutator) MulUpperUnsignedUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext32(d, uint32(int32((int64(m.get32(s1))*int64(m.get32(s2)))>>32)))
}
func (m *Mutator) MulUpperUnsignedUnsignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, uint32(int32((int64(m.get32(s1))*int64(s2))>>32)))
}
func (m *Mutator) MulUpperSignedUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext32(d, uint32((int64(m.get32(s1))*int64(m.get32(s2)))>>32))
}
func (m *Mutator) SetLessThanUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext32(d, bool2uint32(m.get32(s1) < m.get32(s2)))
}
func (m *Mutator) SetLessThanSigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext32(d, bool2uint32(int32(m.get32(s1)) < int32(m.get32(s2))))
}
func (m *Mutator) ShiftLogicalLeft32(d polkavm.Reg, s1, s2 polkavm.Reg) {
	shiftAmount := m.get32(s2) % 32
	shiftedValue := m.get32(s1) << shiftAmount
	m.setNext32(d, shiftedValue)
}
func (m *Mutator) ShiftLogicalLeft64(d polkavm.Reg, s1, s2 polkavm.Reg) {
	shiftAmount := m.get32(s2) % 64
	shiftedValue := m.get32(s1) << shiftAmount
	m.setNext32(d, shiftedValue)
}
func (m *Mutator) ShiftLogicalRight32(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext32(d, m.get32(s1)>>(m.get32(s2)%32))
}
func (m *Mutator) ShiftLogicalRight64(d polkavm.Reg, s1, s2 polkavm.Reg) {
	m.setNext64(d, m.get64(s1)>>(m.get64(s2)%64))
}
func (m *Mutator) ShiftLogicalRightImm32(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext32(d, m.get32(s1)>>s2)
}
func (m *Mutator) ShiftLogicalRightImm64(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	m.setNext64(d, m.get64(s1)>>s2)
}
func (m *Mutator) ShiftArithmeticRight32(d polkavm.Reg, s1, s2 polkavm.Reg) {
	shiftAmount := m.get32(s2) % 32
	shiftedValue := int32(m.get32(s1)) >> shiftAmount
	m.setNext32(d, uint32(shiftedValue))
}
func (m *Mutator) ShiftArithmeticRight64(d polkavm.Reg, s1, s2 polkavm.Reg) {
	shiftAmount := m.get64(s2) % 64
	shiftedValue := int64(m.get64(s1)) >> shiftAmount
	m.setNext64(d, uint64(shiftedValue))
}
func (m *Mutator) DivUnsigned32(d polkavm.Reg, s1, s2 polkavm.Reg) {
	lhs, rhs := m.get32(s1), m.get32(s2)
	if rhs == 0 {
		m.set64(d, math.MaxUint64)
	} else {
		m.set32(d, lhs/rhs)
	}
	m.instance.NextOffsets()
}
func (m *Mutator) DivUnsigned64(d polkavm.Reg, s1, s2 polkavm.Reg) {
	lhs, rhs := m.get64(s1), m.get64(s2)
	if rhs == 0 {
		m.set64(d, math.MaxUint64)
	} else {
		m.set64(d, lhs/rhs)
	}
	m.instance.NextOffsets()
}
func (m *Mutator) DivSigned32(d polkavm.Reg, s1, s2 polkavm.Reg) {
	lhs := int32(m.get32(s1))
	rhs := int32(m.get32(s2))
	if rhs == 0 {
		m.set64(d, math.MaxUint64)
	} else if lhs == math.MinInt32 && rhs == -1 {
		m.set32(d, uint32(lhs))
	} else {
		m.set32(d, uint32(lhs/rhs))
	}
	m.instance.NextOffsets()
}
func (m *Mutator) DivSigned64(d polkavm.Reg, s1, s2 polkavm.Reg) {
	rhs := int64(m.get64(s1))
	lhs := int64(m.get64(s2))
	if rhs == 0 {
		m.set64(d, math.MaxUint64)
	} else if lhs == math.MinInt64 && rhs == -1 {
		m.set64(d, uint64(lhs))
	} else {
		m.set64(d, uint64(lhs/rhs))
	}
	m.instance.NextOffsets()
}
func (m *Mutator) RemUnsigned32(d polkavm.Reg, s1, s2 polkavm.Reg) {
	lhs, rhs := m.get32(s1), m.get32(s2)
	if rhs == 0 {
		m.set32(d, lhs)
	} else {
		m.set32(d, lhs%rhs)
	}
	m.instance.NextOffsets()
}
func (m *Mutator) RemUnsigned64(d polkavm.Reg, s1, s2 polkavm.Reg) {
	lhs, rhs := m.get64(s1), m.get64(s2)
	if rhs == 0 {
		m.set64(d, lhs)
	} else {
		m.set64(d, lhs%rhs)
	}
	m.instance.NextOffsets()
}
func (m *Mutator) RemSigned32(d polkavm.Reg, s1, s2 polkavm.Reg) {
	lhs := int32(m.get32(s1))
	rhs := int32(m.get32(s2))
	if rhs == 0 {
		m.set32(d, uint32(lhs))
	} else if lhs == math.MinInt32 && rhs == -1 {
		m.set32(d, 0)
	} else {
		m.set32(d, uint32(lhs%rhs))
	}
	m.instance.NextOffsets()
}

func (m *Mutator) RemSigned64(d polkavm.Reg, s1, s2 polkavm.Reg) {
	rhs, lhs := int64(m.get64(s1)), int64(m.get64(s2))
	if rhs == 0 {
		m.set64(d, uint64(lhs))
	} else if lhs == math.MinInt32 && rhs == -1 {
		m.set64(d, 0)
	} else {
		m.set64(d, uint64(lhs%rhs))
	}
	m.instance.NextOffsets()
}
func (m *Mutator) CmovIfZero(d polkavm.Reg, s, c polkavm.Reg) {
	if m.get32(c) == 0 {
		m.set32(d, m.get32(s))
	}
	m.instance.NextOffsets()
}
func (m *Mutator) CmovIfZeroImm(d polkavm.Reg, c polkavm.Reg, s uint32) {
	if m.get32(c) == 0 {
		m.set32(d, s)
	}
	m.instance.NextOffsets()
}
func (m *Mutator) CmovIfNotZero(d polkavm.Reg, s, c polkavm.Reg) {
	if m.get32(c) != 0 {
		m.set32(d, m.get32(s))
	}
	m.instance.NextOffsets()
}
func (m *Mutator) CmovIfNotZeroImm(d polkavm.Reg, c polkavm.Reg, s uint32) {
	if m.get32(c) != 0 {
		m.set32(d, s)
	}

	m.instance.NextOffsets()
}

func (m *Mutator) StoreU8(src polkavm.Reg, offset uint32) error {
	return m.store(x8, unsigned, uint64(m.get32(src)), 0, offset)
}
func (m *Mutator) StoreU16(src polkavm.Reg, offset uint32) error {
	return m.store(x16, unsigned, uint64(m.get32(src)), 0, offset)
}
func (m *Mutator) StoreU32(src polkavm.Reg, offset uint32) error {
	return m.store(x32, unsigned, uint64(m.get32(src)), 0, offset)
}
func (m *Mutator) StoreU64(src polkavm.Reg, offset uint32) error {
	return m.store(x32, unsigned, uint64(m.get32(src)), 0, offset)
}
func (m *Mutator) StoreImmU8(offset uint32, value uint32) error {
	return m.store(x8, unsigned, uint64(value), 0, offset)
}
func (m *Mutator) StoreImmU16(offset uint32, value uint32) error {
	return m.store(x16, unsigned, uint64(value), 0, offset)
}
func (m *Mutator) StoreImmU32(offset uint32, value uint32) error {
	return m.store(x32, unsigned, uint64(value), 0, offset)
}
func (m *Mutator) StoreImmU64(offset uint32, value uint32) error {
	return m.store(x64, unsigned, uint64(value), 0, offset)
}
func (m *Mutator) StoreImmIndirectU8(base polkavm.Reg, offset uint32, value uint32) error {
	return m.store(x8, unsigned, uint64(value), base, offset)
}
func (m *Mutator) StoreImmIndirectU16(base polkavm.Reg, offset uint32, value uint32) error {
	return m.store(x16, unsigned, uint64(value), base, offset)
}
func (m *Mutator) StoreImmIndirectU32(base polkavm.Reg, offset uint32, value uint32) error {
	return m.store(x32, unsigned, uint64(value), base, offset)
}
func (m *Mutator) StoreImmIndirectU64(base polkavm.Reg, offset uint32, value uint32) error {
	return m.store(x64, unsigned, uint64(value), base, offset)
}
func (m *Mutator) StoreIndirectU8(src polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.store(x8, unsigned, m.get64(src), base, offset)
}
func (m *Mutator) StoreIndirectU16(src polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.store(x16, unsigned, m.get64(src), base, offset)
}
func (m *Mutator) StoreIndirectU32(src polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.store(x32, unsigned, m.get64(src), base, offset)
}
func (m *Mutator) StoreIndirectU64(src polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.store(x64, unsigned, m.get64(src), base, offset)
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
func (m *Mutator) LoadI32(dst polkavm.Reg, offset uint32) error {
	return m.load(x32, signed, dst, 0, offset)
}
func (m *Mutator) LoadU32(dst polkavm.Reg, offset uint32) error {
	return m.load(x32, unsigned, dst, 0, offset)
}
func (m *Mutator) LoadU64(dst polkavm.Reg, offset uint32) error {
	return m.load(x64, unsigned, dst, 0, offset)
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
func (m *Mutator) LoadIndirectI32(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.load(x32, signed, dst, base, offset)
}
func (m *Mutator) LoadIndirectU32(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.load(x32, unsigned, dst, base, offset)
}
func (m *Mutator) LoadIndirectU64(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return m.load(x64, unsigned, dst, base, offset)
}
func (m *Mutator) LoadImm(dst polkavm.Reg, imm uint32) {
	m.setNext32(dst, imm)
}
func (m *Mutator) LoadImm64(dst polkavm.Reg, imm uint64) {
	m.setNext64(dst, imm)
}
func (m *Mutator) LoadImmAndJump(ra polkavm.Reg, value uint32, target uint32) {
	m.LoadImm(ra, value)
	m.Jump(target)
}
func (m *Mutator) LoadImmAndJumpIndirect(ra polkavm.Reg, base polkavm.Reg, value, offset uint32) error {
	target := m.get32(base) + offset
	m.set32(ra, value)
	return m.djump(target)
}
func (m *Mutator) Jump(target uint32) {
	m.instance.instructionOffset = target
	m.instance.startBasicBlock(m.program)
}

func (m *Mutator) JumpIndirect(base polkavm.Reg, offset uint32) error {
	return m.djump(m.get32(base) + offset)
}

func bool2uint32(v bool) uint32 {
	if v {
		return 1
	}
	return 0
}
