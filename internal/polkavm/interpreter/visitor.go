package interpreter

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"

	"github.com/eigerco/strawberry/internal/polkavm"
)

const (
	Int8Len = iota
	Uint8Len
	Uint16Len
	Int16Len
	Uint32Len
)

var _ polkavm.Visitor = &visitor{}

func newVisitor(i *instance, m *module) *visitor {
	v := &visitor{
		instance:      i,
		hostFunctions: []callFunc{},
		memoryMap:     *m.memoryMap,
		program:       *m.program,
	}
	for _, imp := range m.program.Imports {
		hostFn, ok := m.hostFunctions[imp]
		if !ok {
			log.Println("host function not defined")
			continue
		}

		v.hostFunctions = append(v.hostFunctions, func(instance *instance) error {
			ret, err := hostFn(instance.regs[polkavm.A0], instance.regs[polkavm.A1], instance.regs[polkavm.A2], instance.regs[polkavm.A3], instance.regs[polkavm.A4], instance.regs[polkavm.A5])
			if err != nil {
				return TrapError{fmt.Errorf("external function error: %w", err)}
			}
			instance.regs[polkavm.A0] = ret
			return err
		})
	}
	return v
}

type visitor struct {
	instance      *instance
	program       polkavm.Program
	memoryMap     memoryMap
	hostFunctions []callFunc
}

func (v *visitor) branch(condition bool, target uint32) {
	if condition {
		v.instance.instructionOffset = target
	} else {
		v.onNextInstruction()
	}
}

func (v *visitor) load(memLen int, dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	address := v.get(base) + offset
	slice := v.instance.memory.getMemorySlice(v.program, v.memoryMap, address, memLen)
	if slice == nil {
		return TrapError{fmt.Errorf("unable to load memory slice")}
	}

	var value uint32
	switch memLen {
	case Uint8Len:
		value = uint32(slice[0])
	case Uint16Len:
		value = uint32(binary.LittleEndian.Uint16(slice))
	case Uint32Len:
		value = binary.LittleEndian.Uint32(slice)
	default:
		return fmt.Errorf("invalid memory slice length: %d", memLen)
	}
	v.setNext(dst, value)
	return nil
}

func (v *visitor) store(memLen int, src uint32, base polkavm.Reg, offset uint32) error {
	address := v.get(base) + offset
	slice := v.instance.memory.getMemorySlicePointer(v.memoryMap, address, memLen)
	switch memLen {
	case Uint8Len:
		(*slice)[0] = byte(src)
	case Uint16Len:
		binary.LittleEndian.PutUint16(*slice, uint16(src))
	case Uint32Len:
		binary.LittleEndian.PutUint32(*slice, src)
	default:
		return fmt.Errorf("invalid memory slice length: %d", memLen)
	}

	v.onNextInstruction()
	return nil
}
func (v *visitor) jumpIndirectImpl(target uint32) error {
	if target == VmAddrReturnToHost {
		v.instance.returnToHost = true
		return nil
	}
	instructionOffset := v.program.JumpTableGetByAddress(target)
	if instructionOffset == nil {
		return TrapError{fmt.Errorf("indirect jump to address %v: INVALID", target)}
	}
	v.instance.instructionOffset = *instructionOffset
	return nil
}

func (v *visitor) get(vv polkavm.Reg) uint32 {
	return v.instance.regs[vv]
}

func (v *visitor) set(dst polkavm.Reg, value uint32) {
	v.instance.regs[dst] = value
}

func (v *visitor) setNext(dst polkavm.Reg, value uint32) {
	v.set(dst, value)
	v.onNextInstruction()
}

func (v *visitor) onNextInstruction() {
	v.instance.instructionOffset += v.instance.instructionLength
	v.instance.compiledOffset += 1
}
func (v *visitor) Trap() error {
	log.Printf("Trap at %v: explicit trap", v.instance.instructionOffset)
	return TrapError{fmt.Errorf("trap at %v: explicit trap", v.instance.instructionOffset)}
}
func (v *visitor) Fallthrough() {
	v.onNextInstruction()
}
func (v *visitor) Sbrk(dst polkavm.Reg, size polkavm.Reg) {
	s := v.get(size)
	result, _ := v.instance.memory.sbrk(v.memoryMap, s)
	v.setNext(dst, result)
}
func (v *visitor) MoveReg(d polkavm.Reg, s polkavm.Reg) {
	v.setNext(d, v.get(s))
}
func (v *visitor) BranchEq(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	v.branch(v.get(s1) == v.get(s2), target)
}
func (v *visitor) BranchEqImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(v.get(s1) == s2, target)
}
func (v *visitor) BranchNotEq(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	v.branch(v.get(s1) != v.get(s2), target)
}
func (v *visitor) BranchNotEqImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(v.get(s1) != s2, target)
}
func (v *visitor) BranchLessUnsigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	v.branch(v.get(s1) < v.get(s2), target)
}
func (v *visitor) BranchLessUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(v.get(s1) < s2, target)
}
func (v *visitor) BranchLessSigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	v.branch(int32(v.get(s1)) < int32(v.get(s2)), target)
}
func (v *visitor) BranchLessSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(int32(v.get(s1)) < int32(s2), target)
}
func (v *visitor) BranchGreaterOrEqualUnsigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	v.branch(v.get(s1) >= v.get(s2), target)
}
func (v *visitor) BranchGreaterOrEqualUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(v.get(s1) >= s2, target)
}
func (v *visitor) BranchGreaterOrEqualSigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	v.branch(int32(v.get(s1)) >= int32(v.get(s2)), target)
}
func (v *visitor) BranchGreaterOrEqualSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(int32(v.get(s1)) >= int32(s2), target)
}
func (v *visitor) BranchLessOrEqualUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(v.get(s1) <= s2, target)
}
func (v *visitor) BranchLessOrEqualSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(int32(v.get(s1)) <= int32(s2), target)
}
func (v *visitor) BranchGreaterUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(v.get(s1) > s2, target)
}
func (v *visitor) BranchGreaterSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(int32(v.get(s1)) > int32(s2), target)
}
func (v *visitor) SetLessThanUnsignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, bool2uint32(v.get(s1) < s2))
}
func (v *visitor) SetLessThanSignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, bool2uint32(int32(v.get(s1)) < int32(s2)))
}
func (v *visitor) ShiftLogicalLeftImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)<<s2)
}
func (v *visitor) ShiftArithmeticRightImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, uint32(int32(v.get(s1))>>s2))
}
func (v *visitor) ShiftArithmeticRightImmAlt(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, uint32(int32(v.get(s1))>>s2))
}
func (v *visitor) NegateAndAddImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, s2-v.get(s1))
}
func (v *visitor) SetGreaterThanUnsignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, bool2uint32(v.get(s1) > s2))
}
func (v *visitor) SetGreaterThanSignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, bool2uint32(int32(v.get(s1)) > int32(s2)))
}
func (v *visitor) ShiftLogicalRightImmAlt(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)>>s2)
}
func (v *visitor) ShiftLogicalLeftImmAlt(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)<<s2)
}
func (v *visitor) Add(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)+v.get(s2))
}
func (v *visitor) AddImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)+s2)
}
func (v *visitor) Sub(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)-v.get(s2))
}
func (v *visitor) And(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)&v.get(s2))
}
func (v *visitor) AndImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)&s2)
}
func (v *visitor) Xor(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)^v.get(s2))
}
func (v *visitor) XorImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)^s2)
}
func (v *visitor) Or(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)|v.get(s2))
}
func (v *visitor) OrImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)|s2)
}
func (v *visitor) Mul(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)*v.get(s2))
}
func (v *visitor) MulImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)*s2)
}
func (v *visitor) MulUpperSignedSigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, uint32(mulh(int32(v.get(s1)), int32(v.get(s2)))))
}
func (v *visitor) MulUpperSignedSignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, uint32(mulh(int32(v.get(s1)), int32(s2))))
}
func (v *visitor) MulUpperUnsignedUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, uint32(mulh(int32(v.get(s1)), int32(v.get(s2)))))
}
func (v *visitor) MulUpperUnsignedUnsignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, uint32(mulh(int32(v.get(s1)), int32(s2))))
}
func (v *visitor) MulUpperSignedUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, mulhu(v.get(s1), v.get(s2)))
}
func (v *visitor) SetLessThanUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, bool2uint32(v.get(s1) < v.get(s2)))
}
func (v *visitor) SetLessThanSigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, bool2uint32(v.get(s1) < v.get(s2)))
}
func (v *visitor) ShiftLogicalLeft(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)<<v.get(s2))
}
func (v *visitor) ShiftLogicalRight(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)>>v.get(s2))
}
func (v *visitor) ShiftLogicalRightImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)>>s2)
}
func (v *visitor) ShiftArithmeticRight(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, uint32(int32(v.get(s1))>>s2))
}
func (v *visitor) DivUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, divu(v.get(s1), v.get(s2)))
}
func (v *visitor) DivSigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, uint32(div(int32(v.get(s1)), int32(v.get(s2)))))
}
func (v *visitor) RemUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, remu(v.get(s1), v.get(s2)))
}
func (v *visitor) RemSigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, uint32(rem(int32(v.get(s1)), int32(v.get(s2)))))
}
func (v *visitor) CmovIfZero(d polkavm.Reg, s, c polkavm.Reg) {
	if v.get(c) == 0 {
		v.set(d, v.get(s))
	}
	v.onNextInstruction()
}
func (v *visitor) CmovIfZeroImm(d polkavm.Reg, c polkavm.Reg, s uint32) {
	if v.get(c) == 0 {
		v.set(d, s)
	}
	v.onNextInstruction()
}
func (v *visitor) CmovIfNotZero(d polkavm.Reg, s, c polkavm.Reg) {
	if v.get(c) != 0 {
		v.set(d, v.get(s))
	}
	v.onNextInstruction()
}
func (v *visitor) CmovIfNotZeroImm(d polkavm.Reg, c polkavm.Reg, s uint32) {
	if v.get(c) != 0 {
		v.set(d, s)
	}

	v.onNextInstruction()
}
func (v *visitor) Ecalli(imm uint32) error {
	callFn := v.hostFunctions[imm]
	if callFn == nil {
		log.Println("call function not found")
		return &TrapError{fmt.Errorf("call function not found")}
	}
	if err := callFn(v.instance); err != nil {
		return &ExecutionError{err}
	}
	v.onNextInstruction()
	return nil
}
func (v *visitor) StoreU8(src polkavm.Reg, offset uint32) error {
	return v.store(Uint8Len, v.get(src), 0, offset)
}
func (v *visitor) StoreU16(src polkavm.Reg, offset uint32) error {
	return v.store(Uint16Len, v.get(src), 0, offset)
}
func (v *visitor) StoreU32(src polkavm.Reg, offset uint32) error {
	return v.store(Uint32Len, v.get(src), 0, offset)
}
func (v *visitor) StoreImmU8(offset uint32, value uint32) error {
	return v.store(Uint8Len, value, 0, offset)
}
func (v *visitor) StoreImmU16(offset uint32, value uint32) error {
	return v.store(Uint16Len, value, 0, offset)
}
func (v *visitor) StoreImmU32(offset uint32, value uint32) error {
	return v.store(Uint32Len, value, 0, offset)
}
func (v *visitor) StoreImmIndirectU8(base polkavm.Reg, offset uint32, value uint32) error {
	return v.store(Uint8Len, value, base, offset)
}
func (v *visitor) StoreImmIndirectU16(base polkavm.Reg, offset uint32, value uint32) error {
	return v.store(Uint16Len, value, base, offset)
}
func (v *visitor) StoreImmIndirectU32(base polkavm.Reg, offset uint32, value uint32) error {
	return v.store(Uint32Len, value, base, offset)
}
func (v *visitor) StoreIndirectU8(src polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.store(Uint8Len, v.get(src), base, offset)
}
func (v *visitor) StoreIndirectU16(src polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.store(Uint16Len, v.get(src), base, offset)
}
func (v *visitor) StoreIndirectU32(src polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.store(Uint32Len, v.get(src), base, offset)
}
func (v *visitor) LoadU8(dst polkavm.Reg, offset uint32) error {
	return v.load(Uint8Len, dst, 0, offset)
}
func (v *visitor) LoadI8(dst polkavm.Reg, offset uint32) error {
	return v.load(Int8Len, dst, 0, offset)
}
func (v *visitor) LoadU16(dst polkavm.Reg, offset uint32) error {
	return v.load(Uint16Len, dst, 0, offset)
}
func (v *visitor) LoadI16(dst polkavm.Reg, offset uint32) error {
	return v.load(Int16Len, dst, 0, offset)
}
func (v *visitor) LoadU32(dst polkavm.Reg, offset uint32) error {
	return v.load(Uint32Len, dst, 0, offset)
}
func (v *visitor) LoadIndirectU8(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.load(Uint8Len, dst, base, offset)
}
func (v *visitor) LoadIndirectI8(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.load(Int8Len, dst, base, offset)
}
func (v *visitor) LoadIndirectU16(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.load(Uint16Len, dst, base, offset)
}
func (v *visitor) LoadIndirectI16(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.load(Int16Len, dst, base, offset)
}
func (v *visitor) LoadIndirectU32(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.load(Uint32Len, dst, base, offset)
}
func (v *visitor) LoadImm(dst polkavm.Reg, imm uint32) {
	v.setNext(dst, imm)
}
func (v *visitor) LoadImmAndJump(ra polkavm.Reg, value uint32, target uint32) {
	v.LoadImm(ra, value)
	v.Jump(target)
}
func (v *visitor) LoadImmAndJumpIndirect(ra polkavm.Reg, base polkavm.Reg, value, offset uint32) error {
	target := v.get(base) + offset
	v.set(ra, value)
	return v.jumpIndirectImpl(target)
}
func (v *visitor) Jump(target uint32) {
	v.instance.instructionOffset = target
}
func (v *visitor) JumpIndirect(base polkavm.Reg, offset uint32) error {
	return v.jumpIndirectImpl(v.get(base) + offset)
}

func divu(lhs uint32, rhs uint32) uint32 {
	if rhs == 0 {
		return math.MaxUint32
	} else {
		return lhs / rhs
	}
}

func remu(lhs uint32, rhs uint32) uint32 {
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

func mulh(lhs int32, rhs int32) int32 {
	return int32((int64(lhs) * int64(rhs)) >> 32)
}

func mulhsu(lhs int32, rhs uint32) int32 {
	return int32((int64(lhs) * int64(rhs)) >> 32)
}

func mulhu(lhs uint32, rhs uint32) uint32 {
	return uint32((int64(lhs) * int64(rhs)) >> 32)
}

func bool2uint32(v bool) uint32 {
	if v {
		return 1
	}
	return 0
}
