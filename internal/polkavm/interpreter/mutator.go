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

var _ polkavm.Mutator = &mutator{}

func newMutator(i *instance, m *module, gasLimit int64) *mutator {
	v := &mutator{
		instance:                 i,
		hostFunctions:            []callFunc{},
		memoryMap:                *m.memoryMap,
		program:                  *m.program,
		instructionOffsetToIndex: m.instructionOffsetToIndex,
		gasRemaining:             gasLimit,
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

type mutator struct {
	instance                 *instance
	program                  polkavm.Program
	instructionOffsetToIndex map[uint32]int
	memoryMap                memoryMap
	hostFunctions            []callFunc
	gasRemaining             int64
}

func (v *mutator) GetGasRemaining() int64 {
	return v.gasRemaining
}

func (v *mutator) DeductGas(cost int64) {
	if cost > v.gasRemaining {
		v.gasRemaining = 0
	} else {
		v.gasRemaining -= cost
	}
}

func (v *mutator) startBasicBlock() {
	if compiledOffset, ok := v.instance.offsetForBasicBlock[v.instance.instructionOffset]; ok {
		v.instance.instructionCounter = compiledOffset
	} else {
		v.instance.instructionCounter = len(v.instance.instructions)
		v.addInstructionsForBlock()
	}
}

func (v *mutator) addInstructionsForBlock() {
	startingOffset := len(v.instance.instructions)
	for _, instruction := range v.program.Instructions[v.instructionOffsetToIndex[v.instance.instructionOffset]:] {
		v.instance.instructions = append(v.instance.instructions, instruction)
		if instruction.IsBasicBlockTermination() {
			break
		}
	}
	if len(v.instance.instructions) == startingOffset {
		return
	}
	v.instance.offsetForBasicBlock[v.instance.instructionOffset] = startingOffset
}

func (v *mutator) branch(condition bool, target uint32) {
	if condition {
		v.instance.instructionOffset = target
	} else {
		v.nextOffsets()
	}
	v.startBasicBlock()
}

func (v *mutator) load(memLen int, dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	address := v.get(base) + offset
	slice, err := v.instance.memory.getMemorySlice(v.program, v.memoryMap, address, memLen)
	if err != nil {
		return err
	}
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

func (v *mutator) store(memLen int, src uint32, base polkavm.Reg, offset uint32) error {
	address := v.get(base) + offset
	slice, err := v.instance.memory.getMemorySlicePointer(v.memoryMap, address, memLen)
	if err != nil {
		return err
	}
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

	v.nextOffsets()
	return nil
}

func (v *mutator) jumpIndirectImpl(target uint32) error {
	if target == VmAddrReturnToHost {
		v.instance.returnToHost = true
		return nil
	}
	instructionOffset := v.program.JumpTableGetByAddress(target)
	if instructionOffset == nil {
		return TrapError{fmt.Errorf("indirect jump to address %v: INVALID", target)}
	}
	v.instance.instructionOffset = *instructionOffset
	v.startBasicBlock()
	return nil
}

func (v *mutator) get(vv polkavm.Reg) uint32 {
	return v.instance.regs[vv]
}

func (v *mutator) set(dst polkavm.Reg, value uint32) {
	v.instance.regs[dst] = value
}

func (v *mutator) setNext(dst polkavm.Reg, value uint32) {
	v.set(dst, value)
	v.nextOffsets()
}

func (v *mutator) nextOffsets() {
	v.instance.instructionOffset += v.instance.instructionLength
	v.instance.instructionCounter += 1
}
func (v *mutator) Trap() error {
	log.Printf("Trap at %v: explicit trap", v.instance.instructionOffset)
	return TrapError{fmt.Errorf("trap at %v: explicit trap", v.instance.instructionOffset)}
}
func (v *mutator) Fallthrough() {
	v.nextOffsets()
	v.startBasicBlock()
}
func (v *mutator) Sbrk(dst polkavm.Reg, size polkavm.Reg) {
	s := v.get(size)
	result, _ := v.instance.memory.sbrk(v.memoryMap, s)
	v.setNext(dst, result)
}
func (v *mutator) MoveReg(d polkavm.Reg, s polkavm.Reg) {
	v.setNext(d, v.get(s))
}
func (v *mutator) BranchEq(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	v.branch(v.get(s1) == v.get(s2), target)
}
func (v *mutator) BranchEqImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(v.get(s1) == s2, target)
}
func (v *mutator) BranchNotEq(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	v.branch(v.get(s1) != v.get(s2), target)
}
func (v *mutator) BranchNotEqImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(v.get(s1) != s2, target)
}
func (v *mutator) BranchLessUnsigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	v.branch(v.get(s1) < v.get(s2), target)
}
func (v *mutator) BranchLessUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(v.get(s1) < s2, target)
}
func (v *mutator) BranchLessSigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	v.branch(int32(v.get(s1)) < int32(v.get(s2)), target)
}
func (v *mutator) BranchLessSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(int32(v.get(s1)) < int32(s2), target)
}
func (v *mutator) BranchGreaterOrEqualUnsigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	v.branch(v.get(s1) >= v.get(s2), target)
}
func (v *mutator) BranchGreaterOrEqualUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(v.get(s1) >= s2, target)
}
func (v *mutator) BranchGreaterOrEqualSigned(s1 polkavm.Reg, s2 polkavm.Reg, target uint32) {
	v.branch(int32(v.get(s1)) >= int32(v.get(s2)), target)
}
func (v *mutator) BranchGreaterOrEqualSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(int32(v.get(s1)) >= int32(s2), target)
}
func (v *mutator) BranchLessOrEqualUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(v.get(s1) <= s2, target)
}
func (v *mutator) BranchLessOrEqualSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(int32(v.get(s1)) <= int32(s2), target)
}
func (v *mutator) BranchGreaterUnsignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(v.get(s1) > s2, target)
}
func (v *mutator) BranchGreaterSignedImm(s1 polkavm.Reg, s2 uint32, target uint32) {
	v.branch(int32(v.get(s1)) > int32(s2), target)
}
func (v *mutator) SetLessThanUnsignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, bool2uint32(v.get(s1) < s2))
}
func (v *mutator) SetLessThanSignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, bool2uint32(int32(v.get(s1)) < int32(s2)))
}
func (v *mutator) ShiftLogicalLeftImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)<<s2)
}
func (v *mutator) ShiftArithmeticRightImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, uint32(int32(v.get(s1))>>s2))
}
func (v *mutator) ShiftArithmeticRightImmAlt(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, uint32(int32(v.get(s1))>>s2))
}
func (v *mutator) NegateAndAddImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, s2-v.get(s1))
}
func (v *mutator) SetGreaterThanUnsignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, bool2uint32(v.get(s1) > s2))
}
func (v *mutator) SetGreaterThanSignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, bool2uint32(int32(v.get(s1)) > int32(s2)))
}
func (v *mutator) ShiftLogicalRightImmAlt(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)>>s2)
}
func (v *mutator) ShiftLogicalLeftImmAlt(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)<<s2)
}
func (v *mutator) Add(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)+v.get(s2))
}
func (v *mutator) AddImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)+s2)
}
func (v *mutator) Sub(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)-v.get(s2))
}
func (v *mutator) And(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)&v.get(s2))
}
func (v *mutator) AndImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)&s2)
}
func (v *mutator) Xor(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)^v.get(s2))
}
func (v *mutator) XorImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)^s2)
}
func (v *mutator) Or(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)|v.get(s2))
}
func (v *mutator) OrImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)|s2)
}
func (v *mutator) Mul(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)*v.get(s2))
}
func (v *mutator) MulImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)*s2)
}
func (v *mutator) MulUpperSignedSigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, uint32(int32((int64(v.get(s1))*int64(v.get(s2)))>>32)))
}
func (v *mutator) MulUpperSignedSignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, uint32(int32((int64(v.get(s1))*int64(s2))>>32)))
}
func (v *mutator) MulUpperUnsignedUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, uint32(int32((int64(v.get(s1))*int64(v.get(s2)))>>32)))
}
func (v *mutator) MulUpperUnsignedUnsignedImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, uint32(int32((int64(v.get(s1))*int64(s2))>>32)))
}
func (v *mutator) MulUpperSignedUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, uint32((int64(v.get(s1))*int64(v.get(s2)))>>32))
}
func (v *mutator) SetLessThanUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, bool2uint32(v.get(s1) < v.get(s2)))
}
func (v *mutator) SetLessThanSigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, bool2uint32(v.get(s1) < v.get(s2)))
}
func (v *mutator) ShiftLogicalLeft(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)<<v.get(s2))
}
func (v *mutator) ShiftLogicalRight(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, v.get(s1)>>v.get(s2))
}
func (v *mutator) ShiftLogicalRightImm(d polkavm.Reg, s1 polkavm.Reg, s2 uint32) {
	v.setNext(d, v.get(s1)>>s2)
}
func (v *mutator) ShiftArithmeticRight(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, uint32(int32(v.get(s1))>>s2))
}
func (v *mutator) DivUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, divUnsigned(v.get(s1), v.get(s2)))
}
func (v *mutator) DivSigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, uint32(div(int32(v.get(s1)), int32(v.get(s2)))))
}
func (v *mutator) RemUnsigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, remUnsigned(v.get(s1), v.get(s2)))
}
func (v *mutator) RemSigned(d polkavm.Reg, s1, s2 polkavm.Reg) {
	v.setNext(d, uint32(rem(int32(v.get(s1)), int32(v.get(s2)))))
}
func (v *mutator) CmovIfZero(d polkavm.Reg, s, c polkavm.Reg) {
	if v.get(c) == 0 {
		v.set(d, v.get(s))
	}
	v.nextOffsets()
}
func (v *mutator) CmovIfZeroImm(d polkavm.Reg, c polkavm.Reg, s uint32) {
	if v.get(c) == 0 {
		v.set(d, s)
	}
	v.nextOffsets()
}
func (v *mutator) CmovIfNotZero(d polkavm.Reg, s, c polkavm.Reg) {
	if v.get(c) != 0 {
		v.set(d, v.get(s))
	}
	v.nextOffsets()
}
func (v *mutator) CmovIfNotZeroImm(d polkavm.Reg, c polkavm.Reg, s uint32) {
	if v.get(c) != 0 {
		v.set(d, s)
	}

	v.nextOffsets()
}
func (v *mutator) Ecalli(imm uint32) polkavm.HostCallResult {
	callFn := v.hostFunctions[imm]
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
		if err := callFn(v.instance); err != nil {
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
	v.nextOffsets()
	return result
}
func (v *mutator) StoreU8(src polkavm.Reg, offset uint32) error {
	return v.store(Uint8Len, v.get(src), 0, offset)
}
func (v *mutator) StoreU16(src polkavm.Reg, offset uint32) error {
	return v.store(Uint16Len, v.get(src), 0, offset)
}
func (v *mutator) StoreU32(src polkavm.Reg, offset uint32) error {
	return v.store(Uint32Len, v.get(src), 0, offset)
}
func (v *mutator) StoreImmU8(offset uint32, value uint32) error {
	return v.store(Uint8Len, value, 0, offset)
}
func (v *mutator) StoreImmU16(offset uint32, value uint32) error {
	return v.store(Uint16Len, value, 0, offset)
}
func (v *mutator) StoreImmU32(offset uint32, value uint32) error {
	return v.store(Uint32Len, value, 0, offset)
}
func (v *mutator) StoreImmIndirectU8(base polkavm.Reg, offset uint32, value uint32) error {
	return v.store(Uint8Len, value, base, offset)
}
func (v *mutator) StoreImmIndirectU16(base polkavm.Reg, offset uint32, value uint32) error {
	return v.store(Uint16Len, value, base, offset)
}
func (v *mutator) StoreImmIndirectU32(base polkavm.Reg, offset uint32, value uint32) error {
	return v.store(Uint32Len, value, base, offset)
}
func (v *mutator) StoreIndirectU8(src polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.store(Uint8Len, v.get(src), base, offset)
}
func (v *mutator) StoreIndirectU16(src polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.store(Uint16Len, v.get(src), base, offset)
}
func (v *mutator) StoreIndirectU32(src polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.store(Uint32Len, v.get(src), base, offset)
}
func (v *mutator) LoadU8(dst polkavm.Reg, offset uint32) error {
	return v.load(Uint8Len, dst, 0, offset)
}
func (v *mutator) LoadI8(dst polkavm.Reg, offset uint32) error {
	return v.load(Int8Len, dst, 0, offset)
}
func (v *mutator) LoadU16(dst polkavm.Reg, offset uint32) error {
	return v.load(Uint16Len, dst, 0, offset)
}
func (v *mutator) LoadI16(dst polkavm.Reg, offset uint32) error {
	return v.load(Int16Len, dst, 0, offset)
}
func (v *mutator) LoadU32(dst polkavm.Reg, offset uint32) error {
	return v.load(Uint32Len, dst, 0, offset)
}
func (v *mutator) LoadIndirectU8(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.load(Uint8Len, dst, base, offset)
}
func (v *mutator) LoadIndirectI8(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.load(Int8Len, dst, base, offset)
}
func (v *mutator) LoadIndirectU16(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.load(Uint16Len, dst, base, offset)
}
func (v *mutator) LoadIndirectI16(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.load(Int16Len, dst, base, offset)
}
func (v *mutator) LoadIndirectU32(dst polkavm.Reg, base polkavm.Reg, offset uint32) error {
	return v.load(Uint32Len, dst, base, offset)
}
func (v *mutator) LoadImm(dst polkavm.Reg, imm uint32) {
	v.setNext(dst, imm)
}
func (v *mutator) LoadImmAndJump(ra polkavm.Reg, value uint32, target uint32) {
	v.LoadImm(ra, value)
	v.Jump(target)
}
func (v *mutator) LoadImmAndJumpIndirect(ra polkavm.Reg, base polkavm.Reg, value, offset uint32) error {
	target := v.get(base) + offset
	v.set(ra, value)
	return v.jumpIndirectImpl(target)
}
func (v *mutator) Jump(target uint32) {
	v.instance.instructionOffset = target
	v.startBasicBlock()
}
func (v *mutator) JumpIndirect(base polkavm.Reg, offset uint32) error {
	return v.jumpIndirectImpl(v.get(base) + offset)
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
