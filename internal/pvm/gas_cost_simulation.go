package pvm

import (
	"maps"
)

type SimulationState struct {
	*program

	instructionCounter *uint64 // i
	cost               uint64  // c
	instructionIndex   int     // n
	decodingSlots      uint64  // d
	executionReadiness uint64  // e

	scheduledInstructions []*uint64       // s⃗
	instructionCost       []uint64        // c⃗
	portAvailability      [][]int         // p⃗
	regs                  []regsSet       // r⃗
	instructionExecution  []execResources // x⃗

	execution execResources // x

	skipLen       uint8
	srcRegs       regsSet       // ˇs(c,k,ı) - a set of source registers read by a given instruction
	dstRegs       regsSet       // ˇr(c,k,ı) - a set of destination registers which are written by a given instruction
	instrCost     uint8         // ˇc
	decodeCost    uint8         // ˇd
	executionCost execResources // ˇx
}

type regsSet map[Reg]struct{}

func (regsA regsSet) overlapsWith(regsB regsSet) bool {
	for regA := range regsA {
		_, ok := regsB[regA]
		if ok {
			return true
		}
	}

	return false
}

type execResources struct {
	ALU   uint8 // x_A
	Load  uint8 // x_L
	Store uint8 // x_S
	Mul   uint8 // x_M
	Div   uint8 // x_D
}

func (e *execResources) add(another execResources) {
	e.ALU += another.ALU
	e.Load += another.Load
	e.Store += another.Store
	e.Mul += another.Mul
	e.Div += another.Div
}

func (e *execResources) sub(another execResources) {
	e.ALU -= another.ALU
	e.Load -= another.Load
	e.Store -= another.Store
	e.Mul -= another.Mul
	e.Div -= another.Div
}

func (e *execResources) greaterThan(another execResources) bool {
	return e.ALU > another.ALU &&
		e.Load > another.Load &&
		e.Store > another.Store &&
		e.Mul > another.Mul &&
		e.Div > another.Div
}

func NewSimulation(program *program, instructionCounter uint64) *SimulationState {
	return &SimulationState{
		instructionCounter:    &instructionCounter,
		cost:                  0,
		instructionIndex:      0,
		decodingSlots:         4,
		executionReadiness:    5,
		scheduledInstructions: []*uint64{},
		instructionCost:       []uint64{},
		portAvailability:      [][]int{},
		regs:                  []regsSet{},
		instructionExecution:  []execResources{},
		execution: execResources{
			ALU:   4,
			Load:  4,
			Store: 4,
			Mul:   1,
			Div:   1,
		},
		program: program,
	}
}

func (s *SimulationState) Transition(instructionIndex uint64) {
	s.computeCostsAndRegs(*s.instructionCounter)
	// if n= 0 ∨ (ı(n) ≠ ∅ ∧ dˇ(c,k,ı(n)) ≤ d(n) ∧ ∣ s⃗(n)∣ < 32)
	if instructionIndex == 0 || (s.instructionCounter != nil && uint64(s.decodeCost) <= s.decodingSlots) || len(s.scheduledInstructions) < 32 {
		// X′
		s.ReorderBuffer(instructionIndex)
		return
	}

	// if S(Xn) ≠ ∅ ∧ e(n) > 0
	if _, ok := s.readyForExecution(instructionIndex); ok && s.executionReadiness > 0 {
		// X′′
		s.ExecuteNextPendingInstr(instructionIndex)
		return
	}

	// if ı(n) = ∅ ∧ |s⃗(n)| = 0
	if s.instructionCounter == nil && len(s.scheduledInstructions) == 0 {
		// TODO set the gas for block ϱ∆_ı = max(c(m) − 3, 1) (eq. A.51)
		return
	}

	// otherwise X′′′
	s.SimulateVirtualCPU(instructionIndex)
}

// ReorderBuffer X′
func (s *SimulationState) ReorderBuffer(instructionIndex uint64) {
	if s.opcode(*s.instructionCounter) == MoveReg {
		s.ReorderBufferMov(instructionIndex)
		return
	}

	s.ReorderBufferDecode(instructionIndex)
}

// ReorderBufferMov move_reg instruction is special-cased to be handled by the frontend of our virtual CPU, without being added to
// the reorder buffer: X^mov
func (s *SimulationState) ReorderBufferMov(instructionIndex uint64) {

	// we know that move instruction has only 2 registers
	dstReg, srcReg := s.decodeArgsReg2(*s.instructionCounter)

	// ı(n+1) = ı(n) + 1 + skip(ı(n))
	*s.instructionCounter += uint64(1 + s.skip(*s.instructionCounter))

	// d(n+1) = d(n) − 1
	s.decodingSlots -= 1

	//					⎧ r⃗(n)_j ∪ rˇ(c,k,ı(n)) if⃗ r⃗(n)_j ∩ sˇ(c,k,ı(n)) ≠ ∅
	// j ∈ N ⇒ r⃗(n+1)_j ⎨
	//					⎩ r(n)_j ∖ rˇ(c,k,ı(n)) otherwise
	//
	// if destination reg is the sane as source reg add to the resources list, if not remove it
	for j := range s.regs {
		if dstReg == srcReg {
			if s.regs[dstReg] == nil {
				s.regs[dstReg] = make(map[Reg]struct{})
			}
			s.regs[j][dstReg] = struct{}{}
		} else {
			delete(s.regs[j], dstReg)
		}
	}
}

// ReorderBufferDecode X^decode (eq. A.54)
func (s *SimulationState) ReorderBufferDecode(instructionIndex uint64) {
	s.computeCostsAndRegs(*s.instructionCounter)
	if s.opcode(*s.instructionCounter).IsBasicBlockTermination() { // // if opcode(c,k,ı(n)) ∈ T
		// ı(n+1) = ∅
		s.instructionCounter = nil
	} else { // otherwise
		// ı(n+1) = ı(n) + 1 + skip(ı(n))
		*s.instructionCounter += 1 + uint64(s.skip(*s.instructionCounter))
	}

	// d(n+1) = d(n) − dˇ(c,k,ı(n))
	s.decodingSlots -= uint64(s.decodeCost)

	// s⃗(n+1)_n(n) = 1
	*s.scheduledInstructions[s.instructionIndex] = 1

	// n(n+1) = n(n) + 1
	s.instructionIndex += 1

	// c⃗(n+1)_n(n) = cˇ(c,k,ı(n))
	s.instructionCost[s.instructionIndex] = uint64(s.instrCost)

	// x⃗(n+1)_n(n) = xˇ(c,k,ı(n))
	s.instructionExecution[s.instructionIndex] = s.executionCost

	// p(n+1)_n(n) = { j ∣ sˇ(c,k,ı(n)) ∩ r⃗(n)_j ≠ ∅ }
	for j := range s.regs {
		if s.srcRegs.overlapsWith(s.regs[j]) {
			s.portAvailability[s.instructionIndex] = append(s.portAvailability[s.instructionIndex], j)
		}
	}

	//					⎧ rˇ(c,k,ı(n)) 			if j = n(n)
	// j ∈ N ⇒ r⃗(n+1)_j ⎨
	//					⎩ r⃗(n)_j ∖ rˇ(c,k,ı(n)) otherwise
	s.regs[s.instructionIndex] = s.dstRegs
	for j := range s.regs {
		if j != s.instructionIndex {
			maps.DeleteFunc(s.regs[j], func(reg Reg, _ struct{}) bool {
				_, ok := s.dstRegs[reg]
				return ok
			})
		}
	}
}

// X′′
func (s *SimulationState) ExecuteNextPendingInstr(instructionIndex uint64) {
	readyInstrIndex, ok := s.readyForExecution(instructionIndex)
	if !ok {
		return // TODO
	}

	// s⃗(n+1)_S(Xn ) = 3
	*s.scheduledInstructions[readyInstrIndex] = 3

	// x(n+1) = x(n) − x⃗(n)_S(Xn)
	s.execution.sub(s.instructionExecution[readyInstrIndex])

	// e(n+1) = e(n) −1
	s.executionReadiness -= 1
}

// SimulateVirtualCPU X′′′
func (s *SimulationState) SimulateVirtualCPU(instructionIndex uint64) {
	if len(s.scheduledInstructions) != len(s.instructionCost) || len(s.scheduledInstructions) != len(s.instructionExecution) {
		panic("s, c and x must be the same length")
	}

	// 						⎧ ∅ 		if ∀ k ∈ N, 0 ≤ k ≤ j ⇒ s⃗(n)_k = 4
	// 						⎪ 2 		if s⃗(n)_j = 1
	// j ∈ N ⇒ s⃗(n+1)_j = 	⎨
	// 						⎪ 4 		if s⃗(n)_j= 3 ∧ c⃗(n)_j = 0
	//						⎩ s⃗(n)_j 	otherwise
	for j := range s.scheduledInstructions {
		isFull := true
		for k := range s.scheduledInstructions[:j+1] {
			if s.scheduledInstructions[j] != nil && *s.scheduledInstructions[k] != 4 {
				isFull = false
				break
			}
		}
		if isFull {
			s.scheduledInstructions[j] = nil
		} else if s.scheduledInstructions[j] != nil && *s.scheduledInstructions[j] == 1 {
			*s.scheduledInstructions[j] = 2
		} else if s.scheduledInstructions[j] != nil && *s.scheduledInstructions[j] == 3 && s.instructionCost[j] == 0 {
			*s.scheduledInstructions[j] = 4
		}
	}

	// 						⎧ c⃗(n)_j - 1 	if s⃗(n)_j = 3
	// j ∈ N ⇒ c⃗(n+1)_j = 	⎨
	// 						⎩ c⃗(n)_j 		otherwise
	for j := range s.instructionCost {
		if *s.scheduledInstructions[j] == 3 {
			s.instructionCost[j] -= 1
		}
	}
	//						⎧ ∅ 		if s⃗(n)_j = 3 ∧ c⃗(n)_j = 1
	// j ∈ N ⇒ r⃗(n+1)_j = 	⎨
	//						⎩ r⃗(n)_j 	otherwise
	for j := range s.regs {
		if s.scheduledInstructions[j] != nil && *s.scheduledInstructions[j] == 3 && s.instructionCost[j] == 1 {
			s.regs[j] = nil
		}
	}

	// x(n+1) = x(n) + [j∈N⇒s⃗(n)_j=3∧c⃗(n)_j=1]∑(x⃗(n)_j)
	for j := range s.scheduledInstructions {
		if s.scheduledInstructions[j] != nil && *s.scheduledInstructions[j] == 3 && s.instructionCost[j] == 1 {
			s.execution.add(s.instructionExecution[j])
		}
	}

	// c(n+1) = c(n) + 1
	s.cost += 1

	// d(n+1) = 4
	s.decodingSlots = 4

	// e(n+1) = 5
	s.executionReadiness = 5
}

// S(Xn) = min(j ∈ N ∣ s⃗(n)_j = 2 ∧ x⃗(n)_j ≤ 9 x(n) ∧ (∀k ∈ p⃗(n)_j ⇒ c⃗(n) k ≤ 0))
// The state transition function X′′′ n+1 which simulates the rest of the virtual CPU pipeline is d
func (s *SimulationState) readyForExecution(n uint64) (uint64, bool) {
	for j := uint64(0); j < n; j++ {

		// s⃗(n)_j = 2 (ready state)
		if s.scheduledInstructions[j] != nil && *s.scheduledInstructions[j] != 2 {
			continue
		}

		// x⃗(n)_j ≤ x(n)  (enough execution units)
		if s.instructionExecution[j].greaterThan(s.execution) {
			continue
		}

		// ∀k ∈ p⃗(n)_j : c⃗(n)_k ≤ 0  (all dependencies finished)
		ready := true
		for _, k := range s.portAvailability[j] {
			if s.instructionCost[k] > 0 {
				ready = false
				break
			}
		}

		if ready {
			return j, true // min j ∈ N
		}
	}

	return 0, false // no executable instruction
}

// P
func (s *SimulationState) regsOverlaps(a, b uint8) uint8 {
	if s.dstRegs.overlapsWith(s.srcRegs) {
		return a
	}
	return b
}

// overlapsFirstSrcReg PS
func (s *SimulationState) overlapsFirstSrcReg(instructionCounter uint64, a, b uint8) uint8 {
	regDst, regA, _ := s.decodeArgsReg3(instructionCounter)
	if regDst == regA {
		return a
	}
	return b
}

// b
func (s *SimulationState) branchCost(instructionCounter uint64) uint8 {
	currentSkip := s.skip(instructionCounter)
	_, _, valueX := s.decodeArgsReg2Offset(instructionCounter, currentSkip)
	switch Opcode(s.code[instructionCounter+1+uint64(currentSkip)]) {
	case Trap, Unlikely:
		return 1
	}
	switch Opcode(s.code[valueX]) {
	case Trap, Unlikely:
		return 1
	}

	return 20
}

// b
func (s *SimulationState) branchCostImm(instructionCounter uint64) uint8 {
	currentSkip := s.skip(instructionCounter)
	_, _, valueY := s.decodeArgsRegImmOffset(instructionCounter, currentSkip)
	switch Opcode(s.code[instructionCounter+1+uint64(currentSkip)]) {
	case Trap, Unlikely:
		return 1
	}
	switch Opcode(s.code[valueY]) {
	case Trap, Unlikely:
		return 1
	}

	return 20
}

func (s *SimulationState) computeCostsAndRegs(instructionCounter uint64) {
	switch s.opcode(instructionCounter) {
	case MoveReg:
		dstReg, regA := s.decodeArgsReg2(*s.instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 0, 1, execResources{0, 0, 0, 0, 0} // move_reg 0 1 0 0 0 0 0
	case And:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // and 1 P(1,2) 1 0 0 0 0
	case Xor:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // xor 1 P(1,2) 1 0 0 0 0
	case Or:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // or 1 P(1,2) 1 0 0 0 0
	case Add64:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // add_64 1 P(1,2) 1 0 0 0 0
	case Sub64:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // sub_64 1 P(1,2) 1 0 0 0 0
	case Add32:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // add_32 2 P(2,3) 1 0 0 0 0
	case Sub32:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // sub_32 2 P(2,3) 1 0 0 0 0
	case AndImm:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // and_imm 1 P(1,2) 1 0 0 0 0
	case XorImm:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // xor_imm 1 P(1,2) 1 0 0 0 0
	case OrImm:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // or_imm 1 P(1,2) 1 0 0 0 0
	case AddImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // add_imm_64 1 P(1,2) 1 0 0 0 0
	case ShloRImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // shlo_r_imm_64 1 P(1,2) 1 0 0 0 0
	case SharRImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // shar_r_imm_64 1 P(1,2) 1 0 0 0 0
	case ShloLImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // shlo_l_imm_64 1 P(1,2) 1 0 0 0 0
	case RotR64Imm:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // rot_r_64_imm 1 P(1,2) 1 0 0 0 0
	case ReverseBytes:
		dstReg, regA := s.decodeArgsReg2(*s.instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // reverse_bytes 1 P(1,2) 1 0 0 0 0
	case AddImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // add_imm_32 2 P(2,3) 1 0 0 0 0
	case ShloRImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // shlo_r_imm_32 2 P(2,3) 1 0 0 0 0
	case SharRImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // shar_r_imm_32 2 P(2,3) 1 0 0 0 0
	case ShloLImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // shlo_l_imm_32 2 P(2,3) 1 0 0 0 0
	case RotR32Imm:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // rot_r_32_imm 2 P(2,3) 1 0 0 0 0
	case CountSetBits64:
		dstReg, regA := s.decodeArgsReg2(*s.instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{1, 0, 0, 0, 0} // count_set_bits_64 1 1 1 0 0 0 0
	case CountSetBits32:
		dstReg, regA := s.decodeArgsReg2(*s.instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{1, 0, 0, 0, 0} // count_set_bits_32 1 1 1 0 0 0 0
	case LeadingZeroBits64:
		dstReg, regA := s.decodeArgsReg2(*s.instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{1, 0, 0, 0, 0} // leading_zero_bits_64 1 1 1 0 0 0 0
	case LeadingZeroBits32:
		dstReg, regA := s.decodeArgsReg2(*s.instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{1, 0, 0, 0, 0} // leading_zero_bits_32 1 1 1 0 0 0 0
	case SignExtend8:
		dstReg, regA := s.decodeArgsReg2(*s.instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{1, 0, 0, 0, 0} // sign_extend_8 1 1 1 0 0 0 0
	case SignExtend16:
		dstReg, regA := s.decodeArgsReg2(*s.instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{1, 0, 0, 0, 0} // sign_extend_16 1 1 1 0 0 0 0
	case ZeroExtend16:
		dstReg, regA := s.decodeArgsReg2(*s.instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{1, 0, 0, 0, 0} // zero_extend_16 1 1 1 0 0 0 0
	case TrailingZeroBits64:
		dstReg, regA := s.decodeArgsReg2(*s.instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 1, execResources{2, 0, 0, 0, 0} // trailing_zero_bits_64 2 1 2 0 0 0 0
	case TrailingZeroBits32:
		dstReg, regA := s.decodeArgsReg2(*s.instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 1, execResources{2, 0, 0, 0, 0} // trailing_zero_bits_32 2 1 2 0 0 0 0
	case ShloL64:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // shlo_l_64 1 PS (2,3) 1 0 0 0 0
	case ShloR64:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // shlo_r_64 1 PS (2,3) 1 0 0 0 0
	case SharR64:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // shar_r_64 1 PS (2,3) 1 0 0 0 0
	case RotL64:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // rot_l_64 1 PS (2,3) 1 0 0 0 0
	case RotR64:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // rot_r_64 1 PS (2,3) 1 0 0 0 0
	case ShloL32:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // shlo_l_32 2 PS (3,4) 1 0 0 0 0
	case ShloR32:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // shlo_r_32 2 PS (3,4) 1 0 0 0 0
	case SharR32:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // shar_r_32 2 PS (3,4) 1 0 0 0 0
	case RotL32:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // rot_l_32 2 PS (3,4) 1 0 0 0 0
	case RotR32:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // rot_r_32 2 PS (3,4) 1 0 0 0 0
	case ShloLImmAlt64:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 3, execResources{1, 0, 0, 0, 0} // shlo_l_imm_alt_64 1 3 1 0 0 0 0
	case ShloRImmAlt64:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 3, execResources{1, 0, 0, 0, 0} // shlo_r_imm_alt_64 1 3 1 0 0 0 0
	case SharRImmAlt64:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 3, execResources{1, 0, 0, 0, 0} // shar_r_imm_alt_64 1 3 1 0 0 0 0
	case RotR64ImmAlt:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 3, execResources{1, 0, 0, 0, 0} // rot_r_64_imm_alt 1 3 1 0 0 0 0
	case ShloLImmAlt32:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 4, execResources{1, 0, 0, 0, 0} // shlo_l_imm_alt_32 2 4 1 0 0 0 0
	case ShloRImmAlt32:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 4, execResources{1, 0, 0, 0, 0} // shlo_r_imm_alt_32 2 4 1 0 0 0 0
	case SharRImmAlt32:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 4, execResources{1, 0, 0, 0, 0} // shar_r_imm_alt_32 2 4 1 0 0 0 0
	case RotR32ImmAlt:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 4, execResources{1, 0, 0, 0, 0} // rot_r_32_imm_alt 2 4 1 0 0 0 0
	case SetLtU:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, 3, execResources{1, 0, 0, 0, 0} // set_lt_u 3 3 1 0 0 0 0
	case SetLtS:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, 3, execResources{1, 0, 0, 0, 0} // set_lt_s 3 3 1 0 0 0 0
	case SetLtUImm:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, 3, execResources{1, 0, 0, 0, 0} // set_lt_u_imm 3 3 1 0 0 0 0
	case SetLtSImm:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, 3, execResources{1, 0, 0, 0, 0} // set_lt_s_imm 3 3 1 0 0 0 0
	case SetGtUImm:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, 3, execResources{1, 0, 0, 0, 0} // set_gt_u_imm 3 3 1 0 0 0 0
	case SetGtSImm:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, 3, execResources{1, 0, 0, 0, 0} // set_gt_s_imm 3 3 1 0 0 0 0
	case CmovIz:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 2, execResources{1, 0, 0, 0, 0} // cmov_iz 2 2 1 0 0 0 0
	case CmovNz:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 2, execResources{1, 0, 0, 0, 0} // cmov_nz 2 2 1 0 0 0 0
	case CmovIzImm:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 3, execResources{1, 0, 0, 0, 0} // cmov_iz_imm 2 3 1 0 0 0 0
	case CmovNzImm:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 3, execResources{1, 0, 0, 0, 0} // cmov_nz_imm 2 3 1 0 0 0 0
	case Max:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // max 3 P(2,3) 1 0 0 0 0
	case MaxU:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // max_u 3 P(2,3) 1 0 0 0 0
	case Min:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // min 3 P(2,3) 1 0 0 0 0
	case MinU:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // min_u 3 P(2,3) 1 0 0 0 0
	case LoadIndU8:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_u8 m 1 1 1 0 0 0
	case LoadIndI8:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_i8 m 1 1 1 0 0 0
	case LoadIndU16:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_u16 m 1 1 1 0 0 0
	case LoadIndI16:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_i16 m 1 1 1 0 0 0
	case LoadIndU32:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_u32 m 1 1 1 0 0 0
	case LoadIndI32:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_i32 m 1 1 1 0 0 0
	case LoadIndU64:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_u64 m 1 1 1 0 0 0
	case LoadU8:
		regA, _ := s.decodeArgsRegImm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_u8 m 1 1 1 0 0 0
	case LoadI8:
		regA, _ := s.decodeArgsRegImm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_i8 m 1 1 1 0 0 0
	case LoadU16:
		regA, _ := s.decodeArgsRegImm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_u16 m 1 1 1 0 0 0
	case LoadI16:
		regA, _ := s.decodeArgsRegImm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_i16 m 1 1 1 0 0 0
	case LoadU32:
		regA, _ := s.decodeArgsRegImm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_u32 m 1 1 1 0 0 0
	case LoadI32:
		regA, _ := s.decodeArgsRegImm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_i32 m 1 1 1 0 0 0
	case LoadU64:
		regA, _ := s.decodeArgsRegImm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_u64 m 1 1 1 0 0 0
	case StoreImmIndU8:
		s.decodeArgsRegImm2(*s.instructionCounter, s.skipLen)
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_ind_u8 25 1 1 0 1 0 0
	case StoreImmIndU16:
		s.decodeArgsRegImm2(*s.instructionCounter, s.skipLen)
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_ind_u16 25 1 1 0 1 0 0
	case StoreImmIndU32:
		s.decodeArgsRegImm2(*s.instructionCounter, s.skipLen)
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_ind_u32 25 1 1 0 1 0 0
	case StoreImmIndU64:
		s.decodeArgsRegImm2(*s.instructionCounter, s.skipLen)
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_ind_u64 25 1 1 0 1 0 0
	case StoreIndU8:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_ind_u8 25 1 1 0 1 0 0
	case StoreIndU16:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_ind_u16 25 1 1 0 1 0 0
	case StoreIndU32:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_ind_u32 25 1 1 0 1 0 0
	case StoreIndU64:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_ind_u64 25 1 1 0 1 0 0
	case StoreImmU8:
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_u8 25 1 1 0 1 0 0
	case StoreImmU16:
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_u16 25 1 1 0 1 0 0
	case StoreImmU32:
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_u32 25 1 1 0 1 0 0
	case StoreImmU64:
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_u64 25 1 1 0 1 0 0
	case StoreU8:
		regA, _ := s.decodeArgsRegImm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_u8 25 1 1 0 1 0 0
	case StoreU16:
		regA, _ := s.decodeArgsRegImm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_u16 25 1 1 0 1 0 0
	case StoreU32:
		regA, _ := s.decodeArgsRegImm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_u32 25 1 1 0 1 0 0
	case StoreU64:
		regA, _ := s.decodeArgsRegImm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_u64 25 1 1 0 1 0 0
	case BranchEq:
		regA, regB, _ := s.decodeArgsReg2Offset(*s.instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_eq b 1 1 0 0 0 0
	case BranchNe:
		regA, regB, _ := s.decodeArgsReg2Offset(*s.instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ne b 1 1 0 0 0 0
	case BranchLtU:
		regA, regB, _ := s.decodeArgsReg2Offset(*s.instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_lt_u b 1 1 0 0 0 0
	case BranchLtS:
		regA, regB, _ := s.decodeArgsReg2Offset(*s.instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_lt_s b 1 1 0 0 0 0
	case BranchGeU:
		regA, regB, _ := s.decodeArgsReg2Offset(*s.instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ge_u b 1 1 0 0 0 0
	case BranchGeS:
		regA, regB, _ := s.decodeArgsReg2Offset(*s.instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ge_s b 1 1 0 0 0 0
	case BranchEqImm:
		regA, _, _ := s.decodeArgsRegImmOffset(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_eq_imm b 1 1 0 0 0 0
	case BranchNeImm:
		regA, _, _ := s.decodeArgsRegImmOffset(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ne_imm b 1 1 0 0 0 0
	case BranchLtUImm:
		regA, _, _ := s.decodeArgsRegImmOffset(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_lt_u_imm b 1 1 0 0 0 0
	case BranchLeUImm:
		regA, _, _ := s.decodeArgsRegImmOffset(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_le_u_imm b 1 1 0 0 0 0
	case BranchGeUImm:
		regA, _, _ := s.decodeArgsRegImmOffset(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ge_u_imm b 1 1 0 0 0 0
	case BranchGtUImm:
		regA, _, _ := s.decodeArgsRegImmOffset(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_gt_u_imm b 1 1 0 0 0 0
	case BranchLtSImm:
		regA, _, _ := s.decodeArgsRegImmOffset(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_lt_s_imm b 1 1 0 0 0 0
	case BranchLeSImm:
		regA, _, _ := s.decodeArgsRegImmOffset(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_le_s_imm b 1 1 0 0 0 0
	case BranchGeSImm:
		regA, _, _ := s.decodeArgsRegImmOffset(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ge_s_imm b 1 1 0 0 0 0
	case BranchGtSImm:
		regA, _, _ := s.decodeArgsRegImmOffset(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_gt_s_imm b 1 1 0 0 0 0
	case DivU32:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // div_u_32 60 4 1 0 0 0 1
	case DivS32:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // div_s_32 60 4 1 0 0 0 1
	case RemU32:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // rem_u_32 60 4 1 0 0 0 1
	case RemS32:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // rem_s_32 60 4 1 0 0 0 1
	case DivU64:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // div_u_64 60 4 1 0 0 0 1
	case DivS64:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // div_s_64 60 4 1 0 0 0 1
	case RemU64:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // rem_u_64 60 4 1 0 0 0 1
	case RemS64:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // rem_s_64 60 4 1 0 0 0 1
	case AndInv:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 3, execResources{1, 0, 0, 0, 0} // and_inv 2 3 1 0 0 0 0
	case OrInv:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 3, execResources{1, 0, 0, 0, 0} // or_inv 2 3 1 0 0 0 0
	case Xnor:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // xnor 2 P(2,3) 1 0 0 0 0
	case NegAddImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 3, execResources{1, 0, 0, 0, 0} // neg_add_imm_64 2 3 1 0 0 0 0
	case NegAddImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, 4, execResources{1, 0, 0, 0, 0} // neg_add_imm_32 3 4 1 0 0 0 0
	case LoadImm:
		regA, _ := s.decodeArgsRegImm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{0, 0, 0, 0, 0} // load_imm 1 1 0 0 0 0 0
	case LoadImm64:
		regA, _ := s.decodeArgsRegImmExt(*s.instructionCounter)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 2, execResources{0, 0, 0, 0, 0} // load_imm_64 1 2 0 0 0 0 0
	case Mul64:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, s.regsOverlaps(1, 2), execResources{1, 0, 0, 1, 0} // mul_64 3 P(1,2) 1 0 0 1 0
	case Mul32:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 4, s.regsOverlaps(2, 3), execResources{1, 0, 0, 1, 0} // mul_32 4 P(2,3) 1 0 0 1 0
	case MulImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, s.regsOverlaps(1, 2), execResources{1, 0, 0, 1, 0} // mul_imm_64 3 P(1,2) 1 0 0 1 0
	case MulImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 4, s.regsOverlaps(2, 3), execResources{1, 0, 0, 1, 0} // mul_imm_32 4 P(2,3) 1 0 0 1 0
	case MulUpperSS:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 4, 4, execResources{1, 0, 0, 1, 0} // mul_upper_s_s 4 4 1 0 0 1 0
	case MulUpperUU:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 4, 4, execResources{1, 0, 0, 1, 0} // mul_upper_u_u 4 4 1 0 0 1 0
	case MulUpperSU:
		regDst, regA, regB := s.decodeArgsReg3(*s.instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 6, 4, execResources{1, 0, 0, 1, 0} // mul_upper_s_u 6 4 1 0 0 1 0
	case Trap:
		s.instrCost, s.decodeCost, s.executionCost = 2, 1, execResources{0, 0, 0, 0, 0} // trap 2 1 0 0 0 0 0
	case Fallthrough:
		s.instrCost, s.decodeCost, s.executionCost = 2, 1, execResources{0, 0, 0, 0, 0} // fallthrough 2 1 0 0 0 0 0
	case Unlikely:
		s.instrCost, s.decodeCost, s.executionCost = 40, 1, execResources{0, 0, 0, 0, 0} // unlikely 40 1 0 0 0 0 0
	case Jump:
		s.instrCost, s.decodeCost, s.executionCost = 15, 1, execResources{0, 0, 0, 0, 0} // jump 15 1 0 0 0 0 0
	case LoadImmJump:
		regA, _, _ := s.decodeArgsRegImmOffset(*s.instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 15, 1, execResources{0, 0, 0, 0, 0} // load_imm_jump 15 1 0 0 0 0 0
	case JumpInd:
		regA, _ := s.decodeArgsRegImm(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 22, 1, execResources{0, 0, 0, 0, 0} // jump_ind 22 1 0 0 0 0 0
	case LoadImmJumpInd:
		regA, regB, _, _ := s.decodeArgsReg2Imm2(*s.instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 22, 1, execResources{0, 0, 0, 0, 0} // load_imm_jump_ind 22 1 0 0 0 0 0
	case Ecalli:
		s.instrCost, s.decodeCost, s.executionCost = 100, 4, execResources{1, 0, 0, 0, 0} // ecalli 100 4 1 0 0 0 0
	}
	panic("unable to get cost for instruction")
}

// Decode costs
const (
	// m
	memoryAccessCost = 25 // m = 25
)
