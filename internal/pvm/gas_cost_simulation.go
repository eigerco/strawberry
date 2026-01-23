package pvm

import (
	"maps"
)

type simulationProgram struct {
	*program

	skipLen       uint8
	srcRegs       regsSet       // ˇs(c,k,ı) - a set of source registers read by a given instruction
	dstRegs       regsSet       // ˇr(c,k,ı) - a set of destination registers which are written by a given instruction
	instrCost     uint8         // ˇc
	decodeCost    uint8         // ˇd
	executionCost execResources // ˇx
}

type simulationState struct {
	instructionCounter *uint64 // i
	cost               Gas     // c
	instructionIndex   int     // n
	decodingSlots      uint64  // d
	executionReadiness uint64  // e

	scheduledInstructions []uint64        // s⃗
	instructionCost       []uint64        // c⃗
	portAvailability      [][]int         // p⃗
	regs                  []regsSet       // r⃗
	instructionExecution  []execResources // x⃗

	execution execResources // x
}

func newSimulationState(instructionCounter uint64) simulationState {
	return simulationState{
		instructionCounter:    &instructionCounter,
		cost:                  0,
		instructionIndex:      0,
		decodingSlots:         4,
		executionReadiness:    5,
		scheduledInstructions: []uint64{},
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
	}
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
	return e.ALU > another.ALU ||
		e.Load > another.Load ||
		e.Store > another.Store ||
		e.Mul > another.Mul ||
		e.Div > another.Div
}

func newSimulationProgram(program *program) *simulationProgram {
	return &simulationProgram{program: program}
}

func calculateBasicBlockCosts(p *program, basicBlockInstructions map[uint64]struct{}) map[uint64]Gas {
	basicBlockCosts := map[uint64]Gas{}
	simulation := newSimulationProgram(p)
	for instructionCounter := range basicBlockInstructions {
		state := newSimulationState(instructionCounter)

		for n := uint64(0); ; n++ {
			nextState, ok := simulation.transition(state, n)
			if !ok {
				basicBlockCosts[instructionCounter] = state.cost
				break
			}
			state = nextState
		}
	}
	return basicBlockCosts
}

func (s *simulationProgram) transition(state simulationState, instructionIndex uint64) (simulationState, bool) {
	// if ı(n) = ∅ ∧ |s⃗(n)| = 0
	if state.instructionCounter == nil {
		if len(state.scheduledInstructions) == 0 {
			return simulationState{}, false
		}

		return s.SimulateVirtualCPU(state, instructionIndex), true
	}

	s.skipLen = s.program.skip(*state.instructionCounter)
	s.computeCostsAndRegs(*state.instructionCounter)

	// if n = 0 ∨ (ı(n) ≠ ∅ ∧ dˇ(c,k,ı(n)) ≤ d(n) ∧ ∣ s⃗(n)∣ < 32)
	if instructionIndex == 0 || (state.instructionCounter != nil && uint64(s.decodeCost) <= state.decodingSlots && len(state.scheduledInstructions) < 32) {
		// X′
		return s.ReorderBuffer(state, instructionIndex), true
	}

	// if S(Xn) ≠ ∅ ∧ e(n) > 0
	if _, ok := readyForExecution(&state, instructionIndex); ok && state.executionReadiness > 0 {
		// X′′
		return s.ExecuteNextPendingInstr(state, instructionIndex), true
	}

	// otherwise X′′′
	return s.SimulateVirtualCPU(state, instructionIndex), true
}

// ReorderBuffer X′
func (s *simulationProgram) ReorderBuffer(state simulationState, instructionIndex uint64) simulationState {
	if s.opcode(*state.instructionCounter) == MoveReg {
		return s.ReorderBufferMov(state, instructionIndex)
	}

	return s.ReorderBufferDecode(state, instructionIndex)
}

// ReorderBufferMov move_reg instruction is special-cased to be handled by the frontend of our virtual CPU, without being added to
// the reorder buffer: X^mov
func (s *simulationProgram) ReorderBufferMov(state simulationState, instructionIndex uint64) simulationState {
	// ı(n+1) = ı(n) + 1 + skip(ı(n))
	newInstructionCounter := *state.instructionCounter + uint64(1+s.skip(*state.instructionCounter))

	// d(n+1) = d(n) − 1
	state.decodingSlots -= 1

	//					⎧ r⃗(n)_j ∪ rˇ(c,k,ı(n)) if⃗ r⃗(n)_j ∩ sˇ(c,k,ı(n)) ≠ ∅
	// j ∈ N ⇒ r⃗(n+1)_j ⎨
	//					⎩ r(n)_j ∖ rˇ(c,k,ı(n)) otherwise
	//
	// if destination reg is the same as source reg add to the resources list, if not remove it
	for j := range state.regs {
		if s.srcRegs.overlapsWith(s.srcRegs) {
			if state.regs[j] == nil {
				state.regs[j] = make(map[Reg]struct{})
			}
			for dstReg := range s.dstRegs {
				state.regs[j][dstReg] = struct{}{}
			}
		} else {
			for dstReg := range s.dstRegs {
				delete(state.regs[j], dstReg)
			}
		}
	}
	newState := state
	newState.instructionCounter = &newInstructionCounter
	return newState
}

// ReorderBufferDecode X^decode (eq. A.54)
func (s *simulationProgram) ReorderBufferDecode(state simulationState, instructionIndex uint64) simulationState {
	s.computeCostsAndRegs(*state.instructionCounter)
	if s.opcode(*state.instructionCounter).IsBasicBlockTermination() { // if opcode(c,k,ı(n)) ∈ T
		// ı(n+1) = ∅
		state.instructionCounter = nil
	} else { // otherwise
		// ı(n+1) = ı(n) + 1 + skip(ı(n))
		*state.instructionCounter += 1 + uint64(s.skip(*state.instructionCounter))
	}

	// TODO
	state.scheduledInstructions,
		state.instructionCost,
		state.instructionExecution,
		state.portAvailability,
		state.regs =
		make([]uint64, state.instructionIndex+1), make([]uint64, state.instructionIndex+1),
		make([]execResources, state.instructionIndex+1), make([][]int, state.instructionIndex+1),
		make([]regsSet, state.instructionIndex+1)

	// d(n+1) = d(n) − dˇ(c,k,ı(n))
	state.decodingSlots -= uint64(s.decodeCost)

	// s⃗(n+1)_n(n) = 1
	state.scheduledInstructions[state.instructionIndex] = 1

	// c⃗(n+1)_n(n) = cˇ(c,k,ı(n))
	state.instructionCost[state.instructionIndex] = uint64(s.instrCost)

	// x⃗(n+1)_n(n) = xˇ(c,k,ı(n))
	state.instructionExecution[state.instructionIndex] = s.executionCost

	// p(n+1)_n(n) = { j ∣ sˇ(c,k,ı(n)) ∩ r⃗(n)_j ≠ ∅ }
	for j := range state.regs {
		if s.srcRegs.overlapsWith(state.regs[j]) {
			state.portAvailability[state.instructionIndex] = append(state.portAvailability[state.instructionIndex], j)
		}
	}

	//					⎧ rˇ(c,k,ı(n)) 			if j = n(n)
	// j ∈ N ⇒ r⃗(n+1)_j ⎨
	//					⎩ r⃗(n)_j ∖ rˇ(c,k,ı(n)) otherwise
	state.regs[state.instructionIndex] = s.dstRegs
	for j := range state.regs {
		if j != state.instructionIndex {
			maps.DeleteFunc(state.regs[j], func(reg Reg, _ struct{}) bool {
				_, ok := s.dstRegs[reg]
				return ok
			})
		}
	}

	// n(n+1) = n(n) + 1
	state.instructionIndex += 1

	return state
}

// ExecuteNextPendingInstr X′′
func (s *simulationProgram) ExecuteNextPendingInstr(state simulationState, instructionIndex uint64) simulationState {
	readyInstrIndex, ok := readyForExecution(&state, instructionIndex)
	if !ok {
		return state // TODO
	}

	// s⃗(n+1)_S(Xn ) = 3
	state.scheduledInstructions[readyInstrIndex] = 3

	// x(n+1) = x(n) − x⃗(n)_S(Xn)
	state.execution.sub(state.instructionExecution[readyInstrIndex])

	// e(n+1) = e(n) −1
	state.executionReadiness -= 1
	return state
}

// SimulateVirtualCPU the state transition function X′′′ n+1 which simulates the rest of the virtual CPU pipeline
func (s *simulationProgram) SimulateVirtualCPU(state simulationState, instructionIndex uint64) simulationState {
	if len(state.scheduledInstructions) != len(state.instructionCost) || len(state.scheduledInstructions) != len(state.instructionExecution) {
		panic("s, c and x must be the same length")
	}

	// 						⎧ c⃗(n)_j - 1 	if s⃗(n)_j = 3
	// j ∈ N ⇒ c⃗(n+1)_j = 	⎨
	// 						⎩ c⃗(n)_j 		otherwise
	for j := range state.instructionCost {
		if state.scheduledInstructions[j] == 3 {
			state.instructionCost[j] -= 1
		}
	}

	// 						⎧ ∅ 		if ∀ k ∈ N, 0 ≤ k ≤ j ⇒ s⃗(n)_k = 4
	// 						⎪ 2 		if s⃗(n)_j = 1
	// j ∈ N ⇒ s⃗(n+1)_j = 	⎨
	// 						⎪ 4 		if s⃗(n)_j= 3 ∧ c⃗(n)_j = 0
	//						⎩ s⃗(n)_j 	otherwise
	var newScheduledInstructions []uint64
	for j := range state.scheduledInstructions {
		isFull := true
		// are all scheduled instructions before j not 4
		for k := range state.scheduledInstructions[:j+1] {
			if state.scheduledInstructions[k] != 4 {
				isFull = false
				break
			}
		}
		if isFull {
		} else if state.scheduledInstructions[j] == 1 {
			newScheduledInstructions = append(newScheduledInstructions, 2)
		} else if state.scheduledInstructions[j] == 3 && state.instructionCost[j] == 0 {
			newScheduledInstructions = append(newScheduledInstructions, 4)
		} else {
			newScheduledInstructions = append(newScheduledInstructions, state.scheduledInstructions[j])
		}
	}

	state.scheduledInstructions = newScheduledInstructions

	//						⎧ ∅ 		if s⃗(n)_j = 3 ∧ c⃗(n)_j = 1
	// j ∈ N ⇒ r⃗(n+1)_j = 	⎨
	//						⎩ r⃗(n)_j 	otherwise
	for j := range state.regs {
		if state.scheduledInstructions[j] == 3 && state.instructionCost[j] == 1 {
			state.regs[j] = nil
		}
	}

	// x(n+1) = x(n) + [j∈N⇒s⃗(n)_j=3∧c⃗(n)_j=1]∑(x⃗(n)_j)
	for j := range state.scheduledInstructions {
		if state.scheduledInstructions[j] == 3 && state.instructionCost[j] == 1 {
			state.execution.add(state.instructionExecution[j])
		}
	}

	// c(n+1) = c(n) + 1
	state.cost += 1

	// d(n+1) = 4
	state.decodingSlots = 4

	// e(n+1) = 5
	state.executionReadiness = 5
	return state
}

// S(Xn) = min(j ∈ N ∣ s⃗(n)_j = 2 ∧ x⃗(n)_j ≤ 9 x(n) ∧ (∀k ∈ p⃗(n)_j ⇒ c⃗(n) k ≤ 0))
func readyForExecution(state *simulationState, n uint64) (uint64, bool) {
	for j := uint64(0); j < n; j++ {

		// s⃗(n)_j = 2 (ready state)
		if state.scheduledInstructions[j] != 2 {
			continue
		}

		// x⃗(n)_j ≤ x(n)  (enough execution units)
		if state.instructionExecution[j].greaterThan(state.execution) {
			continue
		}

		// ∀k ∈ p⃗(n)_j : c⃗(n)_k ≤ 0  (all dependencies finished)
		ready := true
		for _, k := range state.portAvailability[j] {
			if state.instructionCost[k] > 0 {
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
func (s *simulationProgram) regsOverlaps(a, b uint8) uint8 {
	if s.dstRegs.overlapsWith(s.srcRegs) {
		return a
	}
	return b
}

// overlapsFirstSrcReg PS
func (s *simulationProgram) overlapsFirstSrcReg(instructionCounter uint64, a, b uint8) uint8 {
	regDst, regA, _ := s.decodeArgsReg3(instructionCounter)
	if regDst == regA {
		return a
	}
	return b
}

// b
func (s *simulationProgram) branchCost(instructionCounter uint64) uint8 {
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
func (s *simulationProgram) branchCostImm(instructionCounter uint64) uint8 {
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

func (s *simulationProgram) computeCostsAndRegs(instructionCounter uint64) {
	s.dstRegs, s.srcRegs = nil, nil
	switch s.opcode(instructionCounter) {
	case MoveReg:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 0, 1, execResources{0, 0, 0, 0, 0} // move_reg 0 1 0 0 0 0 0
	case And:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // and 1 P(1,2) 1 0 0 0 0
	case Xor:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // xor 1 P(1,2) 1 0 0 0 0
	case Or:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // or 1 P(1,2) 1 0 0 0 0
	case Add64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // add_64 1 P(1,2) 1 0 0 0 0
	case Sub64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // sub_64 1 P(1,2) 1 0 0 0 0
	case Add32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // add_32 2 P(2,3) 1 0 0 0 0
	case Sub32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // sub_32 2 P(2,3) 1 0 0 0 0
	case AndImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // and_imm 1 P(1,2) 1 0 0 0 0
	case XorImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // xor_imm 1 P(1,2) 1 0 0 0 0
	case OrImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // or_imm 1 P(1,2) 1 0 0 0 0
	case AddImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // add_imm_64 1 P(1,2) 1 0 0 0 0
	case ShloRImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // shlo_r_imm_64 1 P(1,2) 1 0 0 0 0
	case SharRImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // shar_r_imm_64 1 P(1,2) 1 0 0 0 0
	case ShloLImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // shlo_l_imm_64 1 P(1,2) 1 0 0 0 0
	case RotR64Imm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // rot_r_64_imm 1 P(1,2) 1 0 0 0 0
	case ReverseBytes:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // reverse_bytes 1 P(1,2) 1 0 0 0 0
	case AddImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // add_imm_32 2 P(2,3) 1 0 0 0 0
	case ShloRImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // shlo_r_imm_32 2 P(2,3) 1 0 0 0 0
	case SharRImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // shar_r_imm_32 2 P(2,3) 1 0 0 0 0
	case ShloLImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // shlo_l_imm_32 2 P(2,3) 1 0 0 0 0
	case RotR32Imm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // rot_r_32_imm 2 P(2,3) 1 0 0 0 0
	case CountSetBits64:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{1, 0, 0, 0, 0} // count_set_bits_64 1 1 1 0 0 0 0
	case CountSetBits32:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{1, 0, 0, 0, 0} // count_set_bits_32 1 1 1 0 0 0 0
	case LeadingZeroBits64:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{1, 0, 0, 0, 0} // leading_zero_bits_64 1 1 1 0 0 0 0
	case LeadingZeroBits32:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{1, 0, 0, 0, 0} // leading_zero_bits_32 1 1 1 0 0 0 0
	case SignExtend8:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{1, 0, 0, 0, 0} // sign_extend_8 1 1 1 0 0 0 0
	case SignExtend16:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{1, 0, 0, 0, 0} // sign_extend_16 1 1 1 0 0 0 0
	case ZeroExtend16:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{1, 0, 0, 0, 0} // zero_extend_16 1 1 1 0 0 0 0
	case TrailingZeroBits64:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 1, execResources{2, 0, 0, 0, 0} // trailing_zero_bits_64 2 1 2 0 0 0 0
	case TrailingZeroBits32:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 1, execResources{2, 0, 0, 0, 0} // trailing_zero_bits_32 2 1 2 0 0 0 0
	case ShloL64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // shlo_l_64 1 PS (2,3) 1 0 0 0 0
	case ShloR64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // shlo_r_64 1 PS (2,3) 1 0 0 0 0
	case SharR64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // shar_r_64 1 PS (2,3) 1 0 0 0 0
	case RotL64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // rot_l_64 1 PS (2,3) 1 0 0 0 0
	case RotR64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // rot_r_64 1 PS (2,3) 1 0 0 0 0
	case ShloL32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // shlo_l_32 2 PS (3,4) 1 0 0 0 0
	case ShloR32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // shlo_r_32 2 PS (3,4) 1 0 0 0 0
	case SharR32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // shar_r_32 2 PS (3,4) 1 0 0 0 0
	case RotL32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // rot_l_32 2 PS (3,4) 1 0 0 0 0
	case RotR32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // rot_r_32 2 PS (3,4) 1 0 0 0 0
	case ShloLImmAlt64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 3, execResources{1, 0, 0, 0, 0} // shlo_l_imm_alt_64 1 3 1 0 0 0 0
	case ShloRImmAlt64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 3, execResources{1, 0, 0, 0, 0} // shlo_r_imm_alt_64 1 3 1 0 0 0 0
	case SharRImmAlt64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 3, execResources{1, 0, 0, 0, 0} // shar_r_imm_alt_64 1 3 1 0 0 0 0
	case RotR64ImmAlt:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 3, execResources{1, 0, 0, 0, 0} // rot_r_64_imm_alt 1 3 1 0 0 0 0
	case ShloLImmAlt32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 4, execResources{1, 0, 0, 0, 0} // shlo_l_imm_alt_32 2 4 1 0 0 0 0
	case ShloRImmAlt32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 4, execResources{1, 0, 0, 0, 0} // shlo_r_imm_alt_32 2 4 1 0 0 0 0
	case SharRImmAlt32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 4, execResources{1, 0, 0, 0, 0} // shar_r_imm_alt_32 2 4 1 0 0 0 0
	case RotR32ImmAlt:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 4, execResources{1, 0, 0, 0, 0} // rot_r_32_imm_alt 2 4 1 0 0 0 0
	case SetLtU:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, 3, execResources{1, 0, 0, 0, 0} // set_lt_u 3 3 1 0 0 0 0
	case SetLtS:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, 3, execResources{1, 0, 0, 0, 0} // set_lt_s 3 3 1 0 0 0 0
	case SetLtUImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, 3, execResources{1, 0, 0, 0, 0} // set_lt_u_imm 3 3 1 0 0 0 0
	case SetLtSImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, 3, execResources{1, 0, 0, 0, 0} // set_lt_s_imm 3 3 1 0 0 0 0
	case SetGtUImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, 3, execResources{1, 0, 0, 0, 0} // set_gt_u_imm 3 3 1 0 0 0 0
	case SetGtSImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, 3, execResources{1, 0, 0, 0, 0} // set_gt_s_imm 3 3 1 0 0 0 0
	case CmovIz:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 2, execResources{1, 0, 0, 0, 0} // cmov_iz 2 2 1 0 0 0 0
	case CmovNz:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 2, execResources{1, 0, 0, 0, 0} // cmov_nz 2 2 1 0 0 0 0
	case CmovIzImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 3, execResources{1, 0, 0, 0, 0} // cmov_iz_imm 2 3 1 0 0 0 0
	case CmovNzImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 3, execResources{1, 0, 0, 0, 0} // cmov_nz_imm 2 3 1 0 0 0 0
	case Max:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // max 3 P(2,3) 1 0 0 0 0
	case MaxU:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // max_u 3 P(2,3) 1 0 0 0 0
	case Min:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // min 3 P(2,3) 1 0 0 0 0
	case MinU:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // min_u 3 P(2,3) 1 0 0 0 0
	case LoadIndU8:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_u8 m 1 1 1 0 0 0
	case LoadIndI8:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_i8 m 1 1 1 0 0 0
	case LoadIndU16:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_u16 m 1 1 1 0 0 0
	case LoadIndI16:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_i16 m 1 1 1 0 0 0
	case LoadIndU32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_u32 m 1 1 1 0 0 0
	case LoadIndI32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_i32 m 1 1 1 0 0 0
	case LoadIndU64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_u64 m 1 1 1 0 0 0
	case LoadU8:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_u8 m 1 1 1 0 0 0
	case LoadI8:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_i8 m 1 1 1 0 0 0
	case LoadU16:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_u16 m 1 1 1 0 0 0
	case LoadI16:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_i16 m 1 1 1 0 0 0
	case LoadU32:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_u32 m 1 1 1 0 0 0
	case LoadI32:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_i32 m 1 1 1 0 0 0
	case LoadU64:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_u64 m 1 1 1 0 0 0
	case StoreImmIndU8:
		regA, _, _ := s.decodeArgsRegImm2(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_ind_u8 25 1 1 0 1 0 0
	case StoreImmIndU16:
		regA, _, _ := s.decodeArgsRegImm2(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_ind_u16 25 1 1 0 1 0 0
	case StoreImmIndU32:
		regA, _, _ := s.decodeArgsRegImm2(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_ind_u32 25 1 1 0 1 0 0
	case StoreImmIndU64:
		regA, _, _ := s.decodeArgsRegImm2(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_ind_u64 25 1 1 0 1 0 0
	case StoreIndU8:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_ind_u8 25 1 1 0 1 0 0
	case StoreIndU16:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_ind_u16 25 1 1 0 1 0 0
	case StoreIndU32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_ind_u32 25 1 1 0 1 0 0
	case StoreIndU64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
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
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_u8 25 1 1 0 1 0 0
	case StoreU16:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_u16 25 1 1 0 1 0 0
	case StoreU32:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_u32 25 1 1 0 1 0 0
	case StoreU64:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 25, 1, execResources{1, 0, 1, 0, 0} // store_u64 25 1 1 0 1 0 0
	case BranchEq:
		regA, regB, _ := s.decodeArgsReg2Offset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_eq b 1 1 0 0 0 0
	case BranchNe:
		regA, regB, _ := s.decodeArgsReg2Offset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ne b 1 1 0 0 0 0
	case BranchLtU:
		regA, regB, _ := s.decodeArgsReg2Offset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_lt_u b 1 1 0 0 0 0
	case BranchLtS:
		regA, regB, _ := s.decodeArgsReg2Offset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_lt_s b 1 1 0 0 0 0
	case BranchGeU:
		regA, regB, _ := s.decodeArgsReg2Offset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ge_u b 1 1 0 0 0 0
	case BranchGeS:
		regA, regB, _ := s.decodeArgsReg2Offset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ge_s b 1 1 0 0 0 0
	case BranchEqImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_eq_imm b 1 1 0 0 0 0
	case BranchNeImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ne_imm b 1 1 0 0 0 0
	case BranchLtUImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_lt_u_imm b 1 1 0 0 0 0
	case BranchLeUImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_le_u_imm b 1 1 0 0 0 0
	case BranchGeUImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ge_u_imm b 1 1 0 0 0 0
	case BranchGtUImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_gt_u_imm b 1 1 0 0 0 0
	case BranchLtSImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_lt_s_imm b 1 1 0 0 0 0
	case BranchLeSImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_le_s_imm b 1 1 0 0 0 0
	case BranchGeSImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ge_s_imm b 1 1 0 0 0 0
	case BranchGtSImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_gt_s_imm b 1 1 0 0 0 0
	case DivU32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // div_u_32 60 4 1 0 0 0 1
	case DivS32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // div_s_32 60 4 1 0 0 0 1
	case RemU32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // rem_u_32 60 4 1 0 0 0 1
	case RemS32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // rem_s_32 60 4 1 0 0 0 1
	case DivU64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // div_u_64 60 4 1 0 0 0 1
	case DivS64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // div_s_64 60 4 1 0 0 0 1
	case RemU64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // rem_u_64 60 4 1 0 0 0 1
	case RemS64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 60, 4, execResources{1, 0, 0, 0, 1} // rem_s_64 60 4 1 0 0 0 1
	case AndInv:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 3, execResources{1, 0, 0, 0, 0} // and_inv 2 3 1 0 0 0 0
	case OrInv:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 3, execResources{1, 0, 0, 0, 0} // or_inv 2 3 1 0 0 0 0
	case Xnor:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // xnor 2 P(2,3) 1 0 0 0 0
	case NegAddImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 2, 3, execResources{1, 0, 0, 0, 0} // neg_add_imm_64 2 3 1 0 0 0 0
	case NegAddImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, 4, execResources{1, 0, 0, 0, 0} // neg_add_imm_32 3 4 1 0 0 0 0
	case LoadImm:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 1, execResources{0, 0, 0, 0, 0} // load_imm 1 1 0 0 0 0 0
	case LoadImm64:
		regA, _ := s.decodeArgsRegImmExt(instructionCounter)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 1, 2, execResources{0, 0, 0, 0, 0} // load_imm_64 1 2 0 0 0 0 0
	case Mul64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, s.regsOverlaps(1, 2), execResources{1, 0, 0, 1, 0} // mul_64 3 P(1,2) 1 0 0 1 0
	case Mul32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 4, s.regsOverlaps(2, 3), execResources{1, 0, 0, 1, 0} // mul_32 4 P(2,3) 1 0 0 1 0
	case MulImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 3, s.regsOverlaps(1, 2), execResources{1, 0, 0, 1, 0} // mul_imm_64 3 P(1,2) 1 0 0 1 0
	case MulImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 4, s.regsOverlaps(2, 3), execResources{1, 0, 0, 1, 0} // mul_imm_32 4 P(2,3) 1 0 0 1 0
	case MulUpperSS:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 4, 4, execResources{1, 0, 0, 1, 0} // mul_upper_s_s 4 4 1 0 0 1 0
	case MulUpperUU:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 4, 4, execResources{1, 0, 0, 1, 0} // mul_upper_u_u 4 4 1 0 0 1 0
	case MulUpperSU:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
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
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 15, 1, execResources{0, 0, 0, 0, 0} // load_imm_jump 15 1 0 0 0 0 0
	case JumpInd:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.instrCost, s.decodeCost, s.executionCost = 22, 1, execResources{0, 0, 0, 0, 0} // jump_ind 22 1 0 0 0 0 0
	case LoadImmJumpInd:
		regA, regB, _, _ := s.decodeArgsReg2Imm2(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCost, s.decodeCost, s.executionCost = 22, 1, execResources{0, 0, 0, 0, 0} // load_imm_jump_ind 22 1 0 0 0 0 0
	case Ecalli:
		s.instrCost, s.decodeCost, s.executionCost = 100, 4, execResources{1, 0, 0, 0, 0} // ecalli 100 4 1 0 0 0 0
	default:
		panic("unable to get cost for instruction")
	}
}

// Decode costs
const (
	// m
	memoryAccessCost = 25 // m = 25
)
