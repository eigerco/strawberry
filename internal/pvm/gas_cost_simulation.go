package pvm

type simulationProgram struct {
	*program

	skipLen     uint8
	srcRegs     regsSet       // ˇs(c,k,ı) - a set of source registers read by a given instruction
	dstRegs     regsSet       // ˇr(c,k,ı) - a set of destination registers which are written by a given instruction
	instrCycles uint8         // ˇc
	decodeSlots uint8         // ˇd
	execUnits   execResources // ˇx
}

// S ≡ (ı ∈ { NR,∅ }, c ∈ N, d ∈ N,e ∈ N, t ∈ E, r ∈ ⟦R⟧)
type simulationState struct {
	instructionCounter *uint64              // ı
	cycleCounter       Gas                  // c
	decodeSlots        uint64               // d
	maxInstructions    uint64               // e
	remainingExecUnits execResources        // t
	reorderBuffer      []reorderBufferEntry // r
}

// R ≡ (s ∈ { DEC, WAIT, EXE, FIN, ∅ }, c ∈ N, p ⊆ N, r ⊆ N13, t ∈ E)
type reorderBufferEntry struct {
	status        currentState  // s
	cyclesLeft    uint8         // c
	dependencies  []int         // p
	registers     regsSet       // r
	usedExecUnits execResources // t
}

type currentState byte

const (
	NULL currentState = iota
	DEC
	WAIT
	EXE
	FIN
)

func newSimulationState(instructionCounter uint64) simulationState {
	return simulationState{
		instructionCounter: &instructionCounter,
		cycleCounter:       0,
		decodeSlots:        4,
		maxInstructions:    5,
		remainingExecUnits: execResources{
			ALU:   4,
			Load:  4,
			Store: 4,
			Mul:   1,
			Div:   1,
		},
		reorderBuffer: []reorderBufferEntry{},
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

// ∀a,b ∈ E; ∀ ⊕ ∈ { +,− } ∶ a ⊕ b ≡ c
// where ∀ k∈ { A,L,S,M,D } ∶ c_k ≡ a_k ⊕ b_k
func (e execResources) add(another execResources) execResources {
	return execResources{
		ALU:   e.ALU + another.ALU,
		Load:  e.Load + another.Load,
		Store: e.Store + another.Store,
		Mul:   e.Mul + another.Mul,
		Div:   e.Div + another.Div,
	}
}

func (e execResources) sub(another execResources) execResources {
	return execResources{
		ALU:   e.ALU - another.ALU,
		Load:  e.Load - another.Load,
		Store: e.Store - another.Store,
		Mul:   e.Mul - another.Mul,
		Div:   e.Div - another.Div,
	}
}

// ∀a,b ∈ E; ∀ ⊕ ∈ { <,>,≤,≥ } ∶ a ⊕ b ≡ ⋀[ k∈{ A,L,S,M,D } ] a_k ⊕ b_k
func (e execResources) greaterThan(another execResources) bool {
	return e.ALU > another.ALU &&
		e.Load > another.Load &&
		e.Store > another.Store &&
		e.Mul > another.Mul &&
		e.Div > another.Div
}

func buildGasCostsMap(p *program, basicBlockInstructions map[uint64]struct{}) map[uint64]Gas {
	gasCosts := make(map[uint64]Gas)
	sp := newSimulationProgram(p)
	for instructionCounter := range basicBlockInstructions {
		gasCosts[instructionCounter] = sp.gasCost(instructionCounter)
	}
	return gasCosts
}

func newSimulationProgram(program *program) *simulationProgram {
	return &simulationProgram{program: program}
}

// gasCost ϱ∆ (eq. A.54)
func (s *simulationProgram) gasCost(instructionCounter uint64) Gas {
	initState := newSimulationState(instructionCounter)

	finalState := s.simulate(initState)

	return max(finalState.cycleCounter-3, 1)
}

func (s *simulationProgram) simulate(state simulationState) simulationState {
	// l = |{ i | i ∈ N, x_r[i]s ≠ ∅ }|
	l := 0
	for _, rb := range state.reorderBuffer {
		if rb.status != NULL {
			l++
		}
	}

	// if x_ı ≠ ∅ ∧ dˇ(c,k,xı) ≤ x_d ∧ l < 32
	if state.instructionCounter != nil {
		s.skipLen = s.program.skip(*state.instructionCounter)
		s.computeCostsAndRegs(*state.instructionCounter)
		if uint64(s.decodeSlots) <= state.decodeSlots && l < 32 {
			// X′
			return s.simulate(s.decodeInstruction(state))
		}
	}

	// if S(Xn) ≠ ∅ ∧ e(n) > 0
	if _, ok := readyForExecution(state); ok && state.maxInstructions > 0 {
		// X′′
		return s.execNextPendingInstr(state)
	}

	// otherwise X′′′
	return s.simulateVirtualCPU(state)
}

// ReorderBuffer X′
func (s *simulationProgram) decodeInstruction(state simulationState) simulationState {
	if s.opcode(*state.instructionCounter) == MoveReg {
		return s.decodeMov(state)
	}

	return s.decodeAll(state)
}

// decodeMov move_reg instruction is special-cased to be handled by the frontend of our virtual CPU, without being added to
// the reorder buffer: X^mov
func (s *simulationProgram) decodeMov(state simulationState) simulationState {
	newState := state
	// x′_ı = x_ı + 1 + skip(x_ı)
	newInstructionCounter := *state.instructionCounter + uint64(1+s.skip(*state.instructionCounter))

	// x′_d = d−1
	state.decodeSlots -= 1

	// 			⎧ x_r[j]r ∪ rˇ(c,k,x_ı) if x_r[j]r ∩ sˇ(c,k,x_ı) ≠ ∅
	// x′_r[j]r ⎨
	// 			⎩ x_r[j]r ∖ rˇ(c,k,xı)  otherwise
	// j ∈ N
	// if destination reg is the same as source reg add to the resources list, if not remove it
	for j := range state.reorderBuffer {
		if s.srcRegs.overlapsWith(s.srcRegs) {
			if state.reorderBuffer[j].registers == nil {
				state.reorderBuffer[j].registers = make(map[Reg]struct{})
			}
			for dstReg := range s.dstRegs {
				state.reorderBuffer[j].registers[dstReg] = struct{}{}
			}
		} else {
			for dstReg := range s.dstRegs {
				delete(state.reorderBuffer[j].registers, dstReg)
			}
		}
	}

	newState.instructionCounter = &newInstructionCounter
	return newState
}

// decodeAll X^decode (eq. A.54)
func (s *simulationProgram) decodeAll(state simulationState) simulationState {
	newState := simulationState{}
	if s.opcode(*state.instructionCounter).IsBasicBlockTermination() { // if opcode(c,k,x_ı) ∈ T
		// x′_ı = ∅
		newState.instructionCounter = nil
	} else { // otherwise
		// x′_ı = x_ı + 1 + skip(x_ı)
		newInstructionCounter := *state.instructionCounter + 1 + uint64(s.skip(*state.instructionCounter))
		newState.instructionCounter = &newInstructionCounter
	}

	// x′_d = d − dˇ(c,k,x_ı)
	state.decodeSlots -= uint64(s.decodeSlots)

	// r′ = rˇ(c,k,x_ı)
	dstRegs := s.dstRegs

	// c′ = cˇ(c,k,x_ı)
	instrCycles := s.instrCycles

	// t′ = xˇ(c,k,x_ı)
	execUnits := s.execUnits

	// p′ = { i | i ∈ N, sˇ(c,k,x_ı) ∩ x_r[i]r ≠ ∅ }
	var dependencies []int
	for i := range state.reorderBuffer {
		if state.reorderBuffer[i].registers.overlapsWith(s.srcRegs) {
			dependencies = append(dependencies, i)
		}
		state.reorderBuffer[i].registers = make(map[Reg]struct{})
	}

	// j ∈ N => r′[j] = x_r[j] except: r′[j]r = x_r[j]r ∖ r′
	reorderBuffer := make([]reorderBufferEntry, len(state.reorderBuffer))
	for i := range state.reorderBuffer {
		reorderBuffer[i] = state.reorderBuffer[i]
		for reg := range dstRegs {
			delete(reorderBuffer[i].registers, reg)
		}
	}

	newState.reorderBuffer = append(reorderBuffer, reorderBufferEntry{DEC, instrCycles, dependencies, dstRegs, execUnits})
	return newState
}

// execNextPendingInstr X′′
func (s *simulationProgram) execNextPendingInstr(state simulationState) simulationState {
	newState := simulationState{}
	// n = S(x)
	readyInstrIndex, ok := readyForExecution(state)
	if !ok {
		return state
	}

	// x′_e = x_e − 1
	newState.maxInstructions = state.maxInstructions - 1

	// x′_t = x_t − x_r[n]t
	newState.remainingExecUnits = state.remainingExecUnits.sub(state.reorderBuffer[readyInstrIndex].usedExecUnits)

	// x′_r = x_r except: r′[n]s = EXE
	newState.reorderBuffer[readyInstrIndex].status = EXE

	return newState
}

// simulateVirtualCPU the state simulate function X′′′ n+1 which simulates the rest of the virtual CPU pipeline X′′′ (eq. A.61)
func (s *simulationProgram) simulateVirtualCPU(state simulationState) simulationState {
	newState := simulationState{}

	// x′_d = 4, x′_e = 5, x′_c = x′_c + 1
	newState.decodeSlots = 4
	newState.maxInstructions = 5
	newState.cycleCounter = state.cycleCounter + 1

	// x′_t = x_t + [n ∈ N ⇒ x_r [n]s = EXE ∧ x_r[n]c = 1]∑ x_r[j]t
	for j := range state.reorderBuffer {
		if state.reorderBuffer[j].status == EXE && state.reorderBuffer[j].cyclesLeft == 1 {
			newState.remainingExecUnits = state.remainingExecUnits.add(state.reorderBuffer[j].usedExecUnits)
		}
	}

	newState.reorderBuffer = make([]reorderBufferEntry, len(state.reorderBuffer))
	for j := range state.reorderBuffer {
		isFull := true
		// are all scheduled instructions before j not 4
		for k := range state.reorderBuffer[:j+1] {
			if state.reorderBuffer[k].status != FIN {
				isFull = false
				break
			}
		}
		if isFull {
			newState.reorderBuffer[j].status = NULL
		} else if state.reorderBuffer[j].status == DEC {
			newState.reorderBuffer[j].status = WAIT
		} else if state.reorderBuffer[j].status == EXE {
			switch state.reorderBuffer[j].cyclesLeft {
			case 0:
				newState.reorderBuffer[j].status = FIN
			case 1:
				newState.reorderBuffer[j].registers = nil
			}
			newState.reorderBuffer[j].cyclesLeft = state.reorderBuffer[j].cyclesLeft - 1
		} else {
			newState.reorderBuffer[j] = state.reorderBuffer[j]
			newState.reorderBuffer[j].cyclesLeft = state.reorderBuffer[j].cyclesLeft
		}
	}
	return state
}

// S(Xn) = min(j ∈ N ∣ s⃗(n)_j = 2 ∧ x⃗(n)_j ≤ 9 x(n) ∧ (∀k ∈ p⃗(n)_j ⇒ c⃗(n) k ≤ 0))
//
//	x ↦ min(j ∈ N ∶ x_r[j]s = WAIT ∧ xr[j]t ≤ xt ∧ (∀k∈ xr[j]p ⇒ xr[k]c ≤ 0))
//
// S∶{S → { N, ∅ }
func readyForExecution(state simulationState) (int, bool) {
	for j := range state.reorderBuffer {

		// x_r[j]s = WAIT (ready state)
		if state.reorderBuffer[j].status != WAIT {
			continue
		}

		// x_r[j]t ≤ x_t  (enough execution units)
		if state.reorderBuffer[j].usedExecUnits.greaterThan(state.remainingExecUnits) {
			continue
		}

		// (∀ k ∈ x_r[j]p ⇒ x_r[k]c ≤ 0) (all dependencies finished)
		ready := true
		for k := range state.reorderBuffer {
			if state.reorderBuffer[k].cyclesLeft > 0 {
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
	switch s.opcode(instructionCounter) {
	case MoveReg:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 0, 1, execResources{0, 0, 0, 0, 0} // move_reg 0 1 0 0 0 0 0
	case And:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // and 1 P(1,2) 1 0 0 0 0
	case Xor:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // xor 1 P(1,2) 1 0 0 0 0
	case Or:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // or 1 P(1,2) 1 0 0 0 0
	case Add64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // add_64 1 P(1,2) 1 0 0 0 0
	case Sub64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // sub_64 1 P(1,2) 1 0 0 0 0
	case Add32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // add_32 2 P(2,3) 1 0 0 0 0
	case Sub32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // sub_32 2 P(2,3) 1 0 0 0 0
	case AndImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // and_imm 1 P(1,2) 1 0 0 0 0
	case XorImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // xor_imm 1 P(1,2) 1 0 0 0 0
	case OrImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // or_imm 1 P(1,2) 1 0 0 0 0
	case AddImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // add_imm_64 1 P(1,2) 1 0 0 0 0
	case ShloRImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // shlo_r_imm_64 1 P(1,2) 1 0 0 0 0
	case SharRImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // shar_r_imm_64 1 P(1,2) 1 0 0 0 0
	case ShloLImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // shlo_l_imm_64 1 P(1,2) 1 0 0 0 0
	case RotR64Imm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // rot_r_64_imm 1 P(1,2) 1 0 0 0 0
	case ReverseBytes:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.regsOverlaps(1, 2), execResources{1, 0, 0, 0, 0} // reverse_bytes 1 P(1,2) 1 0 0 0 0
	case AddImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // add_imm_32 2 P(2,3) 1 0 0 0 0
	case ShloRImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // shlo_r_imm_32 2 P(2,3) 1 0 0 0 0
	case SharRImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // shar_r_imm_32 2 P(2,3) 1 0 0 0 0
	case ShloLImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // shlo_l_imm_32 2 P(2,3) 1 0 0 0 0
	case RotR32Imm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // rot_r_32_imm 2 P(2,3) 1 0 0 0 0
	case CountSetBits64:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, 1, execResources{1, 0, 0, 0, 0} // count_set_bits_64 1 1 1 0 0 0 0
	case CountSetBits32:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, 1, execResources{1, 0, 0, 0, 0} // count_set_bits_32 1 1 1 0 0 0 0
	case LeadingZeroBits64:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, 1, execResources{1, 0, 0, 0, 0} // leading_zero_bits_64 1 1 1 0 0 0 0
	case LeadingZeroBits32:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, 1, execResources{1, 0, 0, 0, 0} // leading_zero_bits_32 1 1 1 0 0 0 0
	case SignExtend8:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, 1, execResources{1, 0, 0, 0, 0} // sign_extend_8 1 1 1 0 0 0 0
	case SignExtend16:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, 1, execResources{1, 0, 0, 0, 0} // sign_extend_16 1 1 1 0 0 0 0
	case ZeroExtend16:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, 1, execResources{1, 0, 0, 0, 0} // zero_extend_16 1 1 1 0 0 0 0
	case TrailingZeroBits64:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 1, execResources{2, 0, 0, 0, 0} // trailing_zero_bits_64 2 1 2 0 0 0 0
	case TrailingZeroBits32:
		dstReg, regA := s.decodeArgsReg2(instructionCounter)
		s.dstRegs = regsSet{dstReg: {}}
		s.srcRegs = regsSet{regA: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 1, execResources{2, 0, 0, 0, 0} // trailing_zero_bits_32 2 1 2 0 0 0 0
	case ShloL64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // shlo_l_64 1 PS (2,3) 1 0 0 0 0
	case ShloR64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // shlo_r_64 1 PS (2,3) 1 0 0 0 0
	case SharR64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // shar_r_64 1 PS (2,3) 1 0 0 0 0
	case RotL64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // rot_l_64 1 PS (2,3) 1 0 0 0 0
	case RotR64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, s.overlapsFirstSrcReg(instructionCounter, 2, 3), execResources{1, 0, 0, 0, 0} // rot_r_64 1 PS (2,3) 1 0 0 0 0
	case ShloL32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // shlo_l_32 2 PS (3,4) 1 0 0 0 0
	case ShloR32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // shlo_r_32 2 PS (3,4) 1 0 0 0 0
	case SharR32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // shar_r_32 2 PS (3,4) 1 0 0 0 0
	case RotL32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // rot_l_32 2 PS (3,4) 1 0 0 0 0
	case RotR32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, s.overlapsFirstSrcReg(instructionCounter, 3, 4), execResources{1, 0, 0, 0, 0} // rot_r_32 2 PS (3,4) 1 0 0 0 0
	case ShloLImmAlt64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, 3, execResources{1, 0, 0, 0, 0} // shlo_l_imm_alt_64 1 3 1 0 0 0 0
	case ShloRImmAlt64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, 3, execResources{1, 0, 0, 0, 0} // shlo_r_imm_alt_64 1 3 1 0 0 0 0
	case SharRImmAlt64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, 3, execResources{1, 0, 0, 0, 0} // shar_r_imm_alt_64 1 3 1 0 0 0 0
	case RotR64ImmAlt:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, 3, execResources{1, 0, 0, 0, 0} // rot_r_64_imm_alt 1 3 1 0 0 0 0
	case ShloLImmAlt32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 4, execResources{1, 0, 0, 0, 0} // shlo_l_imm_alt_32 2 4 1 0 0 0 0
	case ShloRImmAlt32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 4, execResources{1, 0, 0, 0, 0} // shlo_r_imm_alt_32 2 4 1 0 0 0 0
	case SharRImmAlt32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 4, execResources{1, 0, 0, 0, 0} // shar_r_imm_alt_32 2 4 1 0 0 0 0
	case RotR32ImmAlt:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 4, execResources{1, 0, 0, 0, 0} // rot_r_32_imm_alt 2 4 1 0 0 0 0
	case SetLtU:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 3, 3, execResources{1, 0, 0, 0, 0} // set_lt_u 3 3 1 0 0 0 0
	case SetLtS:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 3, 3, execResources{1, 0, 0, 0, 0} // set_lt_s 3 3 1 0 0 0 0
	case SetLtUImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 3, 3, execResources{1, 0, 0, 0, 0} // set_lt_u_imm 3 3 1 0 0 0 0
	case SetLtSImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 3, 3, execResources{1, 0, 0, 0, 0} // set_lt_s_imm 3 3 1 0 0 0 0
	case SetGtUImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 3, 3, execResources{1, 0, 0, 0, 0} // set_gt_u_imm 3 3 1 0 0 0 0
	case SetGtSImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 3, 3, execResources{1, 0, 0, 0, 0} // set_gt_s_imm 3 3 1 0 0 0 0
	case CmovIz:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 2, execResources{1, 0, 0, 0, 0} // cmov_iz 2 2 1 0 0 0 0
	case CmovNz:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 2, execResources{1, 0, 0, 0, 0} // cmov_nz 2 2 1 0 0 0 0
	case CmovIzImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 3, execResources{1, 0, 0, 0, 0} // cmov_iz_imm 2 3 1 0 0 0 0
	case CmovNzImm:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 3, execResources{1, 0, 0, 0, 0} // cmov_nz_imm 2 3 1 0 0 0 0
	case Max:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 3, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // max 3 P(2,3) 1 0 0 0 0
	case MaxU:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 3, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // max_u 3 P(2,3) 1 0 0 0 0
	case Min:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 3, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // min 3 P(2,3) 1 0 0 0 0
	case MinU:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 3, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // min_u 3 P(2,3) 1 0 0 0 0
	case LoadIndU8:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_u8 m 1 1 1 0 0 0
	case LoadIndI8:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_i8 m 1 1 1 0 0 0
	case LoadIndU16:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_u16 m 1 1 1 0 0 0
	case LoadIndI16:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_i16 m 1 1 1 0 0 0
	case LoadIndU32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_u32 m 1 1 1 0 0 0
	case LoadIndI32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_i32 m 1 1 1 0 0 0
	case LoadIndU64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_ind_u64 m 1 1 1 0 0 0
	case LoadU8:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_u8 m 1 1 1 0 0 0
	case LoadI8:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_i8 m 1 1 1 0 0 0
	case LoadU16:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_u16 m 1 1 1 0 0 0
	case LoadI16:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_i16 m 1 1 1 0 0 0
	case LoadU32:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_u32 m 1 1 1 0 0 0
	case LoadI32:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_i32 m 1 1 1 0 0 0
	case LoadU64:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = memoryAccessCost, 1, execResources{1, 1, 0, 0, 0} // load_u64 m 1 1 1 0 0 0
	case StoreImmIndU8:
		regA, _, _ := s.decodeArgsRegImm2(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_ind_u8 25 1 1 0 1 0 0
	case StoreImmIndU16:
		regA, _, _ := s.decodeArgsRegImm2(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_ind_u16 25 1 1 0 1 0 0
	case StoreImmIndU32:
		regA, _, _ := s.decodeArgsRegImm2(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_ind_u32 25 1 1 0 1 0 0
	case StoreImmIndU64:
		regA, _, _ := s.decodeArgsRegImm2(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_ind_u64 25 1 1 0 1 0 0
	case StoreIndU8:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_ind_u8 25 1 1 0 1 0 0
	case StoreIndU16:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_ind_u16 25 1 1 0 1 0 0
	case StoreIndU32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_ind_u32 25 1 1 0 1 0 0
	case StoreIndU64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_ind_u64 25 1 1 0 1 0 0
	case StoreImmU8:
		s.srcRegs, s.dstRegs = regsSet{}, regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_u8 25 1 1 0 1 0 0
	case StoreImmU16:
		s.srcRegs, s.dstRegs = regsSet{}, regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_u16 25 1 1 0 1 0 0
	case StoreImmU32:
		s.srcRegs, s.dstRegs = regsSet{}, regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_u32 25 1 1 0 1 0 0
	case StoreImmU64:
		s.srcRegs, s.dstRegs = regsSet{}, regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_imm_u64 25 1 1 0 1 0 0
	case StoreU8:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_u8 25 1 1 0 1 0 0
	case StoreU16:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_u16 25 1 1 0 1 0 0
	case StoreU32:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_u32 25 1 1 0 1 0 0
	case StoreU64:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 25, 1, execResources{1, 0, 1, 0, 0} // store_u64 25 1 1 0 1 0 0
	case BranchEq:
		regA, regB, _ := s.decodeArgsReg2Offset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_eq b 1 1 0 0 0 0
	case BranchNe:
		regA, regB, _ := s.decodeArgsReg2Offset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ne b 1 1 0 0 0 0
	case BranchLtU:
		regA, regB, _ := s.decodeArgsReg2Offset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_lt_u b 1 1 0 0 0 0
	case BranchLtS:
		regA, regB, _ := s.decodeArgsReg2Offset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_lt_s b 1 1 0 0 0 0
	case BranchGeU:
		regA, regB, _ := s.decodeArgsReg2Offset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ge_u b 1 1 0 0 0 0
	case BranchGeS:
		regA, regB, _ := s.decodeArgsReg2Offset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCost(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ge_s b 1 1 0 0 0 0
	case BranchEqImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_eq_imm b 1 1 0 0 0 0
	case BranchNeImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ne_imm b 1 1 0 0 0 0
	case BranchLtUImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_lt_u_imm b 1 1 0 0 0 0
	case BranchLeUImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_le_u_imm b 1 1 0 0 0 0
	case BranchGeUImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ge_u_imm b 1 1 0 0 0 0
	case BranchGtUImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_gt_u_imm b 1 1 0 0 0 0
	case BranchLtSImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_lt_s_imm b 1 1 0 0 0 0
	case BranchLeSImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_le_s_imm b 1 1 0 0 0 0
	case BranchGeSImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_ge_s_imm b 1 1 0 0 0 0
	case BranchGtSImm:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = s.branchCostImm(instructionCounter), 1, execResources{1, 0, 0, 0, 0} // branch_gt_s_imm b 1 1 0 0 0 0
	case DivU32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 60, 4, execResources{1, 0, 0, 0, 1} // div_u_32 60 4 1 0 0 0 1
	case DivS32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 60, 4, execResources{1, 0, 0, 0, 1} // div_s_32 60 4 1 0 0 0 1
	case RemU32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 60, 4, execResources{1, 0, 0, 0, 1} // rem_u_32 60 4 1 0 0 0 1
	case RemS32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 60, 4, execResources{1, 0, 0, 0, 1} // rem_s_32 60 4 1 0 0 0 1
	case DivU64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 60, 4, execResources{1, 0, 0, 0, 1} // div_u_64 60 4 1 0 0 0 1
	case DivS64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 60, 4, execResources{1, 0, 0, 0, 1} // div_s_64 60 4 1 0 0 0 1
	case RemU64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 60, 4, execResources{1, 0, 0, 0, 1} // rem_u_64 60 4 1 0 0 0 1
	case RemS64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 60, 4, execResources{1, 0, 0, 0, 1} // rem_s_64 60 4 1 0 0 0 1
	case AndInv:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 3, execResources{1, 0, 0, 0, 0} // and_inv 2 3 1 0 0 0 0
	case OrInv:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 3, execResources{1, 0, 0, 0, 0} // or_inv 2 3 1 0 0 0 0
	case Xnor:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, s.regsOverlaps(2, 3), execResources{1, 0, 0, 0, 0} // xnor 2 P(2,3) 1 0 0 0 0
	case NegAddImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 3, execResources{1, 0, 0, 0, 0} // neg_add_imm_64 2 3 1 0 0 0 0
	case NegAddImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 3, 4, execResources{1, 0, 0, 0, 0} // neg_add_imm_32 3 4 1 0 0 0 0
	case LoadImm:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, 1, execResources{0, 0, 0, 0, 0} // load_imm 1 1 0 0 0 0 0
	case LoadImm64:
		regA, _ := s.decodeArgsRegImmExt(instructionCounter)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 1, 2, execResources{0, 0, 0, 0, 0} // load_imm_64 1 2 0 0 0 0 0
	case Mul64:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 3, s.regsOverlaps(1, 2), execResources{1, 0, 0, 1, 0} // mul_64 3 P(1,2) 1 0 0 1 0
	case Mul32:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 4, s.regsOverlaps(2, 3), execResources{1, 0, 0, 1, 0} // mul_32 4 P(2,3) 1 0 0 1 0
	case MulImm64:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 3, s.regsOverlaps(1, 2), execResources{1, 0, 0, 1, 0} // mul_imm_64 3 P(1,2) 1 0 0 1 0
	case MulImm32:
		regA, regB, _ := s.decodeArgsReg2Imm(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 4, s.regsOverlaps(2, 3), execResources{1, 0, 0, 1, 0} // mul_imm_32 4 P(2,3) 1 0 0 1 0
	case MulUpperSS:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 4, 4, execResources{1, 0, 0, 1, 0} // mul_upper_s_s 4 4 1 0 0 1 0
	case MulUpperUU:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 4, 4, execResources{1, 0, 0, 1, 0} // mul_upper_u_u 4 4 1 0 0 1 0
	case MulUpperSU:
		regDst, regA, regB := s.decodeArgsReg3(instructionCounter)
		s.dstRegs = regsSet{regDst: {}}
		s.srcRegs = regsSet{regA: {}, regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 6, 4, execResources{1, 0, 0, 1, 0} // mul_upper_s_u 6 4 1 0 0 1 0
	case Trap:
		s.dstRegs, s.srcRegs = regsSet{}, regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 1, execResources{0, 0, 0, 0, 0} // trap 2 1 0 0 0 0 0
	case Fallthrough:
		s.dstRegs, s.srcRegs = regsSet{}, regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 2, 1, execResources{0, 0, 0, 0, 0} // fallthrough 2 1 0 0 0 0 0
	case Unlikely:
		s.dstRegs, s.srcRegs = regsSet{}, regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 40, 1, execResources{0, 0, 0, 0, 0} // unlikely 40 1 0 0 0 0 0
	case Jump:
		s.dstRegs, s.srcRegs = regsSet{}, regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 15, 1, execResources{0, 0, 0, 0, 0} // jump 15 1 0 0 0 0 0
	case LoadImmJump:
		regA, _, _ := s.decodeArgsRegImmOffset(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 15, 1, execResources{0, 0, 0, 0, 0} // load_imm_jump 15 1 0 0 0 0 0
	case JumpInd:
		regA, _ := s.decodeArgsRegImm(instructionCounter, s.skipLen)
		s.srcRegs = regsSet{regA: {}}
		s.dstRegs = regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 22, 1, execResources{0, 0, 0, 0, 0} // jump_ind 22 1 0 0 0 0 0
	case LoadImmJumpInd:
		regA, regB, _, _ := s.decodeArgsReg2Imm2(instructionCounter, s.skipLen)
		s.dstRegs = regsSet{regA: {}}
		s.srcRegs = regsSet{regB: {}}
		s.instrCycles, s.decodeSlots, s.execUnits = 22, 1, execResources{0, 0, 0, 0, 0} // load_imm_jump_ind 22 1 0 0 0 0 0
	case Ecalli:
		s.srcRegs, s.dstRegs = regsSet{}, regsSet{}
		s.instrCycles, s.decodeSlots, s.execUnits = 100, 4, execResources{1, 0, 0, 0, 0} // ecalli 100 4 1 0 0 0 0
	default:
		panic("unable to get cost for instruction")
	}
}

// Decode costs
const (
	// m
	memoryAccessCost = 25 // m = 25
)
