package pvm

import "maps"

type InstructionCost struct {
	Cycles        uint8 // c is the number of cycles a given instruction needs to finish execution, (latency?)
	DecodingSlots uint8 // d is the number of decoding slots necessary to decode it
	Execution     uint8 // x is the number of virtual CPU execution units required to start its execution.
}

// ˇs(c,k,ı) - returns a set of source registers read by a given instruction

// ˇr(c,k,ı) - returns a set of destination registers which are written by a given instruction

// P

// ϱ∆_ı = max(c^(m) − 3, 1)
// the modeled (estimated/cost) execution time (cycles/latency) of the m-th instruction

// dot - modeled value
// check - estimated number for instruction

type SimulationState struct {
	*program

	instructionCounter *uint64 // i
	cost               uint64  // c
	instructionIndex   int     // n
	decodingSlots      uint64  // d
	executionReadiness uint64  // e

	scheduledInstructions []uint64             // s⃗
	instructionCost       []uint64             // c⃗
	portAvailability      [][]int              // p⃗
	regs                  []map[Reg]struct{}   // r⃗
	instructionExecution  []ExecutionResources // x⃗

	execution ExecutionResources // x
}

type ExecutionResources struct {
	ALU   uint8 // x_A
	Load  uint8 // x_L
	Store uint8 // x_S
	Mul   uint8 // x_M
	Div   uint8 // x_D
}

func (e *ExecutionResources) Add(another ExecutionResources) {
	e.ALU += another.ALU
	e.Load += another.Load
	e.Store += another.Store
	e.Mul += another.Mul
	e.Div += another.Div
}
func (e *ExecutionResources) Sub(another ExecutionResources) {
	e.ALU -= another.ALU
	e.Load -= another.Load
	e.Store -= another.Store
	e.Mul -= another.Mul
	e.Div -= another.Div
}

func NewSimulation(program *program, instructionCounter uint64) *SimulationState {
	return &SimulationState{
		instructionCounter:    &instructionCounter,
		cost:                  0,
		instructionIndex:      0,
		decodingSlots:         4,
		executionReadiness:    5,
		scheduledInstructions: []uint64{},
		instructionCost:       []uint64{},
		portAvailability:      [][]int{},
		regs:                  []map[Reg]struct{}{},
		instructionExecution:  []ExecutionResources{},
		execution: ExecutionResources{
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
	_, d, _, _, _, _, _ := s.getCosts(*s.instructionCounter)
	// if n= 0 ∨ (ı(n) ≠ ∅ ∧ dˇ(c,k,ı(n)) ≤ d(n) ∧ ∣ s⃗(n)∣ < 32)
	if instructionIndex == 0 || (s.instructionCounter != nil && uint64(d) <= s.decodingSlots) || len(s.scheduledInstructions) < 32 {
		// Ξ`
		s.ReorderBuffer(instructionIndex)
		return
	}

	// if S(Ξn) ≠ ∅ ∧ e(n) > 0
	if _, ok := s.readyForExecution(instructionIndex); ok && s.executionReadiness > 0 {
		// Ξ``
		s.ExecuteNextPendingInstr(instructionIndex)
		return
	}

	// if ı(n) = ∅ ∧ |s⃗(n)| = 0
	if s.instructionCounter == nil && len(s.scheduledInstructions) == 0 {
		return
	}

	// otherwise Ξ```
	s.SimulateVirtualCPU(instructionIndex)
}

func (s *SimulationState) ReorderBuffer(instructionIndex uint64) {
	if s.opcode(*s.instructionCounter) == MoveReg {
		s.ReorderBufferMov(instructionIndex)
		return
	}

	s.ReorderBufferDecode(instructionIndex)
}

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

func (s *SimulationState) ReorderBufferDecode(instructionIndex uint64) {
	c, d, xA, xL, xS, xM, xD := s.getCosts(*s.instructionCounter)
	if s.opcode(*s.instructionCounter).IsBasicBlockTermination() { // // if opcode(c,k,ı(n)) ∈ T
		// ı(n+1) = ∅
		s.instructionCounter = nil
	} else { // otherwise
		// ı(n+1) = ı(n) + 1 + skip(ı(n))
		*s.instructionCounter += 1 + uint64(s.skip(*s.instructionCounter))
	}

	// d(n+1) = d(n) − dˇ(c,k,ı(n))
	s.decodingSlots -= uint64(d)

	// s⃗(n+1)_n(n) = 1
	s.scheduledInstructions[s.instructionIndex] = 1

	// n(n+1) = n(n) + 1
	s.instructionIndex += 1

	// c⃗(n+1)_n(n) = cˇ(c,k,ı(n))
	s.instructionCost[s.instructionIndex] = uint64(c)

	// x⃗(n+1)_n(n) = xˇ(c,k,ı(n))
	s.instructionExecution[s.instructionIndex] = ExecutionResources{xA, xL, xS, xM, xD}

	// p(n+1)_n(n) = { j ∣ sˇ(c,k,ı(n)) ∩⃗ r⃗(n)_j ≠ ∅ }
	srcRegs := s.getSrcRegs(*s.instructionCounter)
	dstRegs := s.getDstRegs(*s.instructionCounter)

	for j := range s.regs {
		if registersIntersects(srcRegs, s.regs[j]) {
			s.portAvailability[s.instructionIndex] = append(s.portAvailability[s.instructionIndex], j)
		}
	}

	//					⎧ rˇ(c,k,ı(n)) 			if j = n(n)
	// j ∈ N ⇒ r⃗(n+1)_j ⎨
	//					⎩ r⃗(n)_j ∖ rˇ(c,k,ı(n)) otherwise

	s.regs[s.instructionIndex] = dstRegs
	for j := range s.regs {
		if j != s.instructionIndex {
			maps.DeleteFunc(s.regs[j], func(reg Reg, s struct{}) bool {
				_, ok := dstRegs[reg]
				return ok
			})
		}
	}
}

func registersIntersects(regsA, regsB map[Reg]struct{}) bool {
	for regA := range regsA {
		if _, ok := regsB[regA]; ok {
			return true
		}
	}

	return false
}

// sˇ(c,k,ı)
func (s *SimulationState) getSrcRegs(instructionCounter uint64) map[Reg]struct{} {
	ret := make(map[Reg]struct{})
	return ret
}

// rˇ(c,k,ı)
func (s *SimulationState) getDstRegs(instructionCounter uint64) map[Reg]struct{} {
	ret := make(map[Reg]struct{})
	return ret
}

func (s *SimulationState) ExecuteNextPendingInstr(instructionIndex uint64) {
	readyInstrIndex, ok := s.readyForExecution(instructionIndex)
	if !ok {
		return // TODO
	}

	// s⃗(n+1)_S(Ξn ) = 3
	s.scheduledInstructions[readyInstrIndex] = 3

	// x(n+1) = x(n) − x⃗(n)_S(Ξn )
	s.execution.Sub(s.instructionExecution[readyInstrIndex])

	// e(n+1) = e(n) −1
	s.executionReadiness -= 1
}

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
			if s.scheduledInstructions[k] != 4 {
				isFull = false
				break
			}
		}
		if isFull {
			s.scheduledInstructions[j] = nil
		} else if s.scheduledInstructions[j] == 1 {
			s.scheduledInstructions[j] = 2
		} else if s.scheduledInstructions[j] == 3 && s.instructionCost[j] == 0 {
			s.scheduledInstructions[j] = 4
		}
	}

	// 						⎧ c⃗(n)_j - 1 	if s⃗(n)_j = 3
	// j ∈ N ⇒ c⃗(n+1)_j = 	⎨
	// 						⎩ c⃗(n)_j 		otherwise
	for j := range s.instructionCost {
		if s.scheduledInstructions[j] == 3 {
			s.instructionCost[j] -= 1
		}
	}
	//						⎧ ∅ 		if s⃗(n)_j = 3 ∧ c⃗(n)_j = 1
	// j ∈ N ⇒ r⃗(n+1)_j = 	⎨
	//						⎩ r⃗(n)_j 	otherwise
	for j := range s.regs {
		if s.scheduledInstructions[j] == 3 && s.instructionCost[j] == 1 {
			s.regs[j] = nil
		}
	}

	// x(n+1) = x(n) + [j∈N⇒s⃗(n)_j=3∧c⃗(n)_j=1]∑(x⃗(n)_j)
	for j := range s.scheduledInstructions {
		if s.scheduledInstructions[j] == 3 && s.instructionCost[j] == 1 {
			s.execution.Add(s.instructionExecution[j])
		}
	}

	// c(n+1) = c(n) + 1
	s.cost += 1

	// d(n+1) = 4
	s.decodingSlots = 4

	// e(n+1) = 5
	s.executionReadiness = 5
}

// S(Ξn) = min(j ∈ N ∣ s⃗(n) j= 2 ∧ x⃗(n)_j ≤ 9 x(n) ∧(∀k ∈ p⃗(n)_j ⇒ c⃗(n) k ≤ 0))
// The state transition function Ξ′′′ n+1 which simulates the rest of the virtual CPU pipeline is d
func (s *SimulationState) readyForExecution(n uint64) (uint64, bool) {
	for j := uint64(0); j < n; j++ {

		// s⃗(n)_j = 2 (ready state)
		if s.scheduledInstructions[j] != 2 {
			continue
		}

		// x⃗(n)_j ≤ x(n)  (enough execution units)
		if s.instructionExecution[j].ALU > s.execution.ALU &&
			s.instructionExecution[j].Load > s.execution.Load &&
			s.instructionExecution[j].Store > s.execution.Store &&
			s.instructionExecution[j].Mul > s.execution.Mul &&
			s.instructionExecution[j].Div > s.execution.Div {
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

func (p *program) overlaps2Regs(instructionCounter uint64, a, b uint8) uint8 {
	regDst, regA := p.decodeArgsReg2(instructionCounter)
	if regDst == regA {
		return a
	}

	return b
}

func (p *program) overlaps2RegsImm(instructionCounter uint64, a, b uint8) uint8 {
	regA, regB, _ := p.decodeArgsReg2Imm(instructionCounter, p.skip(instructionCounter))
	if regA == regB {
		return a
	}

	return b
}

func (p *program) overlaps3Regs(instructionCounter uint64, a, b uint8) uint8 {
	regDst, regA, regB := p.decodeArgsReg3(instructionCounter)
	if regDst == regA || regDst == regB {
		return a
	}
	return b
}

// PS
func (p *program) overlapsFirstSrcReg(instructionCounter uint64, a, b uint8) uint8 {
	regDst, regA, _ := p.decodeArgsReg3(instructionCounter)
	if regDst == regA {
		return a
	}
	return b
}

// b
func (p *program) branchCost(instructionCounter uint64) uint8 {
	currentSkip := p.skip(instructionCounter)
	_, _, valueX := p.decodeArgsReg2Offset(instructionCounter, currentSkip)
	switch Opcode(p.code[instructionCounter+1+uint64(currentSkip)]) {
	case Trap, Unlikely:
		return 1
	}
	switch Opcode(p.code[valueX]) {
	case Trap, Unlikely:
		return 1
	}

	return 20
}

// b
func (p *program) branchCostImm(instructionCounter uint64) uint8 {
	currentSkip := p.skip(instructionCounter)
	_, _, valueY := p.decodeArgsRegImmOffset(instructionCounter, currentSkip)
	switch Opcode(p.code[instructionCounter+1+uint64(currentSkip)]) {
	case Trap, Unlikely:
		return 1
	}
	switch Opcode(p.code[valueY]) {
	case Trap, Unlikely:
		return 1
	}

	return 20
}

func (p *program) getCosts(instructionCounter uint64) (c, d, xA, xL, xS, xM, xD uint8) {
	switch p.opcode(instructionCounter) {
	case MoveReg:
		return 0, 1, 0, 0, 0, 0, 0 //move_reg 0 1 0 0 0 0 0
	case And:
		return 1, p.overlaps3Regs(instructionCounter, 1, 2), 1, 0, 0, 0, 0 //and 1 P(1,2) 1 0 0 0 0
	case Xor:
		return 1, p.overlaps3Regs(instructionCounter, 1, 2), 1, 0, 0, 0, 0 //xor 1 P(1,2) 1 0 0 0 0
	case Or:
		return 1, p.overlaps3Regs(instructionCounter, 1, 2), 1, 0, 0, 0, 0 //or 1 P(1,2) 1 0 0 0 0
	case Add64:
		return 1, p.overlaps3Regs(instructionCounter, 1, 2), 1, 0, 0, 0, 0 //add_64 1 P(1,2) 1 0 0 0 0
	case Sub64:
		return 1, p.overlaps3Regs(instructionCounter, 1, 2), 1, 0, 0, 0, 0 //sub_64 1 P(1,2) 1 0 0 0 0
	case Add32:
		return 2, p.overlaps3Regs(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //add_32 2 P(2,3) 1 0 0 0 0
	case Sub32:
		return 2, p.overlaps3Regs(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //sub_32 2 P(2,3) 1 0 0 0 0
	case AndImm:
		return 1, p.overlaps2RegsImm(instructionCounter, 1, 2), 1, 0, 0, 0, 0 //and_imm 1 P(1,2) 1 0 0 0 0
	case XorImm:
		return 1, p.overlaps2RegsImm(instructionCounter, 1, 2), 1, 0, 0, 0, 0 //xor_imm 1 P(1,2) 1 0 0 0 0
	case OrImm:
		return 1, p.overlaps2RegsImm(instructionCounter, 1, 2), 1, 0, 0, 0, 0 //or_imm 1 P(1,2) 1 0 0 0 0
	case AddImm64:
		return 1, p.overlaps2RegsImm(instructionCounter, 1, 2), 1, 0, 0, 0, 0 //add_imm_64 1 P(1,2) 1 0 0 0 0
	case ShloRImm64:
		return 1, p.overlaps2RegsImm(instructionCounter, 1, 2), 1, 0, 0, 0, 0 //shlo_r_imm_64 1 P(1,2) 1 0 0 0 0
	case SharRImm64:
		return 1, p.overlaps2RegsImm(instructionCounter, 1, 2), 1, 0, 0, 0, 0 //shar_r_imm_64 1 P(1,2) 1 0 0 0 0
	case ShloLImm64:
		return 1, p.overlaps2RegsImm(instructionCounter, 1, 2), 1, 0, 0, 0, 0 //shlo_l_imm_64 1 P(1,2) 1 0 0 0 0
	case RotR64Imm:
		return 1, p.overlaps2RegsImm(instructionCounter, 1, 2), 1, 0, 0, 0, 0 //rot_r_64_imm 1 P(1,2) 1 0 0 0 0
	case ReverseBytes:
		return 1, p.overlaps2Regs(instructionCounter, 1, 2), 1, 0, 0, 0, 0 //reverse_bytes 1 P(1,2) 1 0 0 0 0
	case AddImm32:
		return 2, p.overlaps2RegsImm(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //add_imm_32 2 P(2,3) 1 0 0 0 0
	case ShloRImm32:
		return 2, p.overlaps2RegsImm(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //shlo_r_imm_32 2 P(2,3) 1 0 0 0 0
	case SharRImm32:
		return 2, p.overlaps2RegsImm(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //shar_r_imm_32 2 P(2,3) 1 0 0 0 0
	case ShloLImm32:
		return 2, p.overlaps2RegsImm(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //shlo_l_imm_32 2 P(2,3) 1 0 0 0 0
	case RotR32Imm:
		return 2, p.overlaps2RegsImm(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //rot_r_32_imm 2 P(2,3) 1 0 0 0 0
	case CountSetBits64:
		return 1, 1, 1, 0, 0, 0, 0 //count_set_bits_64 1 1 1 0 0 0 0
	case CountSetBits32:
		return 1, 1, 1, 0, 0, 0, 0 //count_set_bits_32 1 1 1 0 0 0 0
	case LeadingZeroBits64:
		return 1, 1, 1, 0, 0, 0, 0 //leading_zero_bits_64 1 1 1 0 0 0 0
	case LeadingZeroBits32:
		return 1, 1, 1, 0, 0, 0, 0 //leading_zero_bits_32 1 1 1 0 0 0 0
	case SignExtend8:
		return 1, 1, 1, 0, 0, 0, 0 //sign_extend_8 1 1 1 0 0 0 0
	case SignExtend16:
		return 1, 1, 1, 0, 0, 0, 0 //sign_extend_16 1 1 1 0 0 0 0
	case ZeroExtend16:
		return 1, 1, 1, 0, 0, 0, 0 //zero_extend_16 1 1 1 0 0 0 0
	case TrailingZeroBits64:
		return 2, 1, 2, 0, 0, 0, 0 //trailing_zero_bits_64 2 1 2 0 0 0 0
	case TrailingZeroBits32:
		return 2, 1, 2, 0, 0, 0, 0 //trailing_zero_bits_32 2 1 2 0 0 0 0
	case ShloL64:
		return 1, p.overlapsFirstSrcReg(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //shlo_l_64 1 PS (2,3) 1 0 0 0 0
	case ShloR64:
		return 1, p.overlapsFirstSrcReg(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //shlo_r_64 1 PS (2,3) 1 0 0 0 0
	case SharR64:
		return 1, p.overlapsFirstSrcReg(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //shar_r_64 1 PS (2,3) 1 0 0 0 0
	case RotL64:
		return 1, p.overlapsFirstSrcReg(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //rot_l_64 1 PS (2,3) 1 0 0 0 0
	case RotR64:
		return 1, p.overlapsFirstSrcReg(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //rot_r_64 1 PS (2,3) 1 0 0 0 0
	case ShloL32:
		return 2, p.overlapsFirstSrcReg(instructionCounter, 3, 4), 1, 0, 0, 0, 0 //shlo_l_32 2 PS (3,4) 1 0 0 0 0
	case ShloR32:
		return 2, p.overlapsFirstSrcReg(instructionCounter, 3, 4), 1, 0, 0, 0, 0 //shlo_r_32 2 PS (3,4) 1 0 0 0 0
	case SharR32:
		return 2, p.overlapsFirstSrcReg(instructionCounter, 3, 4), 1, 0, 0, 0, 0 //shar_r_32 2 PS (3,4) 1 0 0 0 0
	case RotL32:
		return 2, p.overlapsFirstSrcReg(instructionCounter, 3, 4), 1, 0, 0, 0, 0 //rot_l_32 2 PS (3,4) 1 0 0 0 0
	case RotR32:
		return 2, p.overlapsFirstSrcReg(instructionCounter, 3, 4), 1, 0, 0, 0, 0 //rot_r_32 2 PS (3,4) 1 0 0 0 0
	case ShloLImmAlt64:
		return 1, 3, 1, 0, 0, 0, 0 //shlo_l_imm_alt_64 1 3 1 0 0 0 0
	case ShloRImmAlt64:
		return 1, 3, 1, 0, 0, 0, 0 //shlo_r_imm_alt_64 1 3 1 0 0 0 0
	case SharRImmAlt64:
		return 1, 3, 1, 0, 0, 0, 0 //shar_r_imm_alt_64 1 3 1 0 0 0 0
	case RotR64ImmAlt:
		return 1, 3, 1, 0, 0, 0, 0 //rot_r_64_imm_alt 1 3 1 0 0 0 0
	case ShloLImmAlt32:
		return 2, 4, 1, 0, 0, 0, 0 //shlo_l_imm_alt_32 2 4 1 0 0 0 0
	case ShloRImmAlt32:
		return 2, 4, 1, 0, 0, 0, 0 //shlo_r_imm_alt_32 2 4 1 0 0 0 0
	case SharRImmAlt32:
		return 2, 4, 1, 0, 0, 0, 0 //shar_r_imm_alt_32 2 4 1 0 0 0 0
	case RotR32ImmAlt:
		return 2, 4, 1, 0, 0, 0, 0 //rot_r_32_imm_alt 2 4 1 0 0 0 0
	case SetLtU:
		return 3, 3, 1, 0, 0, 0, 0 //set_lt_u 3 3 1 0 0 0 0
	case SetLtS:
		return 3, 3, 1, 0, 0, 0, 0 //set_lt_s 3 3 1 0 0 0 0
	case SetLtUImm:
		return 3, 3, 1, 0, 0, 0, 0 //set_lt_u_imm 3 3 1 0 0 0 0
	case SetLtSImm:
		return 3, 3, 1, 0, 0, 0, 0 //set_lt_s_imm 3 3 1 0 0 0 0
	case SetGtUImm:
		return 3, 3, 1, 0, 0, 0, 0 //set_gt_u_imm 3 3 1 0 0 0 0
	case SetGtSImm:
		return 3, 3, 1, 0, 0, 0, 0 //set_gt_s_imm 3 3 1 0 0 0 0
	case CmovIz:
		return 2, 2, 1, 0, 0, 0, 0 //cmov_iz 2 2 1 0 0 0 0
	case CmovNz:
		return 2, 2, 1, 0, 0, 0, 0 //cmov_nz 2 2 1 0 0 0 0
	case CmovIzImm:
		return 2, 3, 1, 0, 0, 0, 0 //cmov_iz_imm 2 3 1 0 0 0 0
	case CmovNzImm:
		return 2, 3, 1, 0, 0, 0, 0 //cmov_nz_imm 2 3 1 0 0 0 0
	case Max:
		return 3, p.overlaps3Regs(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //max 3 P(2,3) 1 0 0 0 0
	case MaxU:
		return 3, p.overlaps3Regs(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //max_u 3 P(2,3) 1 0 0 0 0
	case Min:
		return 3, p.overlaps3Regs(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //min 3 P(2,3) 1 0 0 0 0
	case MinU:
		return 3, p.overlaps3Regs(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //min_u 3 P(2,3) 1 0 0 0 0
	case LoadIndU8:
		return m, 1, 1, 1, 0, 0, 0 //load_ind_u8 m 1 1 1 0 0 0
	case LoadIndI8:
		return m, 1, 1, 1, 0, 0, 0 //load_ind_i8 m 1 1 1 0 0 0
	case LoadIndU16:
		return m, 1, 1, 1, 0, 0, 0 //load_ind_u16 m 1 1 1 0 0 0
	case LoadIndI16:
		return m, 1, 1, 1, 0, 0, 0 //load_ind_i16 m 1 1 1 0 0 0
	case LoadIndU32:
		return m, 1, 1, 1, 0, 0, 0 //load_ind_u32 m 1 1 1 0 0 0
	case LoadIndI32:
		return m, 1, 1, 1, 0, 0, 0 //load_ind_i32 m 1 1 1 0 0 0
	case LoadIndU64:
		return m, 1, 1, 1, 0, 0, 0 //load_ind_u64 m 1 1 1 0 0 0
	case LoadU8:
		return m, 1, 1, 1, 0, 0, 0 //load_u8 m 1 1 1 0 0 0
	case LoadI8:
		return m, 1, 1, 1, 0, 0, 0 //load_i8 m 1 1 1 0 0 0
	case LoadU16:
		return m, 1, 1, 1, 0, 0, 0 //load_u16 m 1 1 1 0 0 0
	case LoadI16:
		return m, 1, 1, 1, 0, 0, 0 //load_i16 m 1 1 1 0 0 0
	case LoadU32:
		return m, 1, 1, 1, 0, 0, 0 //load_u32 m 1 1 1 0 0 0
	case LoadI32:
		return m, 1, 1, 1, 0, 0, 0 //load_i32 m 1 1 1 0 0 0
	case LoadU64:
		return m, 1, 1, 1, 0, 0, 0 //load_u64 m 1 1 1 0 0 0
	case StoreImmIndU8:
		return 25, 1, 1, 0, 1, 0, 0 //store_imm_ind_u8 25 1 1 0 1 0 0
	case StoreImmIndU16:
		return 25, 1, 1, 0, 1, 0, 0 //store_imm_ind_u16 25 1 1 0 1 0 0
	case StoreImmIndU32:
		return 25, 1, 1, 0, 1, 0, 0 //store_imm_ind_u32 25 1 1 0 1 0 0
	case StoreImmIndU64:
		return 25, 1, 1, 0, 1, 0, 0 //store_imm_ind_u64 25 1 1 0 1 0 0
	case StoreIndU8:
		return 25, 1, 1, 0, 1, 0, 0 //store_ind_u8 25 1 1 0 1 0 0
	case StoreIndU16:
		return 25, 1, 1, 0, 1, 0, 0 //store_ind_u16 25 1 1 0 1 0 0
	case StoreIndU32:
		return 25, 1, 1, 0, 1, 0, 0 //store_ind_u32 25 1 1 0 1 0 0
	case StoreIndU64:
		return 25, 1, 1, 0, 1, 0, 0 //store_ind_u64 25 1 1 0 1 0 0
	case StoreImmU8:
		return 25, 1, 1, 0, 1, 0, 0 //store_imm_u8 25 1 1 0 1 0 0
	case StoreImmU16:
		return 25, 1, 1, 0, 1, 0, 0 //store_imm_u16 25 1 1 0 1 0 0
	case StoreImmU32:
		return 25, 1, 1, 0, 1, 0, 0 //store_imm_u32 25 1 1 0 1 0 0
	case StoreImmU64:
		return 25, 1, 1, 0, 1, 0, 0 //store_imm_u64 25 1 1 0 1 0 0
	case StoreU8:
		return 25, 1, 1, 0, 1, 0, 0 //store_u8 25 1 1 0 1 0 0
	case StoreU16:
		return 25, 1, 1, 0, 1, 0, 0 //store_u16 25 1 1 0 1 0 0
	case StoreU32:
		return 25, 1, 1, 0, 1, 0, 0 //store_u32 25 1 1 0 1 0 0
	case StoreU64:
		return 25, 1, 1, 0, 1, 0, 0 //store_u64 25 1 1 0 1 0 0
	case BranchEq:
		return p.branchCost(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_eq b 1 1 0 0 0 0
	case BranchNe:
		return p.branchCost(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_ne b 1 1 0 0 0 0
	case BranchLtU:
		return p.branchCost(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_lt_u b 1 1 0 0 0 0
	case BranchLtS:
		return p.branchCost(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_lt_s b 1 1 0 0 0 0
	case BranchGeU:
		return p.branchCost(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_ge_u b 1 1 0 0 0 0
	case BranchGeS:
		return p.branchCost(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_ge_s b 1 1 0 0 0 0
	case BranchEqImm:
		return p.branchCostImm(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_eq_imm b 1 1 0 0 0 0
	case BranchNeImm:
		return p.branchCostImm(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_ne_imm b 1 1 0 0 0 0
	case BranchLtUImm:
		return p.branchCostImm(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_lt_u_imm b 1 1 0 0 0 0
	case BranchLeUImm:
		return p.branchCostImm(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_le_u_imm b 1 1 0 0 0 0
	case BranchGeUImm:
		return p.branchCostImm(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_ge_u_imm b 1 1 0 0 0 0
	case BranchGtUImm:
		return p.branchCostImm(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_gt_u_imm b 1 1 0 0 0 0
	case BranchLtSImm:
		return p.branchCostImm(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_lt_s_imm b 1 1 0 0 0 0
	case BranchLeSImm:
		return p.branchCostImm(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_le_s_imm b 1 1 0 0 0 0
	case BranchGeSImm:
		return p.branchCostImm(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_ge_s_imm b 1 1 0 0 0 0
	case BranchGtSImm:
		return p.branchCostImm(instructionCounter), 1, 1, 0, 0, 0, 0 //branch_gt_s_imm b 1 1 0 0 0 0
	case DivU32:
		return 60, 4, 1, 0, 0, 0, 1 //div_u_32 60 4 1 0 0 0 1
	case DivS32:
		return 60, 4, 1, 0, 0, 0, 1 //div_s_32 60 4 1 0 0 0 1
	case RemU32:
		return 60, 4, 1, 0, 0, 0, 1 //rem_u_32 60 4 1 0 0 0 1
	case RemS32:
		return 60, 4, 1, 0, 0, 0, 1 //rem_s_32 60 4 1 0 0 0 1
	case DivU64:
		return 60, 4, 1, 0, 0, 0, 1 //div_u_64 60 4 1 0 0 0 1
	case DivS64:
		return 60, 4, 1, 0, 0, 0, 1 //div_s_64 60 4 1 0 0 0 1
	case RemU64:
		return 60, 4, 1, 0, 0, 0, 1 //rem_u_64 60 4 1 0 0 0 1
	case RemS64:
		return 60, 4, 1, 0, 0, 0, 1 //rem_s_64 60 4 1 0 0 0 1
	case AndInv:
		return 2, 3, 1, 0, 0, 0, 0 //and_inv 2 3 1 0 0 0 0
	case OrInv:
		return 2, 3, 1, 0, 0, 0, 0 //or_inv 2 3 1 0 0 0 0
	case Xnor:
		return 2, p.overlaps3Regs(instructionCounter, 2, 3), 1, 0, 0, 0, 0 //xnor 2 P(2,3) 1 0 0 0 0
	case NegAddImm64:
		return 2, 3, 1, 0, 0, 0, 0 //neg_add_imm_64 2 3 1 0 0 0 0
	case NegAddImm32:
		return 3, 4, 1, 0, 0, 0, 0 //neg_add_imm_32 3 4 1 0 0 0 0
	case LoadImm:
		return 1, 1, 0, 0, 0, 0, 0 //load_imm 1 1 0 0 0 0 0
	case LoadImm64:
		return 1, 2, 0, 0, 0, 0, 0 //load_imm_64 1 2 0 0 0 0 0
	case Mul64:
		return 3, p.overlaps3Regs(instructionCounter, 1, 2), 1, 0, 0, 1, 0 //mul_64 3 P(1,2) 1 0 0 1 0
	case Mul32:
		return 4, p.overlaps3Regs(instructionCounter, 2, 3), 1, 0, 0, 1, 0 //mul_32 4 P(2,3) 1 0 0 1 0
	case MulImm64:
		return 3, p.overlaps2RegsImm(instructionCounter, 1, 2), 1, 0, 0, 1, 0 //mul_imm_64 3 P(1,2) 1 0 0 1 0
	case MulImm32:
		return 4, p.overlaps2RegsImm(instructionCounter, 2, 3), 1, 0, 0, 1, 0 //mul_imm_32 4 P(2,3) 1 0 0 1 0
	case MulUpperSS:
		return 4, 4, 1, 0, 0, 1, 0 //mul_upper_s_s 4 4 1 0 0 1 0
	case MulUpperUU:
		return 4, 4, 1, 0, 0, 1, 0 //mul_upper_u_u 4 4 1 0 0 1 0
	case MulUpperSU:
		return 6, 4, 1, 0, 0, 1, 0 //mul_upper_s_u 6 4 1 0 0 1 0
	case Trap:
		return 2, 1, 0, 0, 0, 0, 0 //trap 2 1 0 0 0 0 0
	case Fallthrough:
		return 2, 1, 0, 0, 0, 0, 0 //fallthrough 2 1 0 0 0 0 0
	case Unlikely:
		return 40, 1, 0, 0, 0, 0, 0 //unlikely 40 1 0 0 0 0 0
	case Jump:
		return 15, 1, 0, 0, 0, 0, 0 //jump 15 1 0 0 0 0 0
	case LoadImmJump:
		return 15, 1, 0, 0, 0, 0, 0 //load_imm_jump 15 1 0 0 0 0 0
	case JumpInd:
		return 22, 1, 0, 0, 0, 0, 0 //jump_ind 22 1 0 0 0 0 0
	case LoadImmJumpInd:
		return 22, 1, 0, 0, 0, 0, 0 //load_imm_jump_ind 22 1 0 0 0 0 0
	case Ecalli:
		return 100, 4, 1, 0, 0, 0, 0 //ecalli 100 4 1 0 0 0 0
	}
	panic("unable to get cost for instruction")
}

// Decode costs
const (
	m = 25 // m = 25
)
