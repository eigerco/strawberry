package host_call

import (
	"maps"
	"math"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	. "github.com/eigerco/strawberry/internal/polkavm"
	. "github.com/eigerco/strawberry/internal/polkavm/util"
	"github.com/eigerco/strawberry/internal/state"
)

// Empower ΩE (ξ, ω, μ, (x, y))
func Empower(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < EmpowerCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= EmpowerCost

	// let [m, a, v, o, n] = ω0...5
	m, a, v, o, n := regs[A0], regs[A1], regs[A2], regs[A3], regs[A4]

	// let g = {(s ↦ g) where E4(s) ⌢ E8(g) = do+12i⋅⋅⋅+12 | i ∈ Nn} if Zo⋅⋅⋅+12n ⊂ Vμ otherwise ∇
	for i := range n {
		s, err := readNumber[block.ServiceId](mem, o+(12*i), 4)
		if err != nil {
			return gas, withCode(regs, OOB), mem, ctxPair, err
		}
		g, err := readNumber[uint64](mem, o+(12*i)+4, 8)
		if err != nil {
			return gas, withCode(regs, OOB), mem, ctxPair, err
		}

		ctxPair.RegularCtx.PrivilegedServices.AmountOfGasPerServiceId[s] = g
	}
	ctxPair.RegularCtx.PrivilegedServices.ManagerServiceId = block.ServiceId(m)
	ctxPair.RegularCtx.PrivilegedServices.AssignServiceId = block.ServiceId(a)
	ctxPair.RegularCtx.PrivilegedServices.DesignateServiceId = block.ServiceId(v)
	return gas, regs, mem, ctxPair, nil
}

// Assign ΩA(ξ, ω, μ, (x, y))
func Assign(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < AssignCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= AssignCost

	// let o = ω1
	addr := regs[A1]
	core := regs[A0]
	if core >= uint32(common.TotalNumberOfCores) {
		return gas, withCode(regs, CORE), mem, ctxPair, nil
	}
	for i := 0; i < state.PendingAuthorizersQueueSize; i++ {
		bytes := make([]byte, 32)
		if err := mem.Read(addr+uint32(32*i), bytes); err != nil {
			return gas, withCode(regs, OOB), mem, ctxPair, nil
		}
		ctxPair.RegularCtx.AuthorizationsQueue[core][i] = crypto.Hash(bytes)
	}
	return gas, regs, mem, ctxPair, nil
}

// Designate ΩD (ξ, ω, μ, (x, y))
func Designate(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < DesignateCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= DesignateCost

	const (
		bandersnatch = crypto.BandersnatchSize
		ed25519      = bandersnatch + 32
		bls          = ed25519 + crypto.BLSSize
		metadata     = bls + crypto.MetadataSize
	)
	// let o = ω0
	addr := regs[A0]
	for i := 0; i < common.NumberOfValidators; i++ {
		bytes := make([]byte, 336)
		if err := mem.Read(addr+uint32(336*i), bytes); err != nil {
			return gas, withCode(regs, OOB), mem, ctxPair, nil
		}

		ctxPair.RegularCtx.ValidatorKeys[i] = crypto.ValidatorKey{
			Bandersnatch: crypto.BandersnatchPublicKey(bytes[:bandersnatch]),
			Ed25519:      bytes[bandersnatch:ed25519],
			Bls:          crypto.BlsKey(bytes[ed25519:bls]),
			Metadata:     crypto.MetadataKey(bytes[bls:metadata]),
		}
	}

	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Checkpoint ΩC (ξ, ω, μ, (x, y))
func Checkpoint(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < CheckpointCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= CheckpointCost

	ctxPair.ExceptionalCtx = ctxPair.RegularCtx

	// Split the new ξ' value into its lower and upper parts.
	regs[A0] = uint32(gas & ((1 << 32) - 1))
	regs[A1] = uint32(gas >> 32)

	return gas, regs, mem, ctxPair, nil
}

// New ΩN (ξ, ω, μ, (x, y))
func New(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < NewCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= NewCost

	// let [o, l, gl, gh, ml, mh] = ω0..6
	o, l, gl, gh, ml, mh := regs[A0], regs[A1], regs[A2], regs[A3], regs[A4], regs[A5]

	// c = μo⋅⋅⋅+32 if No⋅⋅⋅+32 ⊂ Vμ otherwise ∇
	c := make([]byte, 32)
	if err := mem.Read(o, c); err != nil {
		return gas, withCode(regs, OOB), mem, ctxPair, nil
	}
	// let g = 2^32 ⋅ gh + gl
	g := 1<<32*uint64(gh) + uint64(gl)

	// let m = 2^32 ⋅ mh + ml
	m := 1<<32*uint64(mh) + uint64(ml)

	codeHash := crypto.Hash(c)

	// let a = (c, s ∶ {}, l ∶ {(c, l) ↦ []}, b ∶ at, g, m) if c ≠ ∇
	a := state.ServiceAccount{
		Storage: make(map[crypto.Hash][]byte),
		PreimageMeta: map[state.PreImageMetaKey]state.PreimageHistoricalTimeslots{
			{Hash: codeHash, Length: state.PreimageLength(l)}: {},
		},
		CodeHash:               codeHash,
		GasLimitForAccumulator: g,
		GasLimitOnTransfer:     m,
	}
	a.Balance = a.ThresholdBalance()

	// let b = (Xs)b − at
	b := ctxPair.RegularCtx.ServiceAccount.Balance - a.ThresholdBalance()

	// if a ≠ ∇ ∧ b ≥ (xs)t
	if b >= ctxPair.RegularCtx.ServiceAccount.ThresholdBalance() {
		ctxPair.RegularCtx.ServiceID = Check(Bump(ctxPair.RegularCtx.ServiceID), ctxPair.RegularCtx.ServicesState)
		ctxPair.RegularCtx.ServicesState[ctxPair.RegularCtx.ServiceID] = a
		ctxPair.RegularCtx.ServiceAccount.Balance = b
		regs[A0] = uint32(ctxPair.RegularCtx.ServiceID)
		return gas, regs, mem, ctxPair, nil
	}

	// otherwise
	return gas, withCode(regs, CASH), mem, ctxPair, nil
}

// Upgrade ΩU (ξ, ω, μ, (x, y))
func Upgrade(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < UpgradeCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= UpgradeCost
	// let [o, gh, gl, mh, ml] = ω0..5
	o, gh, gl, mh, ml := regs[A0], regs[A1], regs[A2], regs[A3], regs[A4]

	// c = μo⋅⋅⋅+32 if No⋅⋅⋅+32 ⊂ Vμ otherwise ∇
	c := make([]byte, 32)
	if err := mem.Read(o, c); err != nil {
		return gas, withCode(regs, OOB), mem, ctxPair, nil
	}

	// let g = 2^32 ⋅ gh + gl
	g := Bit32*uint64(gh) + uint64(gl)

	// let m = 2^32 ⋅ mh + ml
	m := Bit32*uint64(mh) + uint64(ml)

	// (ω′7, (x′s)c, (x′s)g , (x′s)m) = (OK, c, g, m) if c ≠ ∇
	ctxPair.RegularCtx.ServiceAccount.CodeHash = crypto.Hash(c)
	ctxPair.RegularCtx.ServiceAccount.GasLimitForAccumulator = g
	ctxPair.RegularCtx.ServiceAccount.GasLimitOnTransfer = m
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Transfer ΩT (ξ, ω, μ, (x, y), s, δ)
func Transfer(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, serviceIndex block.ServiceId, serviceState state.ServiceState) (Gas, Registers, Memory, AccumulateContextPair, error) {
	transferCost := TransferBaseCost + Gas(regs[A1]) + 1<<32*Gas(regs[A2])
	if gas < transferCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= transferCost

	// let (d, al, ah, gl, gh, o) = ω0..6
	d, al, ah, gl, gh, o := regs[A0], regs[A1], regs[A2], regs[A3], regs[A4], regs[A5]

	// let a = 2^32 ⋅ ah + al
	a := Bit32*uint64(ah) + uint64(al)

	// let g = 2^32 ⋅ gh + gl
	g := Bit32*uint64(gh) + uint64(gl)

	// m = μo⋅⋅⋅+M if No⋅⋅⋅+M ⊂ Vμ otherwise ∇
	m := make([]byte, state.TransferMemoSizeBytes)
	if err := mem.Read(o, m); err != nil {
		return gas, withCode(regs, OK), mem, ctxPair, nil
	}

	// let t ∈ T ∪ {∇} = (s, d, a, m, g)
	t := state.DeferredTransfer{
		SenderServiceIndex:   serviceIndex,
		ReceiverServiceIndex: block.ServiceId(d),
		Balance:              a,
		Memo:                 state.Memo(m),
		GasLimit:             g,
	}
	// let b = (xs)b − a
	b := ctxPair.RegularCtx.ServiceAccount.Balance - a

	mm := maps.Clone(serviceState)
	maps.Copy(mm, ctxPair.RegularCtx.ServicesState)

	service, ok := mm[block.ServiceId(d)]
	// if d !∈ K(δ ∪ xn)
	if !ok {
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	// if g < (δ ∪ xn)[d]m
	if g < service.GasLimitOnTransfer {
		return gas, withCode(regs, LOW), mem, ctxPair, nil
	}

	// if ξ < g
	if gas < Gas(g) {
		return gas, withCode(regs, HIGH), mem, ctxPair, nil
	}

	// if b < (xs)t
	if b < ctxPair.RegularCtx.ServiceAccount.ThresholdBalance() {
		return gas, withCode(regs, CASH), mem, ctxPair, nil
	}

	ctxPair.RegularCtx.DeferredTransfers = append(ctxPair.RegularCtx.DeferredTransfers, t)
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Quit ΩQ(ξ, ω, μ, (x, y), s, δ)
func Quit(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, serviceIndex block.ServiceId, serviceState state.ServiceState) (Gas, Registers, Memory, AccumulateContextPair, error) {
	quitCost := QuitBaseCost + Gas(regs[A1]) + 1<<32*Gas(regs[A2])
	if gas < quitCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= quitCost

	// let [d, o] = ω0,1
	d, o := regs[A0], regs[A1]
	//let a = (xs)b − (xs)t + BS
	a := ctxPair.RegularCtx.ServiceAccount.Balance - ctxPair.RegularCtx.ServiceAccount.ThresholdBalance() + state.BasicMinimumBalance
	//let g = ξ
	g := uint64(gas)

	// m = E−1(μo⋅⋅⋅+M)
	m := make([]byte, state.TransferMemoSizeBytes)
	if err := mem.Read(o, m); err != nil {
		return gas, withCode(regs, OOB), mem, ctxPair, nil
	}

	// if d ∈ {s, 2^32 − 1}
	if block.ServiceId(d) == serviceIndex || d == math.MaxUint32 {
		return gas, withCode(regs, OK), mem, ctxPair, ErrHalt
	}
	// let t ∈ T ≡ (s, d, a, m, g)
	t := state.DeferredTransfer{
		SenderServiceIndex:   serviceIndex,
		ReceiverServiceIndex: block.ServiceId(d),
		Balance:              a,
		Memo:                 state.Memo(m),
		GasLimit:             g,
	}
	mm := maps.Clone(serviceState)
	maps.Copy(mm, ctxPair.RegularCtx.ServicesState)

	service, ok := mm[block.ServiceId(d)]
	// if d !∈ K(δ ∪ xn)
	if !ok {
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	//if g < (δ ∪ xn)[d]m
	if g < service.GasLimitOnTransfer {
		return gas, withCode(regs, LOW), mem, ctxPair, nil
	}

	ctxPair.RegularCtx.DeferredTransfers = append(ctxPair.RegularCtx.DeferredTransfers, t)
	return gas, withCode(regs, OK), mem, ctxPair, ErrHalt
}

// Solicit ΩS (ξ, ω, μ, (x, y), t)
func Solicit(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < SolicitCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= SolicitCost

	// let [o, z] = ω0,1
	o, z := regs[0], regs[1]
	// let h = μo⋅⋅⋅+32 if Zo⋅⋅⋅+32 ⊂ Vμ otherwise ∇
	h := make([]byte, 32)
	if err := mem.Read(o, h); err != nil {
		return gas, withCode(regs, OOB), mem, ctxPair, nil
	}

	// let a = xs
	a := *ctxPair.RegularCtx.ServiceAccount
	preimageHash := crypto.Hash(h)
	// (h, z)
	key := state.PreImageMetaKey{Hash: preimageHash, Length: state.PreimageLength(z)}

	if _, ok := a.PreimageMeta[key]; !ok {
		// except: al[(h, z)] = [] if h ≠ ∇ ∧ (h, z) !∈ (xs)l
		a.PreimageMeta[key] = state.PreimageHistoricalTimeslots{}
	} else if len(a.PreimageMeta[key]) == 2 {
		// except: al[(h, z)] = (xs)l[(h, z)] ++ t if (xs)l[(h, z)] = [x, y]
		a.PreimageMeta[key] = append(a.PreimageMeta[key], timeslot)
	} else {
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	// if ab < at
	if a.Balance < a.ThresholdBalance() {
		return gas, withCode(regs, FULL), mem, ctxPair, nil
	}

	ctxPair.RegularCtx.ServiceAccount = &a
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Forget ΩF (ξ, ω, μ, (x, y), Ht)
func Forget(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < ForgetCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= ForgetCost

	// let [o, z] = ω0,1
	o, z := regs[A0], regs[A1]

	// let h = μo⋅⋅⋅+32 if Zo⋅⋅⋅+32 ⊂ Vμ otherwise ∇
	h := make([]byte, 32)
	if err := mem.Read(o, h); err != nil {
		return gas, withCode(regs, OOB), mem, ctxPair, nil
	}

	// let a = xs
	a := *ctxPair.RegularCtx.ServiceAccount
	preimageHash := crypto.Hash(h)

	// (h, z)
	key := state.PreImageMetaKey{Hash: preimageHash, Length: state.PreimageLength(z)}

	switch len(a.PreimageMeta[key]) {
	case 0: // if (xs)l[h, z] ∈ {[]}

		// except: K(al) = K((xs)l) ∖ {(h, z)}
		// except: K(ap) = K((xs)p) ∖ {h}
		delete(a.PreimageMeta, key)
		delete(a.PreimageLookup, preimageHash)

		ctxPair.RegularCtx.ServiceAccount = &a
		return gas, withCode(regs, OK), mem, ctxPair, nil

	case 2: // if (xs)l[h, z] ∈ {[], [x, y]}, y < t − D
		if a.PreimageMeta[key][1] < timeslot-jamtime.PreimageExpulsionPeriod {

			// except: K(al) = K((xs)l) ∖ {(h, z)}
			// except: K(ap) = K((xs)p) ∖ {h}
			delete(a.PreimageMeta, key)
			delete(a.PreimageLookup, preimageHash)

			ctxPair.RegularCtx.ServiceAccount = &a
			return gas, withCode(regs, OK), mem, ctxPair, nil
		}

	case 1: // if S(xs)l[h, z]S = 1

		// except: al[h, z] = (xs)l[h, z] ++ t
		a.PreimageMeta[key] = append(a.PreimageMeta[key], timeslot)

		ctxPair.RegularCtx.ServiceAccount = &a
		return gas, withCode(regs, OK), mem, ctxPair, nil

	case 3: // if (xs)l[h, z] = [x, y, w]
		if a.PreimageMeta[key][1] < timeslot-jamtime.PreimageExpulsionPeriod { // if y < t − D

			// except: al[h, z] = [(xs)l[h, z]2, t]
			a.PreimageMeta[key] = state.PreimageHistoricalTimeslots{a.PreimageMeta[key][2], timeslot}
			return gas, withCode(regs, OK), mem, ctxPair, nil
		}
	}

	return gas, withCode(regs, HUH), mem, ctxPair, nil
}
