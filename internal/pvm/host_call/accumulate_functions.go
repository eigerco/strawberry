package host_call

import (
	"bytes"
	"errors"
	"math"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	. "github.com/eigerco/strawberry/internal/pvm" //nolint:staticcheck // TODO: remove dot import
	"github.com/eigerco/strawberry/internal/safemath"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// Bless ΩB(ϱ, φ, μ, (x, y)) (v0.7.1)
func Bless(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	gas -= BlessCost

	// let [m, a, v, r, o, n] = φ7...13
	managerServiceId, assignServiceAddr, designateServiceId, createProtectedServiceId, addr, servicesNr := regs[R7], regs[R8], regs[R9], regs[R10], regs[R11], regs[R12]

	// let g = {(s ↦ g) where E4(s) ⌢ E8(g) = μ_o+12i⋅⋅⋅+12 | i ∈ Nn} if No⋅⋅⋅+12n ⊂ Vμ otherwise ∇
	gasPerServiceId := make(map[block.ServiceId]uint64)
	for i := range servicesNr {
		serviceId, err := readNumber[block.ServiceId](mem, addr+(12*i), 4)
		if err != nil {
			// (ℓ, φ_7, (x_e)_(m,a,v,r,z)) if {z, a} ∋ ∇
			return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
		}
		serviceGas, err := readNumber[uint64](mem, addr+(12*i)+4, 8)
		if err != nil {
			// (ℓ, φ_7, (x_e)_(m,a,v,r,z)) if {z, a} ∋ ∇
			return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
		}

		gasPerServiceId[serviceId] = serviceGas
	}

	// Na⋅⋅⋅+4C ⊆ Vµ
	assignersBytes := make([]byte, 4*constants.TotalNumberOfCores)
	if assignServiceAddr > math.MaxUint32 {
		return gas, regs, mem, ctxPair, ErrPanicf("inaccessible memory, address out of range")
	}
	if err := mem.Read(uint32(assignServiceAddr), assignersBytes); err != nil {
		// (ℓ, φ_7, (x_e)_(m,a,v,r,z)) if {z, a} ∋ ∇
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}
	// (E−1(4) (µa⋅⋅⋅+4C)
	var assigners [constants.TotalNumberOfCores]block.ServiceId
	err := jam.Unmarshal(assignersBytes, &assigners)
	if err != nil {
		// (ℓ, φ_7, (x_e)_(m,a,v,r,z)) if {z, a} ∋ ∇
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}
	// (▷, WHO, (x_e)_(m,a,v,r,z)) otherwise if (m, v, r) ∉ ℕ³_S
	if !isServiceId(managerServiceId) || !isServiceId(designateServiceId) || !isServiceId(createProtectedServiceId) {
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	// (▷, OK, (m, a, v, r, z)) otherwise
	ctxPair.RegularCtx.AccumulationState.ManagerServiceId = block.ServiceId(managerServiceId)
	ctxPair.RegularCtx.AccumulationState.AssignedServiceIds = assigners
	ctxPair.RegularCtx.AccumulationState.DesignateServiceId = block.ServiceId(designateServiceId)
	ctxPair.RegularCtx.AccumulationState.CreateProtectedServiceId = block.ServiceId(createProtectedServiceId)
	ctxPair.RegularCtx.AccumulationState.AmountOfGasPerServiceId = gasPerServiceId
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Assign ΩA(ϱ, φ, μ, (x, y)) (v0.7.1)
//
// Function: assign = 15
// Gas: g = 10
//
// let [c, o, a] = φ7···+3
// let q = { [μo+32i···+32 | i ← NQ]  if No···+32Q ⊆ Vμ
//
//	{ ∇                        otherwise
//
// (ε', φ'7, (x'e)q[c], (x'e)a[c]) =
//
//	{ (☇, φ7, (xe)q[c], (xe)a[c])     if q = ∇
//	{ (▸, CORE, (xe)q[c], (xe)a[c])   otherwise if c ≥ C
//	{ (▸, HUH, (xe)q[c], (xe)a[c])    otherwise if xs ≠ (xe)a[c]
//	{ (▸, WHO, (xe)q[c], (xe)a[c])    otherwise if a ∉ NS
//	{ (▸, OK, q, a)                   otherwise
func Assign(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	gas -= AssignCost

	// let [c, o, a] = φ7···+3
	core, addr, newAssigner := regs[R7], regs[R8], regs[R9]

	// Read the queue from memory first (can panic on invalid memory access)
	// q = [μo+32i···+32 | i ← NQ] if No···+32Q ⊆ Vμ otherwise ∇
	// (☇, φ7, (xe)q[c], (xe)a[c]) if q = ∇
	var queue [constants.PendingAuthorizersQueueSize]crypto.Hash
	for i := range constants.PendingAuthorizersQueueSize {
		bytes := make([]byte, 32)
		queueAddr, ok := safemath.Add(addr, 32*uint64(i))
		if !ok {
			return gas, regs, mem, ctxPair, ErrPanicf("address overflow")
		}
		if queueAddr > math.MaxUint32 {
			return gas, regs, mem, ctxPair, ErrPanicf("inaccessible memory, address out of range")
		}
		if err := mem.Read(uint32(queueAddr), bytes); err != nil {
			return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
		}
		queue[i] = crypto.Hash(bytes)
	}

	// (▸, CORE, ...) otherwise if c ≥ C
	if core >= uint64(constants.TotalNumberOfCores) {
		return gas, withCode(regs, CORE), mem, ctxPair, nil
	}

	// (▸, HUH, ...) otherwise if xs ≠ (xe)a[c]
	xs := ctxPair.RegularCtx.ServiceId
	currentAssigned := ctxPair.RegularCtx.AccumulationState.AssignedServiceIds[core]
	if currentAssigned != xs {
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	// (▸, WHO, ...) otherwise if a ∉ NS
	// First check if newAssigner doesn't overflow, otherwise it truncates to 0.
	if !isServiceId(newAssigner) {
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}
	if _, exists := ctxPair.RegularCtx.AccumulationState.ServiceState[block.ServiceId(newAssigner)]; !exists {
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	// (▸, OK, q, a) otherwise
	ctxPair.RegularCtx.AccumulationState.PendingAuthorizersQueues[core] = queue
	ctxPair.RegularCtx.AccumulationState.AssignedServiceIds[core] = block.ServiceId(newAssigner)

	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Designate ΩD (ϱ, φ, μ, (x, y))
func Designate(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	gas -= DesignateCost

	const (
		bandersnatch = crypto.BandersnatchSize
		ed25519      = bandersnatch + crypto.Ed25519PublicSize
		bls          = ed25519 + crypto.BLSSize
		metadata     = bls + crypto.MetadataSize
	)

	// let o = φ7
	addr := regs[R7]
	for i := 0; i < constants.NumberOfValidators; i++ {
		bytes := make([]byte, 336)
		valAddr, ok := safemath.Add(addr, 336*uint64(i))
		if !ok {
			return gas, regs, mem, ctxPair, ErrPanicf("address overflow")
		}
		if valAddr > math.MaxUint32 {
			return gas, regs, mem, ctxPair, ErrPanicf("inaccessible memory, address out of range")
		}
		if err := mem.Read(uint32(valAddr), bytes); err != nil {
			return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
		}

		ctxPair.RegularCtx.AccumulationState.ValidatorKeys[i] = crypto.ValidatorKey{
			Bandersnatch: crypto.BandersnatchPublicKey(bytes[:bandersnatch]),
			Ed25519:      bytes[bandersnatch:ed25519],
			Bls:          crypto.BlsKey(bytes[ed25519:bls]),
			Metadata:     crypto.MetadataKey(bytes[bls:metadata]),
		}
	}

	xs := ctxPair.RegularCtx.ServiceId
	designator := ctxPair.RegularCtx.AccumulationState.DesignateServiceId
	if xs != designator {
		// if xs ≠ (xe)v
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Checkpoint ΩC(ϱ, φ, μ, (x, y))
func Checkpoint(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	gas -= CheckpointCost

	ctxPair.ExceptionalCtx = ctxPair.RegularCtx.Clone()

	// Set the new ϱ' value into φ′7
	regs[R7] = uint64(gas)

	return gas, regs, mem, ctxPair, nil
}

// New ΩN(ϱ, φ, μ, (x, y), t) (v0.7.1)
// ΩN(ϱ, φ, µ, (x,y), t)
// new = 18, g = 10
// let [o, l, g, m, f, i] = φ7...+6
// let c = µo...+32 if No...+32 ⊆ Vµ ∧ l ∈ N²³² otherwise ∇
// let a = (c, s▸▸{}, l▸▸{((c,l)↦[])}, b▸▸at, g, m, p▸▸{}, r▸▸t, f, a▸▸0, p▸▸xs) if c ≠ ∇, otherwise ∇
// let s = xs except sb = (xs)b − at
// (ε′, φ′7, x′i, (x′e)d) ≡
//
//	(☇, φ7, xi, (xe)d)           if c = ∇
//	(▸, HUH, xi, (xe)d)          otherwise if f ≠ 0 ∧ xs ≠ (xe)m
//	(▸, CASH, xi, (xe)d)         otherwise if sb < (xs)t
//	(▸, FULL, xi, (xe)d)         otherwise if xs = (xe)r ∧ i < S ∧ i ∈ K((xe)d)
//	(▸, i, xi, (xe)d ∪ d)        otherwise if xs = (xe)r ∧ i < S
//	                              where d = {(i ↦ a), (xs ↦ s)}
//	(▸, xi, i*, (xe)d ∪ d)       otherwise
//	                              where i* = check(S + (xi − S + 42) mod (2³² − S − 2⁸))
//	                              and d = {(xi ↦ a), (xs ↦ s)}
//
// New ΩN(ϱ, φ, μ, (x, y), t) (v0.7.1)
func New(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
	gas -= NewCost

	// let [o, l, g, m, f, i] = φ7..+6
	addr := regs[R7]
	preimageLength := regs[R8]
	gasLimitAccumulator := regs[R9]
	gasLimitTransfer := regs[R10]
	gratisStorageOffset := regs[R11]
	desiredId := regs[R12]

	// (▸, HUH, x_i, (x_e)_d) otherwise if f ≠ 0 ∧ x_s ≠ (x_e)_m
	xsId := ctxPair.RegularCtx.ServiceId
	managerId := ctxPair.RegularCtx.AccumulationState.ManagerServiceId
	if gratisStorageOffset != 0 && xsId != managerId {
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	// let c = μ_o⋅⋅⋅+32 if N_o⋅⋅⋅+32 ⊂ Vμ ∧ l ∈ N_2^32 otherwise ∇
	if preimageLength >= math.MaxUint32 {
		return gas, regs, mem, ctxPair, ErrPanicf("preimage length exceeds 2^32")
	}

	codeHashBytes := make([]byte, 32)
	if addr > math.MaxUint32 {
		return gas, regs, mem, ctxPair, ErrPanicf("inaccessible memory, address out of range")
	}
	if err := mem.Read(uint32(addr), codeHashBytes); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	codeHash := crypto.Hash(codeHashBytes)

	// Determine actual service ID for the new service
	// Protected path: x_s = (x_e)_r ∧ i < S → use desiredId
	// Regular path: use x_i (NewServiceId)
	registrarId := ctxPair.RegularCtx.AccumulationState.CreateProtectedServiceId
	isProtectedPath := xsId == registrarId && desiredId < service.S

	var actualServiceId block.ServiceId
	if isProtectedPath {
		actualServiceId = block.ServiceId(desiredId)
	} else {
		actualServiceId = ctxPair.RegularCtx.NewServiceId
	}

	// let a = (c, s: {}, l: {(c, l) ↦ []}, b: a_t, g, m, p: {}, r: t, f, a: 0, p: x_s)
	account := service.NewServiceAccount()
	account.CodeHash = codeHash
	account.GasLimitForAccumulator = gasLimitAccumulator
	account.GasLimitOnTransfer = gasLimitTransfer
	account.GratisStorageOffset = gratisStorageOffset
	account.CreationTimeslot = timeslot
	account.MostRecentAccumulationTimeslot = 0
	account.ParentService = xsId

	// l: {((c, l) ↦ [])} - preimage metadata keyed by (codeHash, preimageLength)
	// Key must use actualServiceId since it's interleaved into the StateKey
	k, err := statekey.NewPreimageMeta(actualServiceId, codeHash, uint32(preimageLength))
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	err = account.InsertPreimageMeta(k, preimageLength, service.PreimageHistoricalTimeslots{})
	if err != nil {
		if errors.Is(err, safemath.ErrOverflow) {
			return gas, withCode(regs, FULL), mem, ctxPair, nil
		}
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// b: a_t
	account.Balance, err = account.ThresholdBalance()
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// let s = x_s except s_b = (x_s)_b − a_t
	// (▸, CASH, x_i, (x_e)_d) otherwise if s_b < (x_s)_t
	//
	// Check: (x_s)_b - a_t >= (x_s)_t
	// Rearranged to avoid underflow: (x_s)_b >= a_t + (x_s)_t
	xs := ctxPair.RegularCtx.ServiceAccount()
	newAccountThreshold, err := account.ThresholdBalance()
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}
	creatorThreshold, err := xs.ThresholdBalance()
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// Check for addition overflow
	requiredBalance := newAccountThreshold + creatorThreshold
	if requiredBalance < newAccountThreshold {
		return gas, withCode(regs, CASH), mem, ctxPair, nil
	}

	if xs.Balance < requiredBalance {
		return gas, withCode(regs, CASH), mem, ctxPair, nil
	}

	// Safe to subtract now
	s := xs.Clone()
	s.Balance -= newAccountThreshold

	// Protected path
	// (▸, FULL, x_i, (x_e)_d) otherwise if x_s = (x_e)_r ∧ i < S ∧ i ∈ K((x_e)_d)
	// (▸, i, x_i, (x_e)_d ∪ d) otherwise if x_s = (x_e)_r ∧ i < S
	if isProtectedPath {
		if _, exists := ctxPair.RegularCtx.AccumulationState.ServiceState[actualServiceId]; exists {
			return gas, withCode(regs, FULL), mem, ctxPair, nil
		}

		regs[R7] = uint64(actualServiceId)
		ctxPair.RegularCtx.AccumulationState.ServiceState[actualServiceId] = account
		ctxPair.RegularCtx.AccumulationState.ServiceState[xsId] = s
		return gas, regs, mem, ctxPair, nil
	}

	// Regular path
	// (▸, x_i, i*, (x_e)_d ∪ d) otherwise
	regs[R7] = uint64(actualServiceId)
	nextId := service.BumpIndex(ctxPair.RegularCtx.NewServiceId, ctxPair.RegularCtx.AccumulationState.ServiceState)
	ctxPair.RegularCtx.NewServiceId = nextId
	ctxPair.RegularCtx.AccumulationState.ServiceState[actualServiceId] = account
	ctxPair.RegularCtx.AccumulationState.ServiceState[xsId] = s

	return gas, regs, mem, ctxPair, nil
}

// Upgrade ΩU(ϱ, φ, μ, (x, y))
func Upgrade(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	gas -= UpgradeCost
	// let [o, g, m] = φ7...10
	addr, gasLimitAccumulator, gasLimitTransfer := regs[R7], regs[R8], regs[R9]

	// c = μo⋅⋅⋅+32 if No⋅⋅⋅+32 ⊂ Vμ otherwise ∇
	codeHash := make([]byte, 32)
	if addr > math.MaxUint32 {
		return gas, regs, mem, ctxPair, ErrPanicf("inaccessible memory, address out of range")
	}
	if err := mem.Read(uint32(addr), codeHash); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// (φ′7, (X′s)c, (X′s)g , (X′s)m) = (OK, c, g, m) if c ≠ ∇
	currentService := ctxPair.RegularCtx.ServiceAccount()
	currentService.CodeHash = crypto.Hash(codeHash)
	currentService.GasLimitForAccumulator = gasLimitAccumulator
	currentService.GasLimitOnTransfer = gasLimitTransfer
	ctxPair.RegularCtx.AccumulationState.ServiceState[ctxPair.RegularCtx.ServiceId] = currentService
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Transfer ΩT(ϱ, φ, μ, (x, y))
func Transfer(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	// let (d, a, l, o) = φ7..11
	receiverId, amount, gasLimit, o := regs[R7], regs[R8], regs[R9], regs[R10]

	gas -= TransferBaseCost

	// m = μo⋅⋅⋅+M if No⋅⋅⋅+WT ⊂ Vμ otherwise ∇
	m := make([]byte, service.TransferMemoSizeBytes)
	if o > math.MaxUint32 {
		return gas, regs, mem, ctxPair, ErrPanicf("inaccessible memory, address out of range")
	}
	if err := mem.Read(uint32(o), m); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// let t ∈ T = (s, d, a, m, g)
	deferredTransfer := service.DeferredTransfer{
		SenderServiceIndex:   ctxPair.RegularCtx.ServiceId,
		ReceiverServiceIndex: block.ServiceId(receiverId),
		Balance:              amount,
		Memo:                 service.Memo(m),
		GasLimit:             gasLimit,
	}

	// let d = xd ∪ (xu)d
	allServices := ctxPair.RegularCtx.AccumulationState.ServiceState

	if !isServiceId(receiverId) {
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}
	receiverService, ok := allServices[block.ServiceId(receiverId)]
	// if d !∈ K(d)
	if !ok {
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	// if l < d[d]m
	if gasLimit < receiverService.GasLimitOnTransfer {
		return gas, withCode(regs, LOW), mem, ctxPair, nil
	}

	// let b = (xs)b − a
	// if b < (xs)t
	account := ctxPair.RegularCtx.ServiceAccount()
	accountThresholdBalance, err := account.ThresholdBalance()
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}
	if amount > account.Balance || account.Balance-amount < accountThresholdBalance {
		return gas, withCode(regs, CASH), mem, ctxPair, nil
	}
	account.Balance = account.Balance - amount
	ctxPair.RegularCtx.AccumulationState.ServiceState[ctxPair.RegularCtx.ServiceId] = account
	ctxPair.RegularCtx.DeferredTransfers = append(ctxPair.RegularCtx.DeferredTransfers, deferredTransfer)
	gas -= Gas(gasLimit)
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Eject ΩJ(ϱ, φ, μ, (x, y), t)
func Eject(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
	gas -= EjectCost

	d, o := regs[R7], regs[R8]

	// let h = μo..o+32 if Zo..o+32 ⊂ Vμ
	h := make([]byte, 32)
	if o > math.MaxUint32 {
		return gas, regs, mem, ctxPair, ErrPanicf("inaccessible memory, address out of range")
	}
	if err := mem.Read(uint32(o), h); err != nil {
		// otherwise ∇
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	if !isServiceId(d) {
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}
	if block.ServiceId(d) == ctxPair.RegularCtx.ServiceId {
		// d = x_s => WHO
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	// if d ∈ K((x_u)_d)
	serviceAccount, ok := ctxPair.RegularCtx.AccumulationState.ServiceState[block.ServiceId(d)]
	if !ok {
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	encodedXs, err := jam.Marshal(struct {
		ServiceId block.ServiceId `jam:"length=32"`
	}{ctxPair.RegularCtx.ServiceId})
	if err != nil || !bytes.Equal(serviceAccount.CodeHash[:], encodedXs) {
		// d_c ≠ E32(x_s) => WHO
		return gas, withCode(regs, WHO), mem, ctxPair, err
	}

	if serviceAccount.GetTotalNumberOfItems() != 2 {
		// d_i ≠ 2 => HUH
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	// l = max(81, d_o) - 81
	l := max(81, serviceAccount.GetTotalNumberOfOctets()) - 81

	k, err := statekey.NewPreimageMeta(block.ServiceId(d), crypto.Hash(h), uint32(l))
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}
	historicalTimeslots, ok := serviceAccount.GetPreimageMeta(k)
	if !ok {
		// (h, l) ∉ d_l => HUH
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	// if d_l[h, l] = [x, y], y < t − D => OK
	if len(historicalTimeslots) == 2 && historicalTimeslots[1] < timeslot-constants.PreimageExpulsionPeriod {
		xs := ctxPair.RegularCtx.ServiceAccount()
		// s'_b = ((x_u)d)[x_s]b + d_b
		xs.Balance += serviceAccount.Balance

		delete(ctxPair.RegularCtx.AccumulationState.ServiceState, block.ServiceId(d))
		ctxPair.RegularCtx.AccumulationState.ServiceState[ctxPair.RegularCtx.ServiceId] = xs

		return gas, withCode(regs, OK), mem, ctxPair, nil
	}

	// otherwise => HUH
	return gas, withCode(regs, HUH), mem, ctxPair, nil
}

// Query ΩQ(ϱ, φ, μ, (x, y))
func Query(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	gas -= QueryCost

	addr, preimageMetaKeyLength := regs[R7], regs[R8]

	// let h = μo..o+32 if Zo..o+32 ⊂ Vμ
	h := make([]byte, 32)
	if addr > math.MaxUint32 {
		return gas, regs, mem, ctxPair, ErrPanicf("inaccessible memory, address out of range")
	}
	if err := mem.Read(uint32(addr), h); err != nil {
		// otherwise ∇ => panic
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// let a = (xs)l[h, z] if (h, z) ∈ K((xs)l)
	serviceAccount := ctxPair.RegularCtx.ServiceAccount()

	k, err := statekey.NewPreimageMeta(ctxPair.RegularCtx.ServiceId, crypto.Hash(h), uint32(preimageMetaKeyLength))
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	a, exists := serviceAccount.GetPreimageMeta(k)
	if !exists {
		// a = ∇ => (NONE, 0)
		regs[R8] = 0
		return gas, withCode(regs, NONE), mem, ctxPair, nil
	}

	switch len(a) {
	case 0:
		// a = [] => (0, 0)
		regs[R7], regs[R8] = 0, 0
	case 1:
		// a = [x] => (1 + 2^32 * x, 0)
		regs[R7], regs[R8] = 1+(uint64(a[0])<<32), 0
	case 2:
		// a = [x, y] => (2 + 2^32 * x, y)
		regs[R7], regs[R8] = 2+(uint64(a[0])<<32), uint64(a[1])
	case 3:
		// a = [x, y, z] => (3 + 2^32 * x, y + 2^32 * z)
		regs[R7], regs[R8] = 3+(uint64(a[0])<<32), uint64(a[1])+(uint64(a[2])<<32)
	}

	return gas, regs, mem, ctxPair, nil
}

// Solicit ΩS(ϱ, φ, μ, (x, y), t)
func Solicit(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
	gas -= SolicitCost

	// let [o, z] = φ7,8
	addr, preimageLength := regs[R7], regs[R8]
	// let h = μo⋅⋅⋅+32 if Zo⋅⋅⋅+32 ⊂ Vμ otherwise ∇
	preimageHashBytes := make([]byte, 32)
	if addr > math.MaxUint32 {
		return gas, regs, mem, ctxPair, ErrPanicf("inaccessible memory, address out of range")
	}
	if err := mem.Read(uint32(addr), preimageHashBytes); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// let a = xs
	serviceAccount := ctxPair.RegularCtx.ServiceAccount()
	preimageHash := crypto.Hash(preimageHashBytes)

	// (h, z)
	k, err := statekey.NewPreimageMeta(ctxPair.RegularCtx.ServiceId, preimageHash, uint32(preimageLength))
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}
	preimageMeta, ok := serviceAccount.GetPreimageMeta(k)

	if !ok {
		// except: al[(h, z)] = [] if h ≠ ∇ ∧ (h, z) !∈ (xs)l
		err = serviceAccount.InsertPreimageMeta(k, preimageLength, service.PreimageHistoricalTimeslots{})
		if err != nil {
			if errors.Is(err, safemath.ErrOverflow) {
				return gas, withCode(regs, FULL), mem, ctxPair, nil
			}
			return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
		}
	} else if len(preimageMeta) == 2 {
		// except: al[(h, z)] = (xs)l[(h, z)] ++ t if (xs)l[(h, z)] = [X, Y]
		preimageMeta = append(preimageMeta, timeslot)
		err = serviceAccount.UpdatePreimageMeta(k, preimageMeta)
		if err != nil {
			return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
		}
	} else {
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	// if ab < at
	serviceAccountThresholdBalance, err := serviceAccount.ThresholdBalance()
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}
	if serviceAccount.Balance < serviceAccountThresholdBalance {
		return gas, withCode(regs, FULL), mem, ctxPair, nil
	}

	ctxPair.RegularCtx.AccumulationState.ServiceState[ctxPair.RegularCtx.ServiceId] = serviceAccount
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Forget ΩF(ϱ, φ, μ, (x, y), t)
func Forget(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
	gas -= ForgetCost

	// let [o, z] = φ0,1
	addr, preimageLength := regs[R7], regs[R8]

	// let h = μo⋅⋅⋅+32 if Zo⋅⋅⋅+32 ⊂ Vμ otherwise ∇
	preimageHashBytes := make([]byte, 32)
	if addr > math.MaxUint32 {
		return gas, regs, mem, ctxPair, ErrPanicf("inaccessible memory, address out of range")
	}
	if err := mem.Read(uint32(addr), preimageHashBytes); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// let a = xs
	serviceAccount := ctxPair.RegularCtx.ServiceAccount()
	preimageHash := crypto.Hash(preimageHashBytes)

	// (h, z)
	key, err := statekey.NewPreimageMeta(ctxPair.RegularCtx.ServiceId, preimageHash, uint32(preimageLength))
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	historicalTimeslots, ok := serviceAccount.GetPreimageMeta(key)
	if !ok {
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	switch len(historicalTimeslots) {
	case 0: // if (xs)l[h, z] ∈ {[]}

		// except: K(al) = K((xs)l) ∖ {(h, z)}
		// except: K(ap) = K((xs)p) ∖ {h}
		err := serviceAccount.DeletePreimageMeta(key, preimageLength)
		if err != nil {
			return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
		}
		delete(serviceAccount.PreimageLookup, preimageHash)

		ctxPair.RegularCtx.AccumulationState.ServiceState[ctxPair.RegularCtx.ServiceId] = serviceAccount
		return gas, withCode(regs, OK), mem, ctxPair, nil

	case 2: // if (xs)l[h, z] ∈ {[], [X, Y]}, Y < t − D
		if int(historicalTimeslots[1]) < int(timeslot)-constants.PreimageExpulsionPeriod {

			// except: K(al) = K((xs)l) ∖ {(h, z)}
			// except: K(ap) = K((xs)p) ∖ {h}
			err := serviceAccount.DeletePreimageMeta(key, preimageLength)
			if err != nil {
				return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
			}
			delete(serviceAccount.PreimageLookup, preimageHash)

			ctxPair.RegularCtx.AccumulationState.ServiceState[ctxPair.RegularCtx.ServiceId] = serviceAccount
			return gas, withCode(regs, OK), mem, ctxPair, nil
		}

	case 1: // if S(xs)l[h, z]S = 1

		// except: al[h, z] = (xs)l[h, z] ++ t
		historicalTimeslots = append(historicalTimeslots, timeslot)
		err = serviceAccount.UpdatePreimageMeta(key, historicalTimeslots)
		if err != nil {
			return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
		}

		ctxPair.RegularCtx.AccumulationState.ServiceState[ctxPair.RegularCtx.ServiceId] = serviceAccount
		return gas, withCode(regs, OK), mem, ctxPair, nil

	case 3: // if (xs)l[h, z] = [X, Y, w]
		if int(historicalTimeslots[1]) < int(timeslot)-constants.PreimageExpulsionPeriod { // if Y < t − D

			// except: al[h, z] = [w, t] if (xs)l[h, z] = [x, y, w], y < t − D
			newHistoricalTimeslots := service.PreimageHistoricalTimeslots{historicalTimeslots[2], timeslot}
			err = serviceAccount.UpdatePreimageMeta(key, newHistoricalTimeslots)
			if err != nil {
				return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
			}

			ctxPair.RegularCtx.AccumulationState.ServiceState[ctxPair.RegularCtx.ServiceId] = serviceAccount

			return gas, withCode(regs, OK), mem, ctxPair, nil
		}
	}

	return gas, withCode(regs, HUH), mem, ctxPair, nil
}

// Yield Ω_Taurus(ϱ, φ, μ, (x, y))
func Yield(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	gas -= YieldCost

	addr := regs[R7]

	// let h = μo..o+32 if Zo..o+32 ⊂ Vμ otherwise ∇
	hBytes := make([]byte, 32)
	if addr > math.MaxUint32 {
		return gas, regs, mem, ctxPair, ErrPanicf("inaccessible memory, address out of range")
	}
	if err := mem.Read(uint32(addr), hBytes); err != nil {
		// (ε', φ′7, x′_y) = (panic, φ7, x_y) if h = ∇
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// (φ′7, x′_y) = (OK, h) otherwise
	h := crypto.Hash(hBytes)
	ctxPair.RegularCtx.AccumulationHash = &h

	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Provide Ω_Aries(ϱ, φ, µ, (x,y), s)
func Provide(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, serviceId block.ServiceId) (Gas, Registers, Memory, AccumulateContextPair, error) {
	gas -= ProvideCost

	// let [o, z] = φ8,9
	o, z := regs[R8], regs[R9]
	omega7 := regs[R7]

	// let d = xd ∪ (xu)d
	allServices := ctxPair.RegularCtx.AccumulationState.ServiceState

	// s* = φ7
	ss := block.ServiceId(omega7)
	if uint64(omega7) == math.MaxUint64 {
		ss = serviceId // s* = s
	} else if !isServiceId(omega7) {
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	// i = µ[o..o+z]
	i := make([]byte, z)
	if o > math.MaxUint32 {
		return gas, regs, mem, ctxPair, ErrPanicf("inaccessible memory, address out of range")
	}
	if err := mem.Read(uint32(o), i); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// a = d[s∗] if s∗ ∈ K(d)
	a, ok := allServices[ss]
	if !ok {
		// if a = ∅
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	k, err := statekey.NewPreimageMeta(ss, crypto.HashData(i), uint32(z))
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}
	meta, ok := a.GetPreimageMeta(k)
	if !ok {
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	// if al[H(i), z] ≠ []
	if len(meta) > 0 {
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	for _, p := range ctxPair.RegularCtx.ProvidedPreimages {
		if p.ServiceIndex == ss && bytes.Equal(p.Data, i) {
			// if (s*,i) ∈ xp
			return gas, withCode(regs, HUH), mem, ctxPair, nil
		}
	}

	// x′p = xp ∪ {(s*, i)}
	ctxPair.RegularCtx.ProvidedPreimages = append(ctxPair.RegularCtx.ProvidedPreimages, block.Preimage{
		ServiceIndex: ss,
		Data:         i,
	})

	return gas, withCode(regs, OK), mem, ctxPair, nil
}
