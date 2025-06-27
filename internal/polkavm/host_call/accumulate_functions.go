package host_call

import (
	"bytes"
	"math"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	. "github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// Bless ΩB(ϱ, φ, μ, (x, y))
func Bless(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < BlessCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= BlessCost

	xs := ctxPair.RegularCtx.ServiceId
	manager := ctxPair.RegularCtx.AccumulationState.ManagerServiceId
	// if f ≠ 0 ∧ xs ≠ (xu)m
	if xs != manager {
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	// let [m, a, v, o, n] = φ7...12
	managerServiceId, assignServiceAddr, designateServiceId, addr, servicesNr := regs[A0], regs[A1], regs[A2], regs[A3], regs[A4]
	// let g = {(s ↦ g) where E4(s) ⌢ E8(g) = μ_o+12i⋅⋅⋅+12 | i ∈ Nn} if Zo⋅⋅⋅+12n ⊂ Vμ otherwise ∇
	for i := range servicesNr {
		serviceId, err := readNumber[block.ServiceId](mem, addr+(12*i), 4)
		if err != nil {
			return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
		}
		serviceGas, err := readNumber[uint64](mem, addr+(12*i)+4, 8)
		if err != nil {
			return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
		}

		if ctxPair.RegularCtx.AccumulationState.AmountOfGasPerServiceId == nil {
			ctxPair.RegularCtx.AccumulationState.AmountOfGasPerServiceId = make(map[block.ServiceId]uint64)
		}
		ctxPair.RegularCtx.AccumulationState.AmountOfGasPerServiceId[serviceId] = serviceGas
	}
	ctxPair.RegularCtx.AccumulationState.ManagerServiceId = block.ServiceId(managerServiceId)

	// Na⋅⋅⋅+4C ⊆ Vµ
	assignersBytes := make([]byte, 4*common.TotalNumberOfCores)
	if err := mem.Read(assignServiceAddr, assignersBytes); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}
	// E−1(4) (µa⋅⋅⋅+4C)
	var assigners [common.TotalNumberOfCores]block.ServiceId
	err := jam.Unmarshal(assignersBytes, &assigners)
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	ctxPair.RegularCtx.AccumulationState.AssignedServiceIds = assigners
	ctxPair.RegularCtx.AccumulationState.DesignateServiceId = block.ServiceId(designateServiceId)
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Assign ΩA(ϱ, φ, μ, (x, y))
func Assign(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < AssignCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= AssignCost

	// let [c, o, a] = φ7⋅⋅⋅+3
	core, addr, newAssigner := regs[A0], regs[A1], regs[A2]

	if core >= uint64(common.TotalNumberOfCores) {
		return gas, withCode(regs, CORE), mem, ctxPair, nil
	}

	xs := ctxPair.RegularCtx.ServiceId
	currentAssigned := ctxPair.RegularCtx.AccumulationState.AssignedServiceIds[core]
	//  if xs ≠ (xu)a[c]
	if currentAssigned != xs {
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	var queue [state.PendingAuthorizersQueueSize]crypto.Hash
	for i := 0; i < state.PendingAuthorizersQueueSize; i++ {
		bytes := make([]byte, 32)
		if err := mem.Read(addr+uint64(32*i), bytes); err != nil {
			return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
		}
		ctxPair.RegularCtx.AccumulationState.PendingAuthorizersQueues[core][i] = crypto.Hash(bytes)
		queue[i] = crypto.Hash(bytes)
	}

	ctxPair.RegularCtx.AccumulationState.PendingAuthorizersQueues[core] = queue
	ctxPair.RegularCtx.AccumulationState.AssignedServiceIds[core] = block.ServiceId(newAssigner)

	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Designate ΩD (ϱ, φ, μ, (x, y))
func Designate(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < DesignateCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= DesignateCost

	const (
		bandersnatch = crypto.BandersnatchSize
		ed25519      = bandersnatch + crypto.Ed25519PublicSize
		bls          = ed25519 + crypto.BLSSize
		metadata     = bls + crypto.MetadataSize
	)

	xs := ctxPair.RegularCtx.ServiceId
	designator := ctxPair.RegularCtx.AccumulationState.DesignateServiceId
	if xs != designator {
		// if xs ≠ (xu)v
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	// let o = φ7
	addr := regs[A0]
	for i := 0; i < common.NumberOfValidators; i++ {
		bytes := make([]byte, 336)
		if err := mem.Read(addr+uint64(336*i), bytes); err != nil {
			return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
		}

		ctxPair.RegularCtx.AccumulationState.ValidatorKeys[i] = crypto.ValidatorKey{
			Bandersnatch: crypto.BandersnatchPublicKey(bytes[:bandersnatch]),
			Ed25519:      bytes[bandersnatch:ed25519],
			Bls:          crypto.BlsKey(bytes[ed25519:bls]),
			Metadata:     crypto.MetadataKey(bytes[bls:metadata]),
		}
	}

	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Checkpoint ΩC(ϱ, φ, μ, (x, y))
func Checkpoint(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < CheckpointCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= CheckpointCost

	ctxPair.ExceptionalCtx = ctxPair.RegularCtx

	// Set the new ϱ' value into φ′7
	regs[A0] = uint64(gas)

	return gas, regs, mem, ctxPair, nil
}

// New ΩN(ϱ, φ, μ, (x, y), t)
func New(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < NewCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= NewCost

	// let [o, l, g, m, f] = φ7..+5
	addr, preimageLength, gasLimitAccumulator, gasLimitTransfer, gratisStorageOffset := regs[A0], regs[A1], regs[A2], regs[A3], regs[A4]

	xs := ctxPair.RegularCtx.ServiceId
	manager := ctxPair.RegularCtx.AccumulationState.ManagerServiceId
	// if f ≠ 0 ∧ xs ≠ (xu)m
	if gratisStorageOffset != 0 && xs != manager {
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	// c = μo⋅⋅⋅+32 if No⋅⋅⋅+32 ⊂ Vμ otherwise ∇
	codeHashBytes := make([]byte, 32)
	if err := mem.Read(addr, codeHashBytes); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	codeHash := crypto.Hash(codeHashBytes)

	// let a = (c, s : {},l : {(c, l) ↦ []}, b : at, g, m,p : {}, r : t, f, a : 0, p : xs) if c ≠ ∇
	account := service.ServiceAccount{
		CodeHash:               codeHash,
		GasLimitForAccumulator: gasLimitAccumulator,
		GasLimitOnTransfer:     gasLimitTransfer,
		GratisStorageOffset:    gratisStorageOffset,
		CreationTimeslot:       timeslot,
		ParentService:          xs,
	}

	k, err := statekey.NewPreimageMeta(xs, codeHash, uint32(preimageLength))
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	err = account.InsertPreimageMeta(k, preimageLength, service.PreimageHistoricalTimeslots{})
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// b: at
	account.Balance = account.ThresholdBalance()

	// let s_b = (Xs)b − at
	b := ctxPair.RegularCtx.ServiceAccount().Balance - account.ThresholdBalance()

	// let s = x_s
	currentAccount := ctxPair.RegularCtx.ServiceAccount()

	// if a ≠ ∇ ∧ s_b ≥ (xs)t
	a := ctxPair.RegularCtx.ServiceAccount()

	if b >= a.ThresholdBalance() {
		// φ′7 = x_i
		regs[A0] = uint64(ctxPair.RegularCtx.NewServiceId)
		currentAccount.Balance = b

		// x'_i = check(bump(x_i))
		newId := service.CheckIndex(
			service.BumpIndex(ctxPair.RegularCtx.NewServiceId),
			ctxPair.RegularCtx.AccumulationState.ServiceState,
		)
		ctxPair.RegularCtx.NewServiceId = newId

		// (x'u)d = (xu)d ∪ {xi ↦ a, xs ↦ s}
		ctxPair.RegularCtx.AccumulationState.ServiceState[ctxPair.RegularCtx.ServiceId] = currentAccount
		ctxPair.RegularCtx.AccumulationState.ServiceState[newId] = account

		return gas, regs, mem, ctxPair, nil
	}

	// otherwise
	return gas, withCode(regs, CASH), mem, ctxPair, nil
}

// Upgrade ΩU(ϱ, φ, μ, (x, y))
func Upgrade(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < UpgradeCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= UpgradeCost
	// let [o, g, m] = φ7...10
	addr, gasLimitAccumulator, gasLimitTransfer := regs[A0], regs[A1], regs[A2]

	// c = μo⋅⋅⋅+32 if No⋅⋅⋅+32 ⊂ Vμ otherwise ∇
	codeHash := make([]byte, 32)
	if err := mem.Read(addr, codeHash); err != nil {
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
	receiverId, newBalance, gasLimit, o := regs[A0], regs[A1], regs[A2], regs[A3]

	// g = 10 + φ9
	transferCost := TransferBaseCost + Gas(gasLimit)
	if gas < transferCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= transferCost

	// m = μo⋅⋅⋅+M if No⋅⋅⋅+WT ⊂ Vμ otherwise ∇
	m := make([]byte, service.TransferMemoSizeBytes)
	if err := mem.Read(o, m); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// let t ∈ T = (s, d, a, m, g)
	deferredTransfer := service.DeferredTransfer{
		SenderServiceIndex:   ctxPair.RegularCtx.ServiceId,
		ReceiverServiceIndex: block.ServiceId(receiverId),
		Balance:              newBalance,
		Memo:                 service.Memo(m),
		GasLimit:             gasLimit,
	}

	// let d = xd ∪ (xu)d
	allServices := ctxPair.RegularCtx.AccumulationState.ServiceState

	receiverService, ok := allServices[block.ServiceId(receiverId)]
	// if d !∈ K(δ ∪ xn)
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
	if ctxPair.RegularCtx.ServiceAccount().Balance-newBalance < account.ThresholdBalance() {
		return gas, withCode(regs, CASH), mem, ctxPair, nil
	}

	ctxPair.RegularCtx.DeferredTransfers = append(ctxPair.RegularCtx.DeferredTransfers, deferredTransfer)
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Eject ΩJ(ϱ, φ, μ, (x, y), t)
func Eject(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < EjectCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= EjectCost

	d, o := regs[A0], regs[A1]

	// let h = μo..o+32 if Zo..o+32 ⊂ Vμ
	h := make([]byte, 32)
	if err := mem.Read(o, h); err != nil {
		// otherwise ∇
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
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
	l := max(81, len(serviceAccount.EncodedCodeAndMetadata())) - 81

	k, err := statekey.NewPreimageMeta(ctxPair.RegularCtx.ServiceId, crypto.Hash(h), uint32(l))
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}
	historicalTimeslots, ok := serviceAccount.GetPreimageMeta(k)
	if !ok {
		// (h, l) ∉ d_l => HUH
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	// if d_l[h, l] = [x, y], y < t − D => OK
	if len(historicalTimeslots) == 2 && historicalTimeslots[1] < timeslot-jamtime.PreimageExpulsionPeriod {
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
	if gas < QueryCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= QueryCost

	addr, preimageMetaKeyLength := regs[A0], regs[A1]

	// let h = μo..o+32 if Zo..o+32 ⊂ Vμ
	h := make([]byte, 32)
	if err := mem.Read(addr, h); err != nil {
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
		regs[A1] = 0
		return gas, withCode(regs, NONE), mem, ctxPair, nil
	}

	switch len(a) {
	case 0:
		// a = [] => (0, 0)
		regs[A0], regs[A1] = 0, 0
	case 1:
		// a = [x] => (1 + 2^32 * x, 0)
		regs[A0], regs[A1] = 1+(uint64(a[0])<<32), 0
	case 2:
		// a = [x, y] => (2 + 2^32 * x, y)
		regs[A0], regs[A1] = 2+(uint64(a[0])<<32), uint64(a[1])
	case 3:
		// a = [x, y, z] => (3 + 2^32 * x, y + 2^32 * z)
		regs[A0], regs[A1] = 3+(uint64(a[0])<<32), uint64(a[1])+(uint64(a[2])<<32)
	}

	return gas, regs, mem, ctxPair, nil
}

// Solicit ΩS(ϱ, φ, μ, (x, y), t)
func Solicit(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < SolicitCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= SolicitCost

	// let [o, z] = φ7,8
	addr, preimageLength := regs[A0], regs[A1]
	// let h = μo⋅⋅⋅+32 if Zo⋅⋅⋅+32 ⊂ Vμ otherwise ∇
	preimageHashBytes := make([]byte, 32)
	if err := mem.Read(addr, preimageHashBytes); err != nil {
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
	if serviceAccount.Balance < serviceAccount.ThresholdBalance() {
		return gas, withCode(regs, FULL), mem, ctxPair, nil
	}

	ctxPair.RegularCtx.AccumulationState.ServiceState[ctxPair.RegularCtx.ServiceId] = serviceAccount
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Forget ΩF(ϱ, φ, μ, (x, y), t)
func Forget(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
	if gas < ForgetCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= ForgetCost

	// let [o, z] = φ0,1
	addr, preimageLength := regs[A0], regs[A1]

	// let h = μo⋅⋅⋅+32 if Zo⋅⋅⋅+32 ⊂ Vμ otherwise ∇
	preimageHashBytes := make([]byte, 32)
	if err := mem.Read(addr, preimageHashBytes); err != nil {
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
		return gas, regs, mem, ctxPair, ErrPanicf("preimage historical timeslots not found")
	}

	switch len(historicalTimeslots) {
	case 0: // if (xs)l[h, z] ∈ {[]}

		// except: K(al) = K((xs)l) ∖ {(h, z)}
		// except: K(ap) = K((xs)p) ∖ {h}
		serviceAccount.DeletePreimageMeta(key, preimageLength)
		delete(serviceAccount.PreimageLookup, preimageHash)

		ctxPair.RegularCtx.AccumulationState.ServiceState[ctxPair.RegularCtx.ServiceId] = serviceAccount
		return gas, withCode(regs, OK), mem, ctxPair, nil

	case 2: // if (xs)l[h, z] ∈ {[], [X, Y]}, Y < t − D
		if historicalTimeslots[1] < timeslot-jamtime.PreimageExpulsionPeriod {

			// except: K(al) = K((xs)l) ∖ {(h, z)}
			// except: K(ap) = K((xs)p) ∖ {h}
			serviceAccount.DeletePreimageMeta(key, preimageLength)
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
		if historicalTimeslots[1] < timeslot-jamtime.PreimageExpulsionPeriod { // if Y < t − D

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
	if gas < YieldCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= YieldCost

	addr := regs[A0]

	// let h = μo..o+32 if Zo..o+32 ⊂ Vμ otherwise ∇
	hBytes := make([]byte, 32)
	if err := mem.Read(addr, hBytes); err != nil {
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
	if gas < ProvideCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= ProvideCost

	// let [o, z] = φ8,9
	o, z := regs[A1], regs[A2]
	omega7 := regs[A0]

	// let d = xd ∪ (xu)d
	allServices := ctxPair.RegularCtx.AccumulationState.ServiceState

	// s* = φ7
	ss := block.ServiceId(omega7)
	if uint64(omega7) == math.MaxUint64 {
		ss = serviceId // s* = s
	}

	// a = d[s∗] if s∗ ∈ K(d)
	a, ok := allServices[ss]
	if !ok {
		// if a = ∅
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	// i = µ[o..o+z]
	i := make([]byte, z)
	if err := mem.Read(o, i); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	k, err := statekey.NewPreimageMeta(ss, crypto.HashData(i), uint32(z))
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}
	meta, ok := a.GetPreimageMeta(k)
	if !ok {
		return gas, regs, mem, ctxPair, ErrPanicf("preimage meta not found")
	}

	// if al[H(i), z] ≠ []
	if len(meta) > 0 {
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	for _, p := range ctxPair.RegularCtx.ProvidedPreimages {
		if p.ServiceId == ss && bytes.Equal(p.Data, i) {
			// if (s*,i) ∈ xp
			return gas, withCode(regs, HUH), mem, ctxPair, nil
		}
	}

	// x′p = xp ∪ {(s*, i)}
	ctxPair.RegularCtx.ProvidedPreimages = append(ctxPair.RegularCtx.ProvidedPreimages, ProvidedPreimage{
		ServiceId: ss,
		Data:      i,
	})

	return gas, withCode(regs, OK), mem, ctxPair, nil
}
