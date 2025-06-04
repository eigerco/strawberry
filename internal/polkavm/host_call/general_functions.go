package host_call

import (
	"bytes"
	"fmt"
	"log"
	"math"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type AccountInfo struct {
	CodeHash               crypto.Hash // tc
	Balance                uint64      // tb
	ThresholdBalance       uint64      // tt
	GasLimitForAccumulator uint64      // tg
	GasLimitOnTransfer     uint64      // tm
	TotalStorageSize       uint64      // tl
	TotalItems             uint32      // ti
}

// WorkItemMetadata is used for custom serialization of a work item in the fetch host call, following the S(w) format
type WorkItemMetadata struct {
	ServiceId              block.ServiceId // w_s
	CodeHash               crypto.Hash     // w_h
	GasLimitRefine         uint64          // w_g
	GasLimitAccumulate     uint64          // w_a
	ExportedSegmentsLength uint16          // w_e
	ImportedSegmentsLength uint16          // |w_i|
	ExtrinsicsLength       uint16          // |w_x|
	PayloadLength          uint32          // |w_y|
}

// GasRemaining ΩG(ϱ, ω, ...)
func GasRemaining(gas polkavm.Gas, regs polkavm.Registers) (polkavm.Gas, polkavm.Registers, error) {
	if gas < GasRemainingCost {
		return gas, regs, polkavm.ErrOutOfGas
	}
	gas -= GasRemainingCost

	// Set the new ϱ' value into ω′7
	regs[polkavm.A0] = uint64(gas)

	return gas, regs, nil
}

// Fetch ΩY(ρ, ω, µ, p, n, r, i, i, x, o, t, ...)
func Fetch(
	gas polkavm.Gas, // ρ
	regs polkavm.Registers, // ω
	mem polkavm.Memory, // µ
	workPackage *work.Package, // p
	entropy *crypto.Hash, // n
	authorizerHashOutput []byte, // r
	itemIndex *uint32, // i
	importedSegments []work.Segment, // i
	extrinsicPreimages [][]byte, // x
	operand []state.AccumulationOperand, // o
	transfers []service.DeferredTransfer, // t
) (polkavm.Gas, polkavm.Registers, polkavm.Memory, error) {
	if gas < FetchCost {
		return gas, regs, mem, polkavm.ErrOutOfGas
	}
	gas -= FetchCost

	output := regs[polkavm.A0] // ω7
	offset := regs[polkavm.A1] // ω8
	length := regs[polkavm.A2] // ω9
	dataID := regs[polkavm.A3] // ω10
	idx1 := regs[polkavm.A4]   // ω11
	idx2 := regs[polkavm.A5]   // ω12

	var v []byte

	switch dataID {
	case 0:
		// if ω10 = 0
		out, err := GetChainConstants()
		if err != nil {
			return gas, regs, mem, polkavm.ErrPanicf(err.Error())
		}
		v = out
	case 1:
		// if n ≠ ∅ ∧ ω10 = 1
		if entropy != nil {
			v = entropy[:]
		}
	case 2:
		// if r ≠ ∅ ∧ ω10 = 2
		if len(authorizerHashOutput) > 0 {
			v = authorizerHashOutput
		}
	case 3:
		// if i ≠ ∅ ∧ ω10 = 3 ∧ ω11 < ∣x∣ ∧ ω12 < ∣x[ω11]∣
		if itemIndex != nil && int(idx1) < len(extrinsicPreimages) && int(idx2) < len(extrinsicPreimages[idx1]) {
			v = []byte{extrinsicPreimages[idx1][idx2]}
		}
	case 4:
		// if i ≠ ∅ ∧ ω10 = 4 ∧ ω11 < ∣x[i]∣
		if itemIndex != nil && int(idx1) < len(extrinsicPreimages[*itemIndex]) {
			v = []byte{extrinsicPreimages[*itemIndex][idx1]}
		}
	case 5:
		// if i ≠ ∅ ∧ ω10 = 5 ∧ ω11 < ∣i∣ ∧ ω12 < ∣i[ω11]∣
		if itemIndex != nil && int(idx1) < len(importedSegments) && int(idx2) < len(importedSegments[idx1]) {
			v = []byte{importedSegments[idx1][idx2]}
		}
	case 6:
		// if i ≠ ∅ ∧ ω10 = 6 ∧ ω11 < ∣i[i]∣
		if itemIndex != nil && int(idx1) < len(importedSegments[*itemIndex]) {
			v = []byte{importedSegments[*itemIndex][idx1]}
		}
	case 7:
		// if p ≠ ∅ ∧ ω10 = 7
		if workPackage != nil {
			out, err := jam.Marshal(workPackage)
			if err != nil {
				return gas, regs, mem, polkavm.ErrPanicf(err.Error())
			}
			v = out
		}
	case 8:
		// if p ≠ ∅ ∧ ω10 = 8
		if workPackage != nil {
			// E(pu, ↕pp)
			out, err := jam.Marshal(struct {
				AuthCodeHash     crypto.Hash
				Parameterization []byte
			}{
				workPackage.AuthCodeHash,
				workPackage.Parameterization,
			})
			if err != nil {
				return gas, regs, mem, polkavm.ErrPanicf(err.Error())
			}
			v = out
		}
	case 9:
		// if p ≠ ∅ ∧ ω10 = 9
		if workPackage != nil {
			// pj
			v = workPackage.AuthorizationToken
		}
	case 10:
		// if p ≠ ∅ ∧ ω10 = 10
		if workPackage != nil {
			out, err := jam.Marshal(workPackage.Context)
			if err != nil {
				return gas, regs, mem, polkavm.ErrPanicf(err.Error())
			}
			v = out
		}
	case 11:
		// if p ≠ ∅ ∧ ω10 = 11
		if workPackage != nil {
			var sw [][]byte
			for _, item := range workPackage.WorkItems {
				// S(w) ≡ E(E4(ws), wh, E8(wg, wa), E2(we, ∣wi∣, ∣wx∣), E4(∣wy∣))
				metadata := WorkItemMetadata{
					item.ServiceId,
					item.CodeHash,
					item.GasLimitRefine,
					item.GasLimitAccumulate,
					item.ExportedSegments,
					uint16(len(item.ImportedSegments)),
					uint16(len(item.Extrinsics)),
					uint32(len(item.Payload)),
				}
				bytes, err := jam.Marshal(metadata)
				if err != nil {
					return gas, regs, mem, polkavm.ErrPanicf(err.Error())
				}
				sw = append(sw, bytes)
			}
			out, err := jam.Marshal(sw)
			if err != nil {
				return gas, regs, mem, polkavm.ErrPanicf(err.Error())
			}
			v = out
		}
	case 12:
		// f p ≠ ∅ ∧ ω10 = 12 ∧ ω11 < ∣pw∣
		if workPackage != nil && int(idx1) < len(workPackage.WorkItems) {
			item := workPackage.WorkItems[idx1]
			metadata := WorkItemMetadata{
				item.ServiceId,
				item.CodeHash,
				item.GasLimitRefine,
				item.GasLimitAccumulate,
				item.ExportedSegments,
				uint16(len(item.ImportedSegments)),
				uint16(len(item.Extrinsics)),
				uint32(len(item.Payload)),
			}
			bytes, err := jam.Marshal(metadata)
			if err != nil {
				return gas, regs, mem, polkavm.ErrPanicf(err.Error())
			}
			v = bytes
		}
	case 13:
		// if p ≠ ∅ ∧ ω10 = 13 ∧ ω11 < ∣pw∣
		if workPackage != nil && int(idx1) < len(workPackage.WorkItems) {
			v = workPackage.WorkItems[idx1].Payload
		}
	case 14:
		// if o ≠ ∅ ∧ ω10 = 14
		if len(operand) > 0 {
			out, err := jam.Marshal(operand)
			if err != nil {
				return gas, regs, mem, polkavm.ErrPanicf(err.Error())
			}
			v = out
		}
	case 15:
		// if o ≠ ∅ ∧ ω10 = 15 ∧ ω11 < |o|
		if len(operand) > 0 && int(idx1) < len(operand) {
			out, err := jam.Marshal(operand[idx1])
			if err != nil {
				return gas, regs, mem, polkavm.ErrPanicf(err.Error())
			}
			v = out
		}
	case 16:
		// if t ≠ ∅ ∧ ω10 = 16
		if len(transfers) > 0 {
			out, err := jam.Marshal(transfers)
			if err != nil {
				return gas, regs, mem, polkavm.ErrPanicf(err.Error())
			}
			v = out
		}
	case 17:
		// if t ≠ ∅ ∧ ω10 = 17 ∧ ω11 < ∣t∣
		if len(transfers) > 0 && int(idx1) < len(transfers) {
			out, err := jam.Marshal(transfers[idx1])
			if err != nil {
				return gas, regs, mem, polkavm.ErrPanicf(err.Error())
			}
			v = out
		}
	default:
		return gas, withCode(regs, NONE), mem, nil
	}

	if len(v) == 0 {
		return gas, withCode(regs, NONE), mem, nil
	}

	if err := writeFromOffset(mem, output, v, offset, length); err != nil {
		return gas, regs, mem, err
	}

	regs[polkavm.A0] = uint64(len(v))
	return gas, regs, mem, nil
}

// Lookup ΩL(ϱ, ω, μ, s, s, d)
func Lookup(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, s service.ServiceAccount, serviceId block.ServiceId, serviceState service.ServiceState) (polkavm.Gas, polkavm.Registers, polkavm.Memory, error) {
	if gas < LookupCost {
		return gas, regs, mem, polkavm.ErrOutOfGas
	}
	gas -= LookupCost

	omega7 := regs[polkavm.A0]

	// Determine the lookup key 'a'
	a := s
	if uint64(omega7) != math.MaxUint64 && omega7 != uint64(serviceId) {
		var exists bool
		// lookup service account by serviceId in the serviceState
		a, exists = serviceState[serviceId]
		if !exists {
			regs[polkavm.A0] = uint64(NONE)
			return gas, regs, mem, nil
		}
	}

	// let [h, o] = ω8..+2
	h, o := regs[polkavm.A1], regs[polkavm.A2]

	key := make([]byte, 32)
	if err := mem.Read(h, key); err != nil {
		return gas, regs, mem, polkavm.ErrPanicf(err.Error())
	}

	// lookup value in storage (v) using the hash
	v, exists := a.PreimageLookup[crypto.Hash(key)]
	if !exists {
		// v=∅ => (▸, NONE, μ)
		return gas, withCode(regs, NONE), mem, nil
	}

	if err := writeFromOffset(mem, o, v, regs[polkavm.A3], regs[polkavm.A4]); err != nil {
		return gas, regs, mem, err
	}

	regs[polkavm.A0] = uint64(len(v))
	return gas, regs, mem, nil
}

// Read ΩR(ϱ, ω, μ, s, s, d)
func Read(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, s service.ServiceAccount, serviceId block.ServiceId, serviceState service.ServiceState) (polkavm.Gas, polkavm.Registers, polkavm.Memory, error) {
	if gas < ReadCost {
		return gas, regs, mem, polkavm.ErrOutOfGas
	}
	gas -= ReadCost

	omega7 := regs[polkavm.A0]
	// s* = ω7
	ss := block.ServiceId(omega7)
	if uint64(omega7) == math.MaxUint64 {
		ss = serviceId // s* = s
	}

	a := s.Clone()
	if ss != serviceId {
		var exists bool
		a, exists = serviceState[ss]
		if !exists {
			return gas, regs, mem, polkavm.ErrAccountNotFound
		}
	}

	// let [ko, kz, o] = ω8..+3
	ko, kz, o := regs[polkavm.A1], regs[polkavm.A2], regs[polkavm.A3]

	// read key data from memory at ko..ko+kz
	keyData := make([]byte, kz)
	err := mem.Read(ko, keyData)
	if err != nil {
		return gas, regs, mem, polkavm.ErrPanicf(err.Error())
	}

	// k = H(E4(s*) ⌢ µko..ko+kz)
	serviceIdBytes, err := jam.Marshal(ss)
	if err != nil {
		return gas, regs, mem, polkavm.ErrPanicf(err.Error())
	}

	// Concatenate E4(s) and keyData
	hashInput := make([]byte, 0, len(serviceIdBytes)+len(keyData))
	hashInput = append(hashInput, serviceIdBytes...)
	hashInput = append(hashInput, keyData...)

	// Compute the hash H(E4(s) + keyData) and create a state key from it to use
	// as the storage key.
	k, err := statekey.NewStorage(ss, crypto.HashData(hashInput))
	if err != nil {
		return gas, regs, mem, polkavm.ErrPanicf(err.Error())
	}

	v, exists := a.Storage[k]
	if !exists {
		return gas, withCode(regs, NONE), mem, nil
	}

	if err = writeFromOffset(mem, o, v, regs[polkavm.A4], regs[polkavm.A5]); err != nil {
		return gas, regs, mem, err
	}

	regs[polkavm.A0] = uint64(len(v))
	return gas, regs, mem, nil
}

// Write ΩW(ϱ, ω, μ, s, s)
func Write(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, s service.ServiceAccount, serviceId block.ServiceId) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
	if gas < WriteCost {
		return gas, regs, mem, s, polkavm.ErrOutOfGas
	}
	gas -= WriteCost

	ko := regs[polkavm.A0]
	kz := regs[polkavm.A1]
	vo := regs[polkavm.A2]
	vz := regs[polkavm.A3]

	keyData := make([]byte, kz)
	err := mem.Read(ko, keyData)
	if err != nil {
		return gas, regs, mem, s, polkavm.ErrPanicf(err.Error())
	}

	serviceIdBytes, err := jam.Marshal(serviceId)
	if err != nil {
		return gas, regs, mem, s, polkavm.ErrPanicf(err.Error())
	}

	hashInput := append(serviceIdBytes, keyData...)
	k, err := statekey.NewStorage(serviceId, crypto.HashData(hashInput))
	if err != nil {
		return gas, regs, mem, s, polkavm.ErrPanicf(err.Error())
	}

	a := s.Clone()
	if vz == 0 {
		delete(a.Storage, k)
	} else {
		valueData := make([]byte, vz)
		err = mem.Read(vo, valueData)
		if err != nil {
			return gas, regs, mem, s, polkavm.ErrPanicf(err.Error())
		}

		a.Storage[k] = valueData
	}

	// let l = |s_s[k]| if k ∈ K(s_s); NONE otherwise
	var storageItemLength uint64
	storageItem, ok := s.Storage[k]
	if ok {
		storageItemLength = uint64(len(storageItem))
	} else {
		storageItemLength = uint64(NONE)
	}

	if a.ThresholdBalance() > a.Balance {
		return gas, withCode(regs, FULL), mem, s, nil
	}

	// otherwise a.ThresholdBalance() <= a.Balance
	regs[polkavm.A0] = storageItemLength // l
	return gas, regs, mem, a, err        // return service account 'a' as opposed to 's' for not successful paths
}

// Info ΩI(ϱ, ω, μ, s, d)
func Info(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, serviceId block.ServiceId, serviceState service.ServiceState) (polkavm.Gas, polkavm.Registers, polkavm.Memory, error) {
	if gas < InfoCost {
		return gas, regs, mem, polkavm.ErrOutOfGas
	}
	gas -= InfoCost

	omega7 := regs[polkavm.A0]
	omega8 := regs[polkavm.A1]

	t, exists := serviceState[serviceId]
	if uint64(omega7) != math.MaxUint64 {
		t, exists = serviceState[block.ServiceId(omega7)]
	}
	if !exists {
		return gas, withCode(regs, NONE), mem, nil
	}

	accountInfo := AccountInfo{
		CodeHash:               t.CodeHash,
		Balance:                t.Balance,
		ThresholdBalance:       t.ThresholdBalance(),
		GasLimitForAccumulator: t.GasLimitForAccumulator,
		GasLimitOnTransfer:     t.GasLimitOnTransfer,
		TotalStorageSize:       t.TotalStorageSize(),
		TotalItems:             t.TotalItems(),
	}

	// E(tc, tb, tt, tg , tm, tl, ti)
	m, err := jam.Marshal(accountInfo)
	if err != nil {
		return gas, regs, mem, err
	}

	if err = mem.Write(omega8, m); err != nil {
		return gas, regs, mem, polkavm.ErrPanicf(err.Error())
	}

	return gas, withCode(regs, OK), mem, nil
}

// Log A host call for passing a debugging message from the service/authorizer to the hosting environment for logging to the node operator
func Log(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, core *uint16, serviceId *block.ServiceId) (polkavm.Gas, polkavm.Registers, polkavm.Memory) {
	fullMsg := &bytes.Buffer{}
	lvl := regs[polkavm.A0]

	// Write level
	switch lvl {
	case 0:
		fullMsg.WriteString("FATAL")
	case 1:
		fullMsg.WriteString("WARNING")
	case 2:
		fullMsg.WriteString("INFO")
	case 3:
		fullMsg.WriteString("HELP")
	case 4:
		fullMsg.WriteString("PEDANT")
	default:
		fullMsg.WriteString("UNKNOWN")
	}

	// Write core and service
	if core != nil {
		_, _ = fmt.Fprintf(fullMsg, "@%d", *core)
	}
	if serviceId != nil {
		_, _ = fmt.Fprintf(fullMsg, "#%d", *serviceId)
	}

	to := regs[polkavm.A1]
	tz := regs[polkavm.A2]
	xo := regs[polkavm.A3]
	xz := regs[polkavm.A4]

	// Write target
	if to != 0 && tz != 0 {
		targetBytes := make([]byte, tz)
		err := mem.Read(to, targetBytes)
		if err != nil {
			log.Printf("unable to access memory for target: address %d length %d", to, tz)
		}

		_, _ = fmt.Fprintf(fullMsg, " %s", targetBytes)
	}

	msgBytes := make([]byte, xz)
	err := mem.Read(xo, msgBytes)
	if err != nil {
		log.Printf("unable to access memory for target: address %d length %d", to, tz)
	}

	// Write message
	_, _ = fmt.Fprintf(fullMsg, " %s", msgBytes)

	log.Println(fullMsg.String())
	return gas, regs, mem
}

// GetChainConstants
//
//	c = E(
//
// E8(BI ), E8(BL), E8(BS), E2(C), E4(D), E4(E), E8(GA),
// E8(GI ), E8(GR), E8(GT ), E2(H), E2(I), E2(J), E4(L), E2(O),
// E2(P), E2(Q), E2(R), E2(S), E2(T), E2(U), E2(V), E4(WA),
// E4(WB), E4(WC ), E4(WE), E4(WG), E4(WM), E4(WP ),
// E4(WR), E4(WT ), E4(WX), E4(Y)
//
// )
func GetChainConstants() ([]byte, error) {
	return jam.Marshal(struct {
		AdditionalMinimumBalancePerItem         uint64 // BI
		AdditionalMinimumBalancePerOctet        uint64 // BL
		BasicMinimumBalance                     uint64 // BS
		TotalNumberOfCores                      uint16 // C
		PreimageExpulsionPeriod                 uint32 // D
		TimeslotsPerEpoch                       uint32 // E
		MaxAllocatedGasAccumulation             uint64 // GA
		MaxAllocatedGasIsAuthorized             uint64 // GI
		MaxAllocatedGasRefine                   uint64 // GR
		TotalGasAccumulation                    uint64 // GT
		MaxRecentBlocks                         uint16 // H
		MaxNumberOfItems                        uint16 // I
		MaxNumberOfDependencyItems              uint16 // J
		MaxTimeslotsForPreimage                 uint32 // L
		MaxAuthorizersPerCore                   uint16 // O
		SlotPeriodInSeconds                     uint16 // P
		PendingAuthorizersQueueSize             uint16 // Q
		ValidatorRotationPeriod                 uint16 // R
		MaximumNumberOfEntriesAccumulationQueue uint16 // S
		MaxNumberOfExtrinsics                   uint16 // T
		WorkReportTimeoutPeriod                 uint16 // U
		NumberOfValidators                      uint16 // V
		MaximumSizeIsAuthorizedCode             uint16 // W_A
		MaxWorkPackageSize                      uint32 // W_B
		MaxSizeServiceCode                      uint32 // W_C
		ErasureCodingChunkSize                  uint32 // W_E
		SizeOfSegment                           uint32 // W_G
		MaxNumberOfImportsExports               uint32 // W_M
		NumberOfErasureCodecPiecesInSegment     uint32 // W_P
		MaxWorkPackageSizeBytes                 uint32 // W_R
		TransferMemoSizeBytes                   uint32 // W_T
		MaxNumberOfExports                      uint32 // WX
		TicketSubmissionTimeSlots               uint32 // Y
	}{
		service.AdditionalMinimumBalancePerItem,
		service.AdditionalMinimumBalancePerOctet,
		service.BasicMinimumBalance,
		common.TotalNumberOfCores,
		jamtime.PreimageExpulsionPeriod,
		jamtime.TimeslotsPerEpoch,
		common.MaxAllocatedGasAccumulation,
		common.MaxAllocatedGasIsAuthorized,
		work.MaxAllocatedGasRefine,
		service.TotalGasAccumulation,
		state.MaxRecentBlocks,
		work.MaxNumberOfItems,
		work.MaxNumberOfDependencyItems,
		state.MaxTimeslotsForPreimage,
		state.MaxAuthorizersPerCore,
		jamtime.SlotPeriodInSeconds,
		state.PendingAuthorizersQueueSize,
		uint16(jamtime.ValidatorRotationPeriod),
		state.MaximumNumberOfEntriesAccumulationQueue,
		work.MaxNumberOfExtrinsics,
		uint16(common.WorkReportTimeoutPeriod),
		common.NumberOfValidators,
		state.MaximumSizeIsAuthorizedCode,
		common.MaxWorkPackageSize,
		work.MaxSizeServiceCode,
		common.ErasureCodingChunkSize,
		common.SizeOfSegment,
		work.MaxNumberOfImports,
		common.NumberOfErasureCodecPiecesInSegment,
		common.MaxWorkPackageSizeBytes,
		service.TransferMemoSizeBytes,
		work.MaxNumberOfExports,
		jamtime.TicketSubmissionTimeSlots,
	})
}
