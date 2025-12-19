package host_call

import (
	"bytes"
	"fmt"
	"github.com/eigerco/strawberry/internal/common"
	"math"
	"slices"

	"github.com/eigerco/strawberry/pkg/log"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/pvm"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

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

// GasRemaining ΩG(ϱ, φ, ...)
func GasRemaining(gas pvm.Gas, regs pvm.Registers) (pvm.Gas, pvm.Registers, error) {
	gas -= GasRemainingCost

	// Set the new ϱ' value into φ′7
	regs[pvm.A0] = uint64(gas)

	return gas, regs, nil
}

// Fetch ΩY(ρ, φ, µ, p, n, r, i, i, x, o, t, ...)
func Fetch(
	gas pvm.Gas, // ρ
	regs pvm.Registers, // φ
	mem pvm.Memory, // µ
	workPackage *work.Package, // p
	entropy *crypto.Hash, // n
	authorizerHashOutput []byte, // r
	itemIndex *uint32, // i
	importedSegments []work.Segment, // i
	extrinsicPreimages [][]byte, // x
	operand []*state.AccumulationInput, // o
) (pvm.Gas, pvm.Registers, pvm.Memory, error) {
	gas -= FetchCost

	output := regs[pvm.A0] // φ7
	offset := regs[pvm.A1] // φ8
	length := regs[pvm.A2] // φ9
	dataID := regs[pvm.A3] // φ10
	idx1 := regs[pvm.A4]   // φ11
	idx2 := regs[pvm.A5]   // φ12

	var v []byte

	switch dataID {
	case 0:
		// if φ10 = 0
		v = GetChainConstants()
	case 1:
		// if n ≠ ∅ ∧ φ10 = 1
		if entropy != nil {
			v = entropy[:]
		}
	case 2:
		// if r ≠ ∅ ∧ φ10 = 2
		if len(authorizerHashOutput) > 0 {
			v = authorizerHashOutput
		}
	case 3:
		// if i ≠ ∅ ∧ φ10 = 3 ∧ φ11 < ∣x∣ ∧ φ12 < ∣x[φ11]∣
		if itemIndex != nil && int(idx1) < len(extrinsicPreimages) && int(idx2) < len(extrinsicPreimages[idx1]) {
			v = []byte{extrinsicPreimages[idx1][idx2]}
		}
	case 4:
		// if i ≠ ∅ ∧ φ10 = 4 ∧ φ11 < ∣x[i]∣
		if itemIndex != nil && int(idx1) < len(extrinsicPreimages[*itemIndex]) {
			v = []byte{extrinsicPreimages[*itemIndex][idx1]}
		}
	case 5:
		// if i ≠ ∅ ∧ φ10 = 5 ∧ φ11 < ∣i∣ ∧ φ12 < ∣i[φ11]∣
		if itemIndex != nil && int(idx1) < len(importedSegments) && int(idx2) < len(importedSegments[idx1]) {
			v = []byte{importedSegments[idx1][idx2]}
		}
	case 6:
		// if i ≠ ∅ ∧ φ10 = 6 ∧ φ11 < ∣i[i]∣
		if itemIndex != nil && int(idx1) < len(importedSegments[*itemIndex]) {
			v = []byte{importedSegments[*itemIndex][idx1]}
		}
	case 7:
		// if p ≠ ∅ ∧ φ10 = 7
		if workPackage != nil {
			out, err := jam.Marshal(workPackage)
			if err != nil {
				return gas, regs, mem, pvm.ErrPanicf(err.Error())
			}
			v = out
		}
	case 8:
		// if p ≠ ∅ ∧ φ10 = 8
		if workPackage != nil {
			//pf
			v = workPackage.Parameterization
		}
	case 9:
		// if p ≠ ∅ ∧ φ10 = 9
		if workPackage != nil {
			// pj
			v = workPackage.AuthorizationToken
		}
	case 10:
		// if p ≠ ∅ ∧ φ10 = 10
		if workPackage != nil {
			out, err := jam.Marshal(workPackage.Context)
			if err != nil {
				return gas, regs, mem, pvm.ErrPanicf(err.Error())
			}
			v = out
		}
	case 11:
		// if p ≠ ∅ ∧ φ10 = 11
		if workPackage != nil {
			var sw [][]byte
			for _, item := range workPackage.WorkItems {
				// S(w) ≡ E(E4(ws), wh, E8(wg, wa), E2(we, ∣wi∣, ∣wx∣), E4(∣wy∣))
				metadata := slices.Concat(
					jam.EncodeUint32(uint32(item.ServiceId)),
					item.CodeHash[:],
					jam.EncodeUint64(item.GasLimitRefine),
					jam.EncodeUint64(item.GasLimitAccumulate),
					jam.EncodeUint16(item.ExportedSegments),
					jam.EncodeUint16(uint16(len(item.ImportedSegments))),
					jam.EncodeUint16(uint16(len(item.Extrinsics))),
					jam.EncodeUint32(uint32(len(item.Payload))),
				)
				sw = append(sw, metadata)
			}
			out, err := jam.Marshal(sw)
			if err != nil {
				return gas, regs, mem, pvm.ErrPanicf(err.Error())
			}
			v = out
		}
	case 12:
		// f p ≠ ∅ ∧ φ10 = 12 ∧ φ11 < ∣pw∣
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
				return gas, regs, mem, pvm.ErrPanicf(err.Error())
			}
			v = bytes
		}
	case 13:
		// if p ≠ ∅ ∧ φ10 = 13 ∧ φ11 < ∣pw∣
		if workPackage != nil && int(idx1) < len(workPackage.WorkItems) {
			v = workPackage.WorkItems[idx1].Payload
		}
	case 14:
		// if o ≠ ∅ ∧ φ10 = 14
		if len(operand) > 0 {
			out, err := jam.Marshal(operand)
			if err != nil {
				return gas, regs, mem, pvm.ErrPanicf(err.Error())
			}
			v = out
		}
	case 15:
		// if o ≠ ∅ ∧ φ10 = 15 ∧ φ11 < |o|
		if len(operand) > 0 && int(idx1) < len(operand) {
			out, err := jam.Marshal(operand[idx1])
			if err != nil {
				return gas, regs, mem, pvm.ErrPanicf(err.Error())
			}
			v = out
		}
	default:
		return gas, withCode(regs, NONE), mem, nil
	}

	if len(v) == 0 {
		return gas, withCode(regs, NONE), mem, nil
	}

	if err := writeFromOffset(&mem, output, v, offset, length); err != nil {
		return gas, regs, mem, err
	}

	regs[pvm.A0] = uint64(len(v))
	return gas, regs, mem, nil
}

// Lookup ΩL(ϱ, φ, μ, s, s, d)
func Lookup(gas pvm.Gas, regs pvm.Registers, mem pvm.Memory, s service.ServiceAccount, serviceId block.ServiceId, serviceState service.ServiceState) (pvm.Gas, pvm.Registers, pvm.Memory, error) {
	gas -= LookupCost

	omega7 := regs[pvm.A0]

	// Determine the lookup key 'a'
	a := s
	if uint64(omega7) != math.MaxUint64 && omega7 != uint64(serviceId) {
		var exists bool
		// lookup service account by serviceId in the serviceState
		a, exists = serviceState[serviceId]
		if !exists {
			regs[pvm.A0] = uint64(NONE)
			return gas, regs, mem, nil
		}
	}

	// let [h, o] = φ8..+2
	h, o := regs[pvm.A1], regs[pvm.A2]

	key := make([]byte, 32)
	if h > math.MaxUint32 {
		return gas, regs, mem, pvm.ErrPanicf("inaccessible memory, address out of range")
	}
	if err := mem.Read(uint32(h), key); err != nil {
		return gas, regs, mem, pvm.ErrPanicf(err.Error())
	}

	// lookup value in storage (v) using the hash
	v, exists := a.PreimageLookup[crypto.Hash(key)]
	if !exists {
		// v=∅ => (▸, NONE, μ)
		return gas, withCode(regs, NONE), mem, nil
	}

	if err := writeFromOffset(&mem, o, v, regs[pvm.A3], regs[pvm.A4]); err != nil {
		return gas, regs, mem, err
	}

	regs[pvm.A0] = uint64(len(v))
	return gas, regs, mem, nil
}

// Read ΩR(ϱ, φ, μ, s, s, d)
func Read(gas pvm.Gas, regs pvm.Registers, mem pvm.Memory, s service.ServiceAccount, serviceId block.ServiceId, serviceState service.ServiceState) (pvm.Gas, pvm.Registers, pvm.Memory, error) {
	gas -= ReadCost

	omega7 := regs[pvm.A0]
	// s* = φ7
	ss := block.ServiceId(omega7)
	if uint64(omega7) == math.MaxUint64 {
		ss = serviceId // s* = s
	}

	a := s.Clone()
	if ss != serviceId {
		var exists bool
		a, exists = serviceState[ss]
		if !exists {
			return gas, withCode(regs, NONE), mem, nil
		}
	}

	// let [ko, kz, o] = φ8..+3
	ko, kz, o := regs[pvm.A1], regs[pvm.A2], regs[pvm.A3]

	// read key data from memory at ko..ko+kz
	keyData := make([]byte, kz)
	if ko > math.MaxUint32 {
		return gas, regs, mem, pvm.ErrPanicf("inaccessible memory, address out of range")
	}
	err := mem.Read(uint32(ko), keyData)
	if err != nil {
		return gas, regs, mem, pvm.ErrPanicf(err.Error())
	}

	// Compute the hash H(keyData) and create a state key from it to use
	// as the storage key.
	k, err := statekey.NewStorage(ss, keyData)
	if err != nil {
		return gas, regs, mem, pvm.ErrPanicf(err.Error())
	}

	v, exists := a.GetStorage(k)
	if !exists {
		return gas, withCode(regs, NONE), mem, nil
	}

	if err = writeFromOffset(&mem, o, v, regs[pvm.A4], regs[pvm.A5]); err != nil {
		return gas, regs, mem, err
	}

	regs[pvm.A0] = uint64(len(v))
	return gas, regs, mem, nil
}

// Write ΩW(ϱ, φ, μ, s, s)
func Write(gas pvm.Gas, regs pvm.Registers, mem pvm.Memory, s service.ServiceAccount, serviceId block.ServiceId) (pvm.Gas, pvm.Registers, pvm.Memory, service.ServiceAccount, error) {
	gas -= WriteCost

	ko := regs[pvm.A0]
	kz := regs[pvm.A1]
	vo := regs[pvm.A2]
	vz := regs[pvm.A3]

	//µko⋅⋅⋅+kz
	keyData := make([]byte, kz)
	if ko > math.MaxUint32 {
		return gas, regs, mem, s, pvm.ErrPanicf("inaccessible memory, address out of range")
	}
	err := mem.Read(uint32(ko), keyData)
	if err != nil {
		return gas, regs, mem, s, pvm.ErrPanicf(err.Error())
	}

	k, err := statekey.NewStorage(serviceId, keyData)
	if err != nil {
		return gas, regs, mem, s, pvm.ErrPanicf(err.Error())
	}

	a := s.Clone()
	if vz == 0 {
		if val, ok := s.GetStorage(k); ok {
			err := a.DeleteStorage(k, kz, uint64(len(val)))
			if err != nil {
				return gas, regs, mem, s, pvm.ErrPanicf(err.Error())
			}
		}
	} else {
		valueData := make([]byte, vz)
		if vo > math.MaxUint32 {
			return gas, regs, mem, s, pvm.ErrPanicf("inaccessible memory, address out of range")
		}
		err = mem.Read(uint32(vo), valueData)
		if err != nil {
			return gas, regs, mem, s, pvm.ErrPanicf(err.Error())
		}

		err := a.InsertStorage(k, kz, valueData)
		if err != nil {
			return gas, regs, mem, s, pvm.ErrPanicf(err.Error())
		}
	}

	// let l = |s_s[k]| if k ∈ K(s_s); NONE otherwise
	var storageItemLength uint64
	storageItem, ok := s.GetStorage(k)
	if ok {
		storageItemLength = uint64(len(storageItem))
	} else {
		storageItemLength = uint64(NONE)
	}

	thresholdBalance, err := a.ThresholdBalance()
	if err != nil {
		return gas, regs, mem, s, pvm.ErrPanicf(err.Error())
	}
	if thresholdBalance > a.Balance {
		return gas, withCode(regs, FULL), mem, s, nil
	}

	// otherwise a.ThresholdBalance() <= a.Balance
	regs[pvm.A0] = storageItemLength // l
	return gas, regs, mem, a, err    // return service account 'a' as opposed to 's' for not successful paths
}

// Info ΩI(ϱ, φ, μ, s, d)
func Info(gas pvm.Gas, regs pvm.Registers, mem pvm.Memory, serviceId block.ServiceId, serviceState service.ServiceState) (pvm.Gas, pvm.Registers, pvm.Memory, error) {
	gas -= InfoCost

	omega7 := regs[pvm.A0]
	o := regs[pvm.A1]

	account, exists := serviceState[serviceId]
	if uint64(omega7) != math.MaxUint64 {
		account, exists = serviceState[block.ServiceId(omega7)]
	}
	if !exists {
		return gas, withCode(regs, NONE), mem, nil
	}

	thresholdBalance, err := account.ThresholdBalance()
	if err != nil {
		return gas, regs, mem, pvm.ErrPanicf(err.Error())
	}

	// E(ac, E8(ab, at, ag, am, ao), E4(ai), E8(af), E4(ar, aa, ap))
	v := slices.Concat(
		account.CodeHash[:],
		jam.EncodeUint64(account.Balance),
		jam.EncodeUint64(thresholdBalance),
		jam.EncodeUint64(account.GasLimitForAccumulator),
		jam.EncodeUint64(account.GasLimitOnTransfer),
		jam.EncodeUint64(account.GetTotalNumberOfOctets()),
		jam.EncodeUint32(account.GetTotalNumberOfItems()),
		jam.EncodeUint64(account.GratisStorageOffset),
		jam.EncodeUint32(uint32(account.CreationTimeslot)),
		jam.EncodeUint32(uint32(account.MostRecentAccumulationTimeslot)),
		jam.EncodeUint32(uint32(account.ParentService)),
	)

	if err = writeFromOffset(&mem, o, v, regs[pvm.A2], regs[pvm.A3]); err != nil {
		return gas, regs, mem, pvm.ErrPanicf(err.Error())
	}

	// φ′7 = |v|
	regs[pvm.A0] = uint64(len(v))

	return gas, regs, mem, nil
}

// Log A host call for passing a debugging message from the service/authorizer to the hosting environment for logging to the node operator
func Log(gas pvm.Gas, regs pvm.Registers, mem pvm.Memory, core *uint16, serviceId *block.ServiceId) (pvm.Gas, pvm.Registers, pvm.Memory, error) {
	gas -= LogCost

	fullMsg := &bytes.Buffer{}
	lvl := regs[pvm.A0]

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

	to := regs[pvm.A1]
	tz := regs[pvm.A2]
	xo := regs[pvm.A3]
	xz := regs[pvm.A4]

	// Write target
	if to != 0 && tz != 0 {
		targetBytes := make([]byte, tz)
		if to > math.MaxUint32 {
			return gas, regs, mem, pvm.ErrPanicf("inaccessible memory, address out of range")
		}
		err := mem.Read(uint32(to), targetBytes)
		if err != nil {
			log.VM.Error().Msgf("unable to access memory for target: address %d length %d", to, tz)
		}

		_, _ = fmt.Fprintf(fullMsg, " %s", targetBytes)
	}

	msgBytes := make([]byte, xz)
	if xo > math.MaxUint32 {
		return gas, regs, mem, pvm.ErrPanicf("inaccessible memory, address out of range")
	}
	err := mem.Read(uint32(xo), msgBytes)
	if err != nil {
		log.VM.Error().Msgf("unable to access memory for target: address %d length %d", to, tz)
	}

	// Write message
	_, _ = fmt.Fprintf(fullMsg, " %s", msgBytes)

	log.VM.Info().Str("msg", fullMsg.String()).Msg("Service log")
	return gas, withCode(regs, WHAT), mem, nil
}

// GetChainConstants
//
//	c = E(
//
// E8(BI), E8(BL), E8(BS), E2(C), E4(D), E4(E), E8(GA),
// E8(GI), E8(GR), E8(GT), E2(H), E2(I), E2(J), E4(L), E2(O),
// E2(P), E2(Q), E2(R), E2(S), E2(T), E2(U), E2(V), E4(WA),
// E4(WB), E4(WC), E4(WE), E4(WG), E4(WM), E4(WP),
// E4(WR), E4(WT), E4(WX), E4(Y)
//
// )

var encodedChainConstants = slices.Concat(
	jam.EncodeUint64(service.AdditionalMinimumBalancePerItem),    // BI
	jam.EncodeUint64(service.AdditionalMinimumBalancePerOctet),   // BL
	jam.EncodeUint64(service.BasicMinimumBalance),                // BS
	jam.EncodeUint16(common.TotalNumberOfCores),                  // C
	jam.EncodeUint32(jamtime.PreimageExpulsionPeriod),            // D
	jam.EncodeUint32(jamtime.TimeslotsPerEpoch),                  // E
	jam.EncodeUint64(common.MaxAllocatedGasAccumulation),         // GA
	jam.EncodeUint64(common.MaxAllocatedGasIsAuthorized),         // GI
	jam.EncodeUint64(common.MaxAllocatedGasRefine),               // GR
	jam.EncodeUint64(common.TotalGasAccumulation),                // GT
	jam.EncodeUint16(state.MaxRecentBlocks),                      // H
	jam.EncodeUint16(work.MaxNumberOfItems),                      // I
	jam.EncodeUint16(work.MaxNumberOfDependencyItems),            // J
	jam.EncodeUint16(block.MaxTicketsPerBlock),                   // K
	jam.EncodeUint32(state.MaxTimeslotsForLookupAnchor),          // L
	jam.EncodeUint16(common.MaxTicketAttemptsPerValidator),       // N
	jam.EncodeUint16(state.MaxAuthorizersPerCore),                // O
	jam.EncodeUint16(jamtime.SlotPeriodInSeconds),                // P
	jam.EncodeUint16(state.PendingAuthorizersQueueSize),          // Q
	jam.EncodeUint16(uint16(jamtime.ValidatorRotationPeriod)),    // R
	jam.EncodeUint16(work.MaxNumberOfExtrinsics),                 // T
	jam.EncodeUint16(uint16(common.WorkReportTimeoutPeriod)),     // U
	jam.EncodeUint16(common.NumberOfValidators),                  // V
	jam.EncodeUint32(state.MaximumSizeIsAuthorizedCode),          // W_A
	jam.EncodeUint32(common.MaxWorkPackageSize),                  // W_B
	jam.EncodeUint32(work.MaxSizeServiceCode),                    // W_C
	jam.EncodeUint32(common.ErasureCodingChunkSize),              // W_E
	jam.EncodeUint32(work.MaxNumberOfImports),                    // W_M
	jam.EncodeUint32(common.NumberOfErasureCodecPiecesInSegment), // W_P
	jam.EncodeUint32(common.MaxWorkPackageSizeBytes),             // W_R
	jam.EncodeUint32(service.TransferMemoSizeBytes),              // W_T
	jam.EncodeUint32(work.MaxNumberOfExports),                    // W_X
	jam.EncodeUint32(jamtime.TicketSubmissionTimeSlots),          // Y
)

func GetChainConstants() []byte {
	return encodedChainConstants
}
