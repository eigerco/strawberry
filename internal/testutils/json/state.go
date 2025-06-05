// Package jsonutils provides utilities for encoding and decoding internal JAM
// types to and from JSON based on the ASN.1 schema for jam types.
// (https://github.com/w3f/jamtestvectors/tree/master/jam-types-asn)

// The functionality provided is useful for testing and debugging purposes, ie
// dumping and restoring state snapshots. It should not be used in production
// code.

// This package does its best to ensure deterministic encoding by sorting various fields as
// specified by the GP appendix D. This allows for more useful JSON diffing.
package json

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type AuthPools [][]string

func NewAuthPools(pools state.CoreAuthorizersPool) AuthPools {
	poolsStrs := make([][]string, len(pools))
	for i, pool := range pools {
		poolStrs := make([]string, len(pool))
		for j, hash := range pool {
			poolStrs[j] = hashToHex(hash)
		}
		poolsStrs[i] = poolStrs
	}

	return poolsStrs
}

func (ap AuthPools) To() state.CoreAuthorizersPool {
	pools := state.CoreAuthorizersPool{}
	for i, poolStrs := range ap {
		pool := make([]crypto.Hash, len(poolStrs))
		for j, hashStr := range poolStrs {
			pool[j] = hexToHash(hashStr)
		}
		pools[i] = pool
	}

	return pools
}

type AuthQueues [][]string

func NewAuthQueues(queues state.PendingAuthorizersQueues) AuthQueues {
	queuesStrs := make([][]string, len(queues))
	for i, queue := range queues {
		queueStrs := make([]string, len(queue))
		for j, hash := range queue {
			queueStrs[j] = hashToHex(hash)
		}
		queuesStrs[i] = queueStrs
	}

	return queuesStrs
}

func (aq AuthQueues) To() state.PendingAuthorizersQueues {
	queues := state.PendingAuthorizersQueues{}
	for i, queueStrs := range aq {
		queue := state.PendingAuthorizersQueue{}
		for j, hashStr := range queueStrs {
			queue[j] = hexToHash(hashStr)
		}
		queues[i] = queue
	}

	return queues
}

type BlockInfo struct {
	HeaderHash string     `json:"header_hash"`
	MMR        MMR        `json:"mmr"`
	StateRoot  string     `json:"state_root"`
	Reported   []Reported `json:"reported"`
}

type MMR struct {
	Peaks []*string `json:"peaks"`
}

type Reported struct {
	Hash        string `json:"hash"`
	ExportsRoot string `json:"exports_root"`
}

func (bi BlockInfo) To() state.BlockState {
	peaks := make([]*crypto.Hash, len(bi.MMR.Peaks))
	for i, peakStr := range bi.MMR.Peaks {
		if peakStr == nil {
			continue
		}
		hash := hexToHash(*peakStr)
		peaks[i] = &hash
	}

	reportHashes := make(map[crypto.Hash]crypto.Hash)
	for _, reported := range bi.Reported {
		reportHashes[hexToHash(reported.Hash)] = hexToHash(reported.ExportsRoot)
	}

	return state.BlockState{
		HeaderHash:            hexToHash(bi.HeaderHash),
		StateRoot:             hexToHash(bi.StateRoot),
		AccumulationResultMMR: peaks,
		WorkReportHashes:      reportHashes,
	}
}

func NewBlockInfo(blockState state.BlockState) BlockInfo {
	peaks := make([]*string, len(blockState.AccumulationResultMMR))
	for i, peak := range blockState.AccumulationResultMMR {
		if peak == nil {
			continue
		}
		hexStr := hashToHex(*peak)
		peaks[i] = &hexStr
	}

	reported := make([]Reported, 0, len(blockState.WorkReportHashes))
	for hash, exportsRoot := range blockState.WorkReportHashes {
		reported = append(reported, Reported{
			Hash:        hashToHex(hash),
			ExportsRoot: hashToHex(exportsRoot),
		})
	}
	sort.Slice(reported, func(i, j int) bool {
		return strings.Compare(reported[i].Hash[1:], reported[j].Hash[1:]) < 0
	})

	return BlockInfo{
		HeaderHash: hashToHex(blockState.HeaderHash),
		MMR: MMR{
			Peaks: peaks,
		},
		StateRoot: hashToHex(blockState.StateRoot),
		Reported:  reported,
	}
}

type BlockHistory []BlockInfo

func (bh BlockHistory) To() []state.BlockState {
	blocks := make([]state.BlockState, len(bh))
	for i, blockInfo := range bh {
		blocks[i] = blockInfo.To()
	}

	return blocks
}

func NewBlockHistory(blocks []state.BlockState) BlockHistory {
	newBlocks := make([]BlockInfo, len(blocks))
	for i, blockState := range blocks {
		newBlocks[i] = NewBlockInfo(blockState)
	}

	return newBlocks
}

type ValidatorData struct {
	Bandersnatch string `json:"bandersnatch"`
	Ed25519      string `json:"ed25519"`
	Bls          string `json:"bls"`
	Metadata     string `json:"metadata"`
}

func (vd ValidatorData) To() crypto.ValidatorKey {
	return crypto.ValidatorKey{
		Bandersnatch: hexToBandersnatch(vd.Bandersnatch),
		Ed25519:      ed25519.PublicKey(hexToBytes(vd.Ed25519)),
		Bls:          crypto.BlsKey(hexToBytes(vd.Bls)),
		Metadata:     crypto.MetadataKey(hexToBytes(vd.Metadata)),
	}
}

func NewValidatorData(vk crypto.ValidatorKey) ValidatorData {
	return ValidatorData{
		Bandersnatch: bandersnatchToHex(vk.Bandersnatch),
		Ed25519:      bytesToHex(vk.Ed25519),
		Bls:          bytesToHex(vk.Bls[:]),
		Metadata:     bytesToHex(vk.Metadata[:]),
	}
}

type ValidatorsData []ValidatorData

func (vd ValidatorsData) To() safrole.ValidatorsData {
	validators := safrole.ValidatorsData{}
	for i, validatorData := range vd {
		vk := validatorData.To()
		validators[i] = vk
	}

	return validators
}

func NewValidatorsData(validators safrole.ValidatorsData) ValidatorsData {
	validatorsData := make(ValidatorsData, len(validators))
	for i, validator := range validators {
		validatorsData[i] = NewValidatorData(validator)
	}

	return validatorsData
}

type TicketsOrKeys struct {
	Keys    []string     `json:"keys,omitempty"`
	Tickets []TicketBody `json:"tickets,omitempty"`
}

func (tk TicketsOrKeys) To() safrole.SealingKeys {
	if len(tk.Keys) > 0 && len(tk.Tickets) > 0 {
		panic("cannot have both keys and tickets")
	}

	sealingKeys := safrole.SealingKeys{}

	if len(tk.Keys) > 0 {
		keys := crypto.EpochKeys{}
		for i, keyStr := range tk.Keys {
			keys[i] = hexToBandersnatch(keyStr)
		}
		err := sealingKeys.SetValue(keys)
		if err != nil {
			panic(fmt.Sprintf("failed to set keys: %v", err))
		}
	}
	if len(tk.Tickets) > 0 {
		tickets := safrole.TicketsBodies{}
		for i, ticket := range tk.Tickets {
			tickets[i] = ticket.To()
		}
		err := sealingKeys.SetValue(tickets)
		if err != nil {
			panic(fmt.Sprintf("failed to set tickets: %v", err))
		}
	}

	return sealingKeys
}

func NewTicketsOrKeys(sealingKeys safrole.SealingKeys) TicketsOrKeys {
	tok := TicketsOrKeys{}
	switch value := sealingKeys.Get().(type) {
	case safrole.TicketsBodies:
		tickets := make([]TicketBody, len(value))
		for i, ticket := range value {
			ticket := NewTicketBody(ticket)
			tickets[i] = ticket
		}
		tok.Tickets = tickets
	case crypto.EpochKeys:
		keys := make([]string, len(value))
		for i, key := range value {
			keys[i] = bandersnatchToHex(key)
		}
		tok.Keys = keys
	}

	return tok
}

type TicketBody struct {
	ID      string `json:"id"`
	Attempt uint8  `json:"attempt"`
}

func (tb TicketBody) To() block.Ticket {
	return block.Ticket{
		Identifier: crypto.BandersnatchOutputHash(hexToBytes(tb.ID)),
		EntryIndex: tb.Attempt,
	}
}

func NewTicketBody(ticket block.Ticket) TicketBody {
	return TicketBody{
		ID:      bytesToHex(ticket.Identifier[:]),
		Attempt: ticket.EntryIndex,
	}
}

type TicketsAccumulator []TicketBody

func (ta TicketsAccumulator) To() []block.Ticket {
	tickets := make([]block.Ticket, len(ta))
	for i, ticket := range ta {
		tickets[i] = ticket.To()
	}
	return tickets
}

func NewTicketsAccumulator(tickets []block.Ticket) TicketsAccumulator {
	ticketsAccumulator := make(TicketsAccumulator, len(tickets))
	for i, ticket := range tickets {
		ticketsAccumulator[i] = NewTicketBody(ticket)
	}

	return ticketsAccumulator
}

type EntropyPool []string

func (ep EntropyPool) To() state.EntropyPool {
	entropyPool := state.EntropyPool{}
	for i, entropy := range ep {
		entropyPool[i] = hexToHash(entropy)
	}

	return entropyPool
}

func NewEntropyPool(entropyPool state.EntropyPool) EntropyPool {
	entropyPoolStr := make(EntropyPool, len(entropyPool))
	for i, entropy := range entropyPool {
		entropyPoolStr[i] = hashToHex(entropy)
	}
	return entropyPoolStr
}

type Accounts []Account

func (a Accounts) To() service.ServiceState {
	accounts := service.ServiceState{}
	for _, account := range a {
		accountData := account.Data.To()
		accounts[block.ServiceId(account.ID)] = accountData
	}

	return accounts
}

func NewAccounts(accounts service.ServiceState) Accounts {
	newAccounts := make(Accounts, 0, len(accounts))
	for id, account := range accounts {
		newAccounts = append(newAccounts, Account{
			ID:   uint32(id),
			Data: NewAccountData(account),
		})
	}
	// Sevice accounts are sorted by the little endian encoding of their ID as per GP (D.2).
	sort.Slice(newAccounts, func(i, j int) bool {
		bi, err := jam.Marshal(newAccounts[i].ID)
		if err != nil {
			panic(fmt.Sprintf("failed to jam marshal account ID: %v", err))
		}
		bj, err := jam.Marshal(newAccounts[j].ID)
		if err != nil {
			panic(fmt.Sprintf("failed to jam marshal account ID: %v", err))
		}
		return bytes.Compare(bi, bj) < 0
	})

	return newAccounts
}

type Account struct {
	ID   uint32      `json:"id"`
	Data AccountData `json:"data"`
}

type AccountData struct {
	Service    ServiceInfo      `json:"service"`
	Preimages  []PreimageInfo   `json:"preimages"`
	LookupMeta []LookupMetaInfo `json:"lookup_meta"`
	Storage    *Storage         `json:"storage"`
}

func (ad AccountData) To() service.ServiceAccount {
	storage := map[statekey.StateKey][]byte{}
	if ad.Storage != nil {
		for k, v := range *ad.Storage {
			stateKey := hexToBytes(k)
			storage[statekey.StateKey(stateKey)] = hexToBytes(v)
		}
	}

	preimages := map[crypto.Hash][]byte{}
	for _, preimage := range ad.Preimages {
		preimages[hexToHash(preimage.Hash)] = hexToBytes(preimage.Blob)
	}

	lookupMeta := map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{}
	for _, meta := range ad.LookupMeta {
		key := service.PreImageMetaKey{
			Hash:   hexToHash(meta.Key.Hash),
			Length: service.PreimageLength(meta.Key.Length),
		}
		values := make(service.PreimageHistoricalTimeslots, len(meta.Value))
		for i, slot := range meta.Value {
			values[i] = jamtime.Timeslot(slot)
		}
		lookupMeta[key] = values
	}

	return service.ServiceAccount{
		Storage:                storage,
		PreimageLookup:         preimages,
		PreimageMeta:           lookupMeta,
		CodeHash:               hexToHash(ad.Service.CodeHash),
		Balance:                ad.Service.Balance,
		GasLimitForAccumulator: ad.Service.MinItemGas,
		GasLimitOnTransfer:     ad.Service.MinMemoGas,
	}
}

func NewAccountData(account service.ServiceAccount) AccountData {
	var storage *Storage
	if len(account.Storage) > 0 {
		s := Storage{}
		for sk, blob := range account.Storage {
			k := bytesToHex(sk[:])
			s[k] = bytesToHex(blob)
		}
		storage = &s
	}

	preimages := make([]PreimageInfo, 0, len(account.PreimageLookup))
	for hash, blob := range account.PreimageLookup {
		preimages = append(preimages, PreimageInfo{
			Hash: hashToHex(hash),
			Blob: bytesToHex(blob),
		})
	}
	// Sort as per state serialization in the GP (D.2).
	// h_1...29
	sort.Slice(preimages, func(i, j int) bool {
		hi := hexToBytes(preimages[i].Hash)
		hj := hexToBytes(preimages[j].Hash)
		return bytes.Compare(hi[1:29+1], hj[1:29+1]) < 0
	})

	lookupMeta := make([]LookupMetaInfo, 0, len(account.PreimageMeta))
	for preimageKey, values := range account.PreimageMeta {
		newValues := make([]uint32, len(values))
		for i, slot := range values {
			newValues[i] = uint32(slot)
		}
		lookupMeta = append(lookupMeta, LookupMetaInfo{
			Key: LookupMetaKey{
				Hash:   hashToHex(preimageKey.Hash),
				Length: uint32(preimageKey.Length),
			},
			Value: newValues,
		})
	}
	// Sort as per state serialization in the GP (D.2)
	// H(h)_2...30
	sort.Slice(lookupMeta, func(i, j int) bool {
		lengthi, err := jam.Marshal(lookupMeta[i].Key.Length)
		if err != nil {
			panic(fmt.Sprintf("failed to jam marshal lookup meta key length: %v", err))
		}
		hashi := crypto.HashData(hexToBytes(lookupMeta[i].Key.Hash))
		keyi := append(lengthi, hashi[2:30+1]...)

		lengthj, err := jam.Marshal(lookupMeta[j].Key.Length)
		if err != nil {
			panic(fmt.Sprintf("failed to jam marshal lookup meta key length: %v", err))
		}
		hashj := crypto.HashData(hexToBytes(lookupMeta[j].Key.Hash))
		keyj := append(lengthj, hashj[2:30+1]...)

		return bytes.Compare(keyi, keyj) < 0
	})

	return AccountData{
		Service: ServiceInfo{
			CodeHash:   bytesToHex(account.CodeHash[:]),
			Balance:    account.Balance,
			MinItemGas: account.GasLimitForAccumulator,
			MinMemoGas: account.GasLimitOnTransfer,
			Bytes:      account.TotalStorageSize(),
			Items:      account.TotalItems(),
		},
		Preimages:  preimages,
		LookupMeta: lookupMeta,
		Storage:    storage,
	}
}

type Storage map[string]string

type ServiceInfo struct {
	CodeHash   string `json:"code_hash"`
	Balance    uint64 `json:"balance"`
	MinItemGas uint64 `json:"min_item_gas"`
	MinMemoGas uint64 `json:"min_memo_gas"`
	Bytes      uint64 `json:"bytes"`
	Items      uint32 `json:"items"`
}

type PreimageInfo struct {
	Hash string `json:"hash"`
	Blob string `json:"blob"`
}

type LookupMetaInfo struct {
	Key   LookupMetaKey `json:"key"`
	Value []uint32      `json:"value"`
}

type LookupMetaKey struct {
	Hash   string `json:"hash"`
	Length uint32 `json:"length"`
}

type ActivityStatistics struct {
	ValsCurrent []ValidatorStatistics `json:"vals_current"`
	ValsLast    []ValidatorStatistics `json:"vals_last"`
	Cores       []CoreStatistics      `json:"cores"`
	Services    ServiceStatistics     `json:"services"`
}

func (as ActivityStatistics) To() validator.ActivityStatisticsState {
	valsCurrent := [common.NumberOfValidators]validator.ValidatorStatistics{}
	for i, v := range as.ValsCurrent {
		valsCurrent[i] = validator.ValidatorStatistics{
			NumOfBlocks:                 v.Blocks,
			NumOfTickets:                v.Tickets,
			NumOfPreimages:              v.PreImages,
			NumOfBytesAllPreimages:      v.PreImagesSize,
			NumOfGuaranteedReports:      v.Guarantees,
			NumOfAvailabilityAssurances: v.Assurances,
		}
	}

	valsLast := [common.NumberOfValidators]validator.ValidatorStatistics{}
	for i, v := range as.ValsLast {
		valsLast[i] = validator.ValidatorStatistics{
			NumOfBlocks:                 v.Blocks,
			NumOfTickets:                v.Tickets,
			NumOfPreimages:              v.PreImages,
			NumOfBytesAllPreimages:      v.PreImagesSize,
			NumOfGuaranteedReports:      v.Guarantees,
			NumOfAvailabilityAssurances: v.Assurances,
		}
	}

	coreStats := [common.TotalNumberOfCores]validator.CoreStatistics{}
	for i, c := range as.Cores {
		coreStats[i] = validator.CoreStatistics{
			DALoad:         c.DALoad,
			Popularity:     c.Popularity,
			Imports:        c.Imports,
			Exports:        c.Exports,
			ExtrinsicSize:  c.ExtrinsicSize,
			ExtrinsicCount: c.ExtrinsicCount,
			BundleSize:     c.BundleSize,
			GasUsed:        c.GasUsed,
		}
	}

	return validator.ActivityStatisticsState{
		ValidatorsCurrent: valsCurrent,
		ValidatorsLast:    valsLast,
		Cores:             coreStats,
		Services:          as.Services.To(),
	}
}

func NewActivityStatistics(stats validator.ActivityStatisticsState) ActivityStatistics {
	valsCurrent := make([]ValidatorStatistics, common.NumberOfValidators)
	for i, v := range stats.ValidatorsCurrent {
		valsCurrent[i] = ValidatorStatistics{
			Blocks:        v.NumOfBlocks,
			Tickets:       uint32(v.NumOfTickets),
			PreImages:     uint32(v.NumOfPreimages),
			PreImagesSize: uint32(v.NumOfBytesAllPreimages),
			Guarantees:    uint32(v.NumOfGuaranteedReports),
			Assurances:    uint32(v.NumOfAvailabilityAssurances),
		}
	}

	valsLast := make([]ValidatorStatistics, common.NumberOfValidators)
	for i, v := range stats.ValidatorsLast {
		valsLast[i] = ValidatorStatistics{
			Blocks:        v.NumOfBlocks,
			Tickets:       uint32(v.NumOfTickets),
			PreImages:     uint32(v.NumOfPreimages),
			PreImagesSize: uint32(v.NumOfBytesAllPreimages),
			Guarantees:    uint32(v.NumOfGuaranteedReports),
			Assurances:    uint32(v.NumOfAvailabilityAssurances),
		}
	}

	coreStats := make([]CoreStatistics, common.TotalNumberOfCores)
	for i, c := range stats.Cores {
		coreStats[i] = CoreStatistics{
			DALoad:         c.DALoad,
			Popularity:     c.Popularity,
			Imports:        c.Imports,
			Exports:        c.Exports,
			ExtrinsicSize:  c.ExtrinsicSize,
			ExtrinsicCount: c.ExtrinsicCount,
			BundleSize:     c.BundleSize,
			GasUsed:        c.GasUsed,
		}
	}

	return ActivityStatistics{
		ValsCurrent: valsCurrent,
		ValsLast:    valsLast,
		Cores:       coreStats,
		Services:    NewServiceStatistics(stats.Services),
	}
}

type ValidatorStatistics struct {
	Blocks        uint32 `json:"blocks"`
	Tickets       uint32 `json:"tickets"`
	PreImages     uint32 `json:"pre_images"`
	PreImagesSize uint32 `json:"pre_images_size"`
	Guarantees    uint32 `json:"guarantees"`
	Assurances    uint32 `json:"assurances"`
}

type CoreStatistics struct {
	DALoad         uint32 `json:"da_load"`
	Popularity     uint16 `json:"popularity"`
	Imports        uint16 `json:"imports"`
	Exports        uint16 `json:"exports"`
	ExtrinsicSize  uint32 `json:"extrinsic_size"`
	ExtrinsicCount uint16 `json:"extrinsic_count"`
	BundleSize     uint32 `json:"bundle_size"`
	GasUsed        uint64 `json:"gas_used"`
}

type ServiceStatisticsRecord struct {
	ProvidedCount      uint16 `json:"provided_count"`
	ProvidedSize       uint32 `json:"provided_size"`
	RefinementCount    uint32 `json:"refinement_count"`
	RefinementGasUsed  uint64 `json:"refinement_gas_used"`
	Imports            uint32 `json:"imports"`
	Exports            uint32 `json:"exports"`
	ExtrinsicSize      uint32 `json:"extrinsic_size"`
	ExtrinsicCount     uint32 `json:"extrinsic_count"`
	AccumulateCount    uint32 `json:"accumulate_count"`
	AccumulateGasUsed  uint64 `json:"accumulate_gas_used"`
	OnTransfersCount   uint32 `json:"on_transfers_count"`
	OnTransfersGasUsed uint64 `json:"on_transfers_gas_used"`
}

type ServiceStatisticsEntry struct {
	ID     uint32                  `json:"id"`
	Record ServiceStatisticsRecord `json:"record"`
}

type ServiceStatistics []ServiceStatisticsEntry

func (s ServiceStatistics) To() validator.ServiceStatistics {
	newServiceStats := make(validator.ServiceStatistics, len(s))
	for _, statEntry := range s {
		newServiceStats[block.ServiceId(statEntry.ID)] = validator.ServiceActivityRecord{
			ProvidedCount:      statEntry.Record.ProvidedCount,
			ProvidedSize:       statEntry.Record.ProvidedSize,
			RefinementCount:    statEntry.Record.RefinementCount,
			RefinementGasUsed:  statEntry.Record.RefinementGasUsed,
			Imports:            statEntry.Record.Imports,
			Exports:            statEntry.Record.Exports,
			ExtrinsicSize:      statEntry.Record.ExtrinsicSize,
			ExtrinsicCount:     statEntry.Record.ExtrinsicCount,
			AccumulateCount:    statEntry.Record.AccumulateCount,
			AccumulateGasUsed:  statEntry.Record.AccumulateGasUsed,
			OnTransfersCount:   statEntry.Record.OnTransfersCount,
			OnTransfersGasUsed: statEntry.Record.OnTransfersGasUsed,
		}
	}

	return newServiceStats
}

func NewServiceStatistics(s validator.ServiceStatistics) ServiceStatistics {
	newServiceStats := make(ServiceStatistics, 0, len(s))
	for id, record := range s {
		newServiceStats = append(newServiceStats, ServiceStatisticsEntry{
			ID: uint32(id),
			Record: ServiceStatisticsRecord{
				ProvidedCount:      record.ProvidedCount,
				ProvidedSize:       record.ProvidedSize,
				RefinementCount:    record.RefinementCount,
				RefinementGasUsed:  record.RefinementGasUsed,
				Imports:            record.Imports,
				Exports:            record.Exports,
				ExtrinsicSize:      record.ExtrinsicSize,
				ExtrinsicCount:     record.ExtrinsicCount,
				AccumulateCount:    record.AccumulateCount,
				AccumulateGasUsed:  record.AccumulateGasUsed,
				OnTransfersCount:   record.OnTransfersCount,
				OnTransfersGasUsed: record.OnTransfersGasUsed,
			},
		})
	}

	// Sort by Service ID
	sort.Slice(newServiceStats, func(i, j int) bool {
		return newServiceStats[i].ID < newServiceStats[j].ID
	})

	return newServiceStats
}

type DisputeRecords struct {
	Good      []string `json:"good"`
	Bad       []string `json:"bad"`
	Wonky     []string `json:"wonky"`
	Offenders []string `json:"offenders"`
}

func (d DisputeRecords) To() state.Judgements {
	good := make([]crypto.Hash, len(d.Good))
	for i, hash := range d.Good {
		good[i] = hexToHash(hash)
	}

	bad := make([]crypto.Hash, len(d.Bad))
	for i, hash := range d.Bad {
		bad[i] = hexToHash(hash)
	}

	wonky := make([]crypto.Hash, len(d.Wonky))
	for i, hash := range d.Wonky {
		wonky[i] = hexToHash(hash)
	}

	offenders := make([]ed25519.PublicKey, len(d.Offenders))
	for i, key := range d.Offenders {
		offenders[i] = ed25519.PublicKey(hexToBytes(key))
	}

	return state.Judgements{
		GoodWorkReports:     good,
		BadWorkReports:      bad,
		WonkyWorkReports:    wonky,
		OffendingValidators: offenders,
	}
}

func NewDisputeRecords(judgements state.Judgements) DisputeRecords {
	good := make([]string, len(judgements.GoodWorkReports))
	for i, hash := range judgements.GoodWorkReports {
		good[i] = hashToHex(hash)
	}

	bad := make([]string, len(judgements.BadWorkReports))
	for i, hash := range judgements.BadWorkReports {
		bad[i] = hashToHex(hash)
	}

	wonky := make([]string, len(judgements.WonkyWorkReports))
	for i, hash := range judgements.WonkyWorkReports {
		wonky[i] = hashToHex(hash)
	}

	offenders := make([]string, len(judgements.OffendingValidators))
	for i, key := range judgements.OffendingValidators {
		offenders[i] = bytesToHex(key)
	}

	return DisputeRecords{
		Good:      good,
		Bad:       bad,
		Wonky:     wonky,
		Offenders: offenders,
	}
}

type AvailabilityAssigments []*AvailabilityAssigment

func (aa AvailabilityAssigments) To() state.CoreAssignments {
	assignments := state.CoreAssignments{}
	for i, a := range aa {
		if a == nil {
			continue
		}
		report := a.Report.To()

		assignments[i] = &state.Assignment{
			WorkReport: &report,
			Time:       jamtime.Timeslot(a.Timeout),
		}
	}

	return assignments
}

func NewAvailabilityAssigments(assignments state.CoreAssignments) AvailabilityAssigments {
	aa := make(AvailabilityAssigments, len(assignments))
	for i, a := range assignments {
		if a == nil {
			continue
		}
		report := NewWorkReport(*a.WorkReport)
		aa[i] = &AvailabilityAssigment{
			Report:  &report,
			Timeout: uint32(a.Time),
		}
	}

	return aa
}

type AvailabilityAssigment struct {
	Report  *WorkReport `json:"report,omitempty"`
	Timeout uint32      `json:"timeout"`
}

type WorkReport struct {
	PackageSpec       WorkPackageSpec         `json:"package_spec"`
	Context           RefineContext           `json:"context"`
	CoreIndex         uint16                  `json:"core_index"`
	AuthorizerHash    string                  `json:"authorizer_hash"`
	AuthOutput        string                  `json:"auth_output"`
	SegmentRootLookup []SegmentRootLookupItem `json:"segment_root_lookup"`
	Results           []WorkResult            `json:"results"`
	AuthGasUsed       uint64                  `json:"auth_gas_used"`
}

func (w WorkReport) To() block.WorkReport {
	results := make([]block.WorkResult, len(w.Results))
	for i, r := range w.Results {
		results[i] = r.To()
	}

	segmentRootLookup := map[crypto.Hash]crypto.Hash{}
	for _, item := range w.SegmentRootLookup {
		segmentRootLookup[hexToHash(item.WorkPackageHash)] = hexToHash(item.SegmentTreeRoot)
	}

	return block.WorkReport{
		WorkPackageSpecification: w.PackageSpec.To(),
		RefinementContext:        w.Context.To(),
		CoreIndex:                w.CoreIndex,
		AuthorizerHash:           hexToHash(w.AuthorizerHash),
		Output:                   hexToBytes(w.AuthOutput),
		SegmentRootLookup:        segmentRootLookup,
		WorkResults:              results,
		AuthGasUsed:              w.AuthGasUsed,
	}
}

func NewWorkReport(report block.WorkReport) WorkReport {
	results := make([]WorkResult, len(report.WorkResults))
	for i, r := range report.WorkResults {
		results[i] = NewWorkResult(r)
	}

	segmentRootLookup := make([]SegmentRootLookupItem, 0, len(report.SegmentRootLookup))
	for workPackageHash, segmentTreeRoot := range report.SegmentRootLookup {
		segmentRootLookup = append(segmentRootLookup, SegmentRootLookupItem{
			WorkPackageHash: hashToHex(workPackageHash),
			SegmentTreeRoot: hashToHex(segmentTreeRoot),
		})
	}
	sort.Slice(segmentRootLookup, func(i, j int) bool {
		return strings.Compare(segmentRootLookup[i].WorkPackageHash, segmentRootLookup[j].WorkPackageHash) < 0
	})

	return WorkReport{
		PackageSpec:       NewWorkPackageSpec(report.WorkPackageSpecification),
		Context:           NewRefineContext(report.RefinementContext),
		CoreIndex:         report.CoreIndex,
		AuthorizerHash:    hashToHex(report.AuthorizerHash),
		AuthOutput:        bytesToHex(report.Output),
		Results:           results,
		SegmentRootLookup: segmentRootLookup,
		AuthGasUsed:       uint64(report.AuthGasUsed),
	}
}

type SegmentRootLookupItem struct {
	WorkPackageHash string `json:"work_package_hash"`
	SegmentTreeRoot string `json:"segment_tree_root"`
}

type WorkPackageSpec struct {
	Hash         string `json:"hash"`
	Length       uint32 `json:"length"`
	ErasureRoot  string `json:"erasure_root"`
	ExportsRoot  string `json:"exports_root"`
	ExportsCount uint16 `json:"exports_count"`
}

func (w WorkPackageSpec) To() block.WorkPackageSpecification {
	return block.WorkPackageSpecification{
		WorkPackageHash:           hexToHash(w.Hash),
		AuditableWorkBundleLength: w.Length,
		ErasureRoot:               hexToHash(w.ErasureRoot),
		SegmentRoot:               hexToHash(w.ExportsRoot),
		SegmentCount:              w.ExportsCount,
	}
}

func NewWorkPackageSpec(spec block.WorkPackageSpecification) WorkPackageSpec {
	return WorkPackageSpec{
		Hash:         hashToHex(spec.WorkPackageHash),
		Length:       spec.AuditableWorkBundleLength,
		ErasureRoot:  hashToHex(spec.ErasureRoot),
		ExportsRoot:  hashToHex(spec.SegmentRoot),
		ExportsCount: spec.SegmentCount,
	}
}

type RefineContext struct {
	Anchor           string   `json:"anchor"`
	StateRoot        string   `json:"state_root"`
	BeefyRoot        string   `json:"beefy_root"`
	LookupAnchor     string   `json:"lookup_anchor"`
	LookupAnchorSlot uint32   `json:"lookup_anchor_slot"`
	Prerequisites    []string `json:"prerequisites"`
}

func (r RefineContext) To() block.RefinementContext {
	prerequisites := make([]crypto.Hash, len(r.Prerequisites))
	for i, prereq := range r.Prerequisites {
		prerequisites[i] = hexToHash(prereq)
	}

	return block.RefinementContext{
		Anchor: block.RefinementContextAnchor{
			HeaderHash:         hexToHash(r.Anchor),
			PosteriorStateRoot: hexToHash(r.StateRoot),
			PosteriorBeefyRoot: hexToHash(r.BeefyRoot),
		},
		LookupAnchor: block.RefinementContextLookupAnchor{
			HeaderHash: hexToHash(r.LookupAnchor),
			Timeslot:   jamtime.Timeslot(r.LookupAnchorSlot),
		},
		PrerequisiteWorkPackage: prerequisites,
	}
}

func NewRefineContext(context block.RefinementContext) RefineContext {
	anchor := hashToHex(context.Anchor.HeaderHash)
	stateRoot := hashToHex(context.Anchor.PosteriorStateRoot)
	beefyRoot := hashToHex(context.Anchor.PosteriorBeefyRoot)
	lookupAnchor := hashToHex(context.LookupAnchor.HeaderHash)
	prerequisites := make([]string, len(context.PrerequisiteWorkPackage))
	for i, prereq := range context.PrerequisiteWorkPackage {
		prerequisites[i] = hashToHex(prereq)
	}

	return RefineContext{
		Anchor:           anchor,
		StateRoot:        stateRoot,
		BeefyRoot:        beefyRoot,
		LookupAnchor:     lookupAnchor,
		LookupAnchorSlot: uint32(context.LookupAnchor.Timeslot),
		Prerequisites:    prerequisites,
	}
}

type WorkResult struct {
	ServiceID     uint32             `json:"service_id"`
	CodeHash      string             `json:"code_hash"`
	PayloadHash   string             `json:"payload_hash"`
	AccumulateGas uint64             `json:"accumulate_gas"`
	Result        map[string]*string `json:"result"`
	RefineLoad    RefineLoad         `json:"refine_load"`
}

var toWorkResultErrorMap = map[string]block.WorkResultError{
	"out-of-gas":    block.OutOfGas,
	"panic":         block.UnexpectedTermination,
	"bad-exports":   block.InvalidNumberOfExports,
	"bad-code":      block.CodeNotAvailable,
	"code-oversize": block.CodeTooLarge,
}

// TODO potentially use an init() fn to generate this.
var fromWorkResultErrorMap = map[block.WorkResultError]string{
	block.OutOfGas:               "out-of-gas",
	block.UnexpectedTermination:  "panic",
	block.InvalidNumberOfExports: "bad-exports",
	block.CodeNotAvailable:       "bad-code",
	block.CodeTooLarge:           "code-oversize",
}

func (w WorkResult) To() block.WorkResult {
	serviceID := block.ServiceId(w.ServiceID)

	resultOutput := block.WorkResultOutputOrError{}
	if len(w.Result) != 1 {
		panic("work result map should have one key/value")
	}
	for resultType, output := range w.Result {
		if resultType == "ok" {
			if output == nil {
				panic("work result was ok with nil output")
			}
			err := resultOutput.SetValue(hexToBytes(*output))
			if err != nil {
				panic(err)
			}
		} else {
			workResultError, ok := toWorkResultErrorMap[resultType]
			if !ok {
				panic(fmt.Sprintf("unknown work result type %s", resultType))
			}
			err := resultOutput.SetValue(workResultError)
			if err != nil {
				panic(err)
			}
		}
	}

	return block.WorkResult{
		ServiceId:              serviceID,
		ServiceHashCode:        hexToHash(w.CodeHash),
		PayloadHash:            hexToHash(w.PayloadHash),
		GasPrioritizationRatio: w.AccumulateGas,
		Output:                 resultOutput,
		GasUsed:                w.RefineLoad.GasUsed,
		ImportsCount:           w.RefineLoad.Imports,
		ExtrinsicCount:         w.RefineLoad.ExtrinsicCount,
		ExtrinsicSize:          w.RefineLoad.ExtrinsicSize,
		ExportsCount:           w.RefineLoad.Exports,
	}
}

func NewWorkResult(result block.WorkResult) WorkResult {
	resultMap := make(map[string]*string)
	switch v := result.Output.Inner.(type) {
	case []byte:
		output := bytesToHex(v)
		resultMap["ok"] = &output
	case block.WorkResultError:
		resultError := fromWorkResultErrorMap[v]
		resultMap[resultError] = nil
	}

	return WorkResult{
		ServiceID:     uint32(result.ServiceId),
		CodeHash:      hashToHex(result.ServiceHashCode),
		PayloadHash:   hashToHex(result.PayloadHash),
		AccumulateGas: result.GasPrioritizationRatio,
		Result:        resultMap,
		RefineLoad: RefineLoad{
			GasUsed:        result.GasUsed,
			Imports:        result.ImportsCount,
			ExtrinsicCount: result.ExtrinsicCount,
			ExtrinsicSize:  result.ExtrinsicSize,
			Exports:        result.ExportsCount,
		},
	}
}

type RefineLoad struct {
	GasUsed        uint64 `json:"gas_used"`
	Imports        uint16 `json:"imports"`
	ExtrinsicCount uint16 `json:"extrinsic_count"`
	ExtrinsicSize  uint32 `json:"extrinsic_size"`
	Exports        uint16 `json:"exports"`
}

type PrivilegedServices struct {
	ManagerService   uint32            `json:"chi_m"`
	AssignService    uint32            `json:"chi_a"`
	DesignateService uint32            `json:"chi_v"`
	GasUsed          map[uint32]uint64 `json:"chi_g"`
}

func (p PrivilegedServices) To() service.PrivilegedServices {
	gasUsed := make(map[block.ServiceId]uint64)
	for serviceId, gas := range p.GasUsed {
		gasUsed[block.ServiceId(serviceId)] = gas
	}

	return service.PrivilegedServices{
		ManagerServiceId:        block.ServiceId(p.ManagerService),
		AssignServiceId:         block.ServiceId(p.AssignService),
		DesignateServiceId:      block.ServiceId(p.DesignateService),
		AmountOfGasPerServiceId: gasUsed,
	}
}

func NewPrivilegedServices(services service.PrivilegedServices) PrivilegedServices {
	gasUsed := make(map[uint32]uint64)
	for serviceId, gas := range services.AmountOfGasPerServiceId {
		gasUsed[uint32(serviceId)] = gas
	}

	return PrivilegedServices{
		ManagerService:   uint32(services.ManagerServiceId),
		AssignService:    uint32(services.AssignServiceId),
		DesignateService: uint32(services.DesignateServiceId),
		GasUsed:          gasUsed,
	}
}

type AccumulatedQueue [][]string

func (a AccumulatedQueue) To() state.AccumulationHistory {
	history := state.AccumulationHistory{}
	for i, queueStr := range a {
		queue := map[crypto.Hash]struct{}{}
		for _, hashStr := range queueStr {
			queue[hexToHash(hashStr)] = struct{}{}
		}
		history[i] = queue
	}

	return history
}

func NewAccumulatedQueue(history state.AccumulationHistory) AccumulatedQueue {
	accumulatedQueue := make(AccumulatedQueue, len(history))
	for i, queue := range history {
		queueStr := make([]string, 0, len(queue))
		for hash := range queue {
			queueStr = append(queueStr, hashToHex(hash))
		}
		sort.Strings(queueStr)
		accumulatedQueue[i] = queueStr
	}

	return accumulatedQueue
}

type ReadyQueue [][]ReadyRecord

func (rq ReadyQueue) To() state.AccumulationQueue {
	queue := state.AccumulationQueue{}
	for i, records := range rq {
		newRecords := make([]state.WorkReportWithUnAccumulatedDependencies, 0, len(records))
		for _, record := range records {
			dependencies := map[crypto.Hash]struct{}{}
			for _, hashStr := range record.Dependencies {
				dependencies[hexToHash(hashStr)] = struct{}{}
			}
			newRecords = append(newRecords, state.WorkReportWithUnAccumulatedDependencies{
				WorkReport:   record.Report.To(),
				Dependencies: dependencies,
			})
		}
		queue[i] = newRecords
	}

	return queue
}

func NewReadyQueue(queue state.AccumulationQueue) ReadyQueue {
	readyQueue := make(ReadyQueue, len(queue))
	for i, records := range queue {
		newRecords := make([]ReadyRecord, 0, len(records))
		for _, record := range records {
			dependencies := make([]string, 0, len(record.Dependencies))
			for hash := range record.Dependencies {
				dependencies = append(dependencies, hashToHex(hash))
			}
			sort.Strings(dependencies)
			newRecords = append(newRecords, ReadyRecord{
				Report:       NewWorkReport(record.WorkReport),
				Dependencies: dependencies,
			})
		}
		readyQueue[i] = newRecords
	}

	return readyQueue
}

type ReadyRecord struct {
	Report       WorkReport
	Dependencies []string
}

type SafroleState struct {
	PendingValidators  ValidatorsData     `json:"gamma_k"`
	RingCommitment     string             `json:"gamma_z"`
	SealingKeySeries   TicketsOrKeys      `json:"gamma_s"`
	TicketsAccumulator TicketsAccumulator `json:"gamma_a"`
}

func (s SafroleState) To() safrole.State {
	return safrole.State{
		NextValidators:    s.PendingValidators.To(),
		RingCommitment:    crypto.RingCommitment(hexToBytes(s.RingCommitment)),
		SealingKeySeries:  s.SealingKeySeries.To(),
		TicketAccumulator: s.TicketsAccumulator.To(),
	}
}

func NewSafroleState(state safrole.State) SafroleState {
	return SafroleState{
		PendingValidators:  NewValidatorsData(state.NextValidators),
		RingCommitment:     bytesToHex(state.RingCommitment[:]),
		SealingKeySeries:   NewTicketsOrKeys(state.SealingKeySeries),
		TicketsAccumulator: NewTicketsAccumulator(state.TicketAccumulator),
	}
}

type State struct {
	AuthPools               AuthPools              `json:"alpha"`
	AuthQueues              AuthQueues             `json:"varphi"`
	BlockHistory            BlockHistory           `json:"beta"`
	SafroleState            SafroleState           `json:"gamma"`
	DisputeRecords          DisputeRecords         `json:"psi"`
	EntropyPool             EntropyPool            `json:"eta"`
	QueuedValidators        ValidatorsData         `json:"iota"`
	ActiveValidators        ValidatorsData         `json:"kappa"`
	ArchivedValidators      ValidatorsData         `json:"lambda"`
	AvailabilityAssignments AvailabilityAssigments `json:"rho"`
	Timeslot                uint32                 `json:"tau"`
	PrivilegedServices      PrivilegedServices     `json:"chi"`
	ActivityStatistics      ActivityStatistics     `json:"pi"`
	ReadyQueue              ReadyQueue             `json:"theta"`
	AccumulatedQueue        AccumulatedQueue       `json:"xi"`
	Accounts                Accounts               `json:"accounts"`
}

func (s State) To() state.State {
	return state.State{
		CoreAuthorizersPool:      s.AuthPools.To(),
		PendingAuthorizersQueues: s.AuthQueues.To(),
		RecentBlocks:             s.BlockHistory.To(),
		ValidatorState: validator.ValidatorState{
			QueuedValidators:   s.QueuedValidators.To(),
			CurrentValidators:  s.ActiveValidators.To(),
			ArchivedValidators: s.ArchivedValidators.To(),
			SafroleState:       s.SafroleState.To(),
		},
		EntropyPool:         s.EntropyPool.To(),
		PastJudgements:      s.DisputeRecords.To(),
		CoreAssignments:     s.AvailabilityAssignments.To(),
		TimeslotIndex:       jamtime.Timeslot(s.Timeslot),
		ActivityStatistics:  s.ActivityStatistics.To(),
		PrivilegedServices:  s.PrivilegedServices.To(),
		AccumulationQueue:   s.ReadyQueue.To(),
		AccumulationHistory: s.AccumulatedQueue.To(),
		Services:            s.Accounts.To(),
	}
}

func NewState(state state.State) State {
	return State{
		AuthPools:               NewAuthPools(state.CoreAuthorizersPool),
		AuthQueues:              NewAuthQueues(state.PendingAuthorizersQueues),
		BlockHistory:            NewBlockHistory(state.RecentBlocks),
		SafroleState:            NewSafroleState(state.ValidatorState.SafroleState),
		DisputeRecords:          NewDisputeRecords(state.PastJudgements),
		EntropyPool:             NewEntropyPool(state.EntropyPool),
		QueuedValidators:        NewValidatorsData(state.ValidatorState.QueuedValidators),
		ActiveValidators:        NewValidatorsData(state.ValidatorState.CurrentValidators),
		ArchivedValidators:      NewValidatorsData(state.ValidatorState.ArchivedValidators),
		AvailabilityAssignments: NewAvailabilityAssigments(state.CoreAssignments),
		Timeslot:                uint32(state.TimeslotIndex),
		PrivilegedServices:      NewPrivilegedServices(state.PrivilegedServices),
		ActivityStatistics:      NewActivityStatistics(state.ActivityStatistics),
		ReadyQueue:              NewReadyQueue(state.AccumulationQueue),
		AccumulatedQueue:        NewAccumulatedQueue(state.AccumulationHistory),
		Accounts:                NewAccounts(state.Services),
	}
}

func DumpStateSnapshot(state state.State) string {
	b, err := json.MarshalIndent(NewState(state), "", "    ")
	if err != nil {
		panic(fmt.Sprintf("failed to marshal state: %v", err))
	}
	return string(b)
}

func RestoreStateSnapshot(b []byte) state.State {
	var state State
	err := json.Unmarshal(b, &state)
	if err != nil {
		panic(fmt.Sprintf("failed to unmarshal state: %v", err))
	}
	return state.To()
}

func hashToHex(hash crypto.Hash) string {
	return bytesToHex(hash[:])
}

func hexToHash(hashStr string) crypto.Hash {
	return crypto.Hash(hexToBytes(hashStr))
}

func hexToBandersnatch(bStr string) crypto.BandersnatchPublicKey {
	return crypto.BandersnatchPublicKey(hexToBytes(bStr))
}

func bandersnatchToHex(b crypto.BandersnatchPublicKey) string {
	return bytesToHex(b[:])
}

func bytesToHex(bytes []byte) string {
	return "0x" + hex.EncodeToString(bytes)
}

func hexToBytes(hexStr string) []byte {
	bytes, err := hex.DecodeString(strings.Replace(hexStr, "0x", "", 1))
	if err != nil {
		panic(fmt.Sprintf("failed to decode hex string: %v", err))
	}

	return bytes
}
