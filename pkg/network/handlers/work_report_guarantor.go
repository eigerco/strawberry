package handlers

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/eigerco/strawberry/internal/authorization"
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/refine"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/internal/work/results"
	"github.com/eigerco/strawberry/pkg/network/peer"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	// The maximum amount of signatures we can obtain to guarantee work report
	maxSignaturesRequiredToGuarantee = 3
	// We need at least this amount of signatures to guarantee work report
	minSignaturesRequiredToGuarantee = 2
	// The third guarantor should be given a reasonable amount of time (e.g. two seconds) to produce
	// an additional signature before the guaranteed work-report is distrubuted
	maxWaitTimeForThirdGuarantor = time.Second * 2
)

// WorkReportGuarantor handles CE-134 and CE-135:
// - CE-134: share a work-package with other guarantors, run local refinement, collect wr hashes signatures
// - CE-135: if enough signatures are gathered, broadcast the guaranteed work-report to validators
type WorkReportGuarantor struct {
	validatorIndex uint16
	privateKey     ed25519.PrivateKey
	guarantors     []*peer.Peer
	mu             sync.RWMutex
	auth           authorization.AuthPVMInvoker
	refine         refine.RefinePVMInvoker
	state          *state.State
	peerSet        *peer.PeerSet
}

// SegmentRootMapping It maps a work-package hash (h⊞) to the actual segment root (H).
type SegmentRootMapping struct {
	WorkPackageHash crypto.Hash // h⊞
	SegmentRoot     crypto.Hash // H
}

type guaranteeResponse struct {
	workReportHash crypto.Hash
	validatorIndex uint16
	signature      crypto.Ed25519Signature
	err            error
}

type localReportResult struct {
	report block.WorkReport
	err    error
}

func NewWorkReportGuarantor(
	validatorIndex uint16,
	privateKey ed25519.PrivateKey,
	auth authorization.AuthPVMInvoker,
	refine refine.RefinePVMInvoker,
	state state.State,
	peerSet *peer.PeerSet,
) *WorkReportGuarantor {
	return &WorkReportGuarantor{
		validatorIndex: validatorIndex,
		privateKey:     privateKey,
		auth:           auth,
		refine:         refine,
		state:          &state,
		peerSet:        peerSet,
	}
}

func (h *WorkReportGuarantor) SetGuarantors(guarantors []*peer.Peer) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.guarantors = guarantors
}

// ValidateAndProcessWorkPackage sends the work-package bundle to other guarantors and runs local refinement
func (h *WorkReportGuarantor) ValidateAndProcessWorkPackage(ctx context.Context, coreIndex uint16, bundle work.PackageBundle) error {
	// Validate the basic structure and constraints of the work-package
	if err := bundle.Package.ValidateLimits(); err != nil {
		return err
	}
	if err := bundle.Package.ValidateGas(); err != nil {
		return err
	}
	if err := bundle.Package.ValidateSize(); err != nil {
		return err
	}

	if err := h.validateAgainstAuthorizationPool(coreIndex, bundle.Package); err != nil {
		return err
	}

	// Run authorization to produce the auth output needed for refinement
	authOutput, err := h.auth.InvokePVM(bundle.Package, coreIndex)
	if err != nil {
		return fmt.Errorf("authorization failed: %w", err)
	}
	// TODO retrieve import segments and produce the mappings
	segments := h.buildSegmentRootMapping(bundle)

	return h.processWorkPackage(ctx, authOutput, segments, coreIndex, bundle)
}

// validateAgainstAuthorizationPool checks 11.29:
//   - the work-package AuthCodeHash must be present in the core's pool.
func (h *WorkReportGuarantor) validateAgainstAuthorizationPool(
	coreIdx uint16,
	pkg work.Package,
) error {
	pool := h.state.CoreAuthorizersPool[coreIdx]
	for _, hash := range pool {
		if hash == pkg.AuthCodeHash {
			// authorized
			return nil
		}
	}
	return fmt.Errorf("auth hash %x is not in authorizer pool for core %d",
		pkg.AuthCodeHash, coreIdx)
}

// Start sharing work package bundle with other guarantors and local refinement in parallel
func (h *WorkReportGuarantor) processWorkPackage(
	ctx context.Context,
	authOutput []byte,
	segments []SegmentRootMapping,
	coreIndex uint16,
	bundle work.PackageBundle,
) error {
	if coreIndex >= common.TotalNumberOfCores {
		return fmt.Errorf("invalid coreIndex: %d (must be < %d)",
			coreIndex, common.TotalNumberOfCores)
	}

	h.mu.RLock()
	guarantors := h.guarantors
	h.mu.RUnlock()

	if guarantors == nil {
		return errors.New("no guarantors set")
	}

	remoteResultCh := make(chan guaranteeResponse, len(guarantors))
	localResultCh := make(chan localReportResult, 1)

	bundleBytes, err := jam.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("failed to marshal WP bundle: %w", err)
	}

	// share work package with guarantors
	var wg sync.WaitGroup
	for _, g := range guarantors {
		wg.Add(1)
		go h.shareWorkPackage(ctx, &wg, g, remoteResultCh, segments, coreIndex, bundleBytes)
	}

	// start local refinement in parallel
	wg.Add(1)
	go func() {
		defer wg.Done()
		workReport, err := results.ProduceWorkReport(h.refine, h.state.Services, authOutput, coreIndex, bundle, buildSegmentRootLookup(segments))
		if err != nil {
			localResultCh <- localReportResult{err: err}
			log.Printf("local refinement failed: %v", err)
			return
		}

		log.Println("local refinement finished")

		localResultCh <- localReportResult{report: workReport}
	}()

	localResult, remoteResponses, err := h.collectReports(ctx, remoteResultCh, localResultCh)
	if err != nil {
		return err
	}

	wg.Wait()

	h.processWorkReports(ctx, localResult, remoteResponses)

	return nil
}

// CE-134:
// Share the work-package bundle with other guarantors and collect signed responses.
//
// Guarantor -> Guarantor
//
// --> Core Index ++ Segments-Root Mappings
// --> Work-Package Bundle
// --> FIN
// <-- Work-Report Hash ++ Ed25519 Signature
// <-- FIN
func (h *WorkReportGuarantor) shareWorkPackage(
	ctx context.Context,
	wg *sync.WaitGroup,
	g *peer.Peer,
	guaranteeCh chan<- guaranteeResponse,
	segments []SegmentRootMapping,
	coreIndex uint16,
	bundleBytes []byte,
) {
	defer wg.Done()

	if g.ValidatorIndex == nil {
		guaranteeCh <- guaranteeResponse{
			err: fmt.Errorf("missing validator index for peer %v", g),
		}
		log.Printf("Skipping peer with unknown validator index: %v", g)
		return
	}
	validatorIndex := *g.ValidatorIndex

	response, err := h.sendWorkPackage(ctx, g, coreIndex, segments, bundleBytes)
	if err != nil {
		guaranteeCh <- guaranteeResponse{err: err}
		log.Printf("Failed to share WP with peer %v: %v", validatorIndex, err)
		return
	}

	log.Printf("Received work-report hash and signature from peer %v:\n- Hash: %x\n- Signature: %x",
		validatorIndex, response.WorkReportHash, response.Signature)

	guaranteeCh <- guaranteeResponse{
		workReportHash: response.WorkReportHash,
		validatorIndex: validatorIndex,
		signature:      response.Signature,
	}
}

// Collect local refinement result and responses from other guarantors (via channel).
// Filter only matching hashes, add local signature, and construct the full Guarantee.
// If enough signatures are collected (>= 2) after the timeout (maxWaitTimeForThirdGuarantor), proceed to distribute it (CE-135).
func (h *WorkReportGuarantor) processWorkReports(
	ctx context.Context,
	localResult localReportResult,
	remoteResponses []guaranteeResponse,
) {

	if localResult.err != nil {
		log.Println("aborting guarantee distribution: local refinement failed")

		return
	}

	wrHash, err := localResult.report.Hash()
	if err != nil {
		log.Printf("failed to compute work report hash: %v", err)
		return
	}

	var creds []block.CredentialSignature
	for _, r := range remoteResponses {
		if r.workReportHash != wrHash {
			log.Printf("ignoring mismatching work report hash from validator %d local=%x, remote=%x",
				r.validatorIndex, wrHash, r.workReportHash)
			continue
		}
		creds = append(creds, block.CredentialSignature{ValidatorIndex: r.validatorIndex, Signature: r.signature})
	}

	localSig := ed25519.Sign(h.privateKey, wrHash[:])
	creds = append(creds, block.CredentialSignature{ValidatorIndex: h.validatorIndex, Signature: crypto.Ed25519Signature(localSig)})

	log.Printf("local work-report hash and signature:\n- Hash: %x\n- signature: %x", wrHash, localSig)

	if len(creds) < minSignaturesRequiredToGuarantee {
		log.Printf("not enough credentials to guarantee work report")
		return
	}

	// sort by validator index (required by 11.25)
	sort.Slice(creds, func(i, j int) bool {
		return creds[i].ValidatorIndex < creds[j].ValidatorIndex
	})

	log.Printf("total number of credentials gathered to guarantee work report: %d", len(creds))

	guarantee := block.Guarantee{
		WorkReport:  localResult.report,
		Timeslot:    jamtime.CurrentTimeslot(),
		Credentials: creds,
	}

	err = h.distributeGuaranteedWorkReport(ctx, guarantee)
	if err != nil {
		log.Printf("failed to distribute guarantee work report: %v", err)
	}
}

// collectReports collects valid work-report refinements (local and remote) following CE-134/135.
//
// - Wait for at least two successful refinement responses (local or remote), without any timeout
// - Once two valid results are received, start a timer for a possible third response
// - If a third valid result arrives before the timer expires, return immediately
// - If the timer expires first, proceed with the two collected results
// - Remote failures are tolerated and skipped
// - Local refinement failure is tolerated as long as enough remote signatures are collected
// - Context cancellation causes an immediate exit
func (h *WorkReportGuarantor) collectReports(
	ctx context.Context,
	remoteCh <-chan guaranteeResponse,
	localCh <-chan localReportResult,
) (localReportResult, []guaranteeResponse, error) {
	var remoteResults []guaranteeResponse
	var localRes localReportResult
	var totalValidResults uint
	var timer *time.Timer

	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case r := <-remoteCh:
			if r.err != nil {
				log.Printf("remote refinment failed: %v", r.err)
				continue
			}
			totalValidResults++
			remoteResults = append(remoteResults, r)

		case l := <-localCh:
			localRes = l
			if l.err != nil {
				log.Printf("local refinment failed: %v", l.err)
				continue
			}
			totalValidResults++

		case <-ctx.Done():
			return localRes, remoteResults, ctx.Err()

		case <-safeTimerC(timer):
			// Timer expired
			return localRes, remoteResults, nil
		}

		if totalValidResults == minSignaturesRequiredToGuarantee {
			// First 2 valid results already received — start the timer
			timer = time.NewTimer(maxWaitTimeForThirdGuarantor)
		}

		if totalValidResults == maxSignaturesRequiredToGuarantee {
			// If we already have all signatures before timer fires, return early
			return localRes, remoteResults, nil
		}
	}
}

// safeTimerC safely returns a channel to select on only if timer is active
func safeTimerC(t *time.Timer) <-chan time.Time {
	if t != nil {
		return t.C
	}
	// blocked forever if no timer yet
	return make(<-chan time.Time)
}

// TODO: Build segment-root mappings based on historical data
func (h *WorkReportGuarantor) buildSegmentRootMapping(pkg work.PackageBundle) []SegmentRootMapping {
	return []SegmentRootMapping{}
}

// sendWorkPackage sends 2 messages to another guarantor and closes the stream:
//
// --> Core Index ++ Segments-Root Mappings
//   - Informs the receiving guarantor which core this work-package belongs to.
//   - Provides the mapping between imported segment hashes and their Merkle roots.
//   - This mapping is used during refinement to validate imported segments.
//
// --> Work-Package Bundle
//   - Contains the actual work-package bundle and any associated extrinsics.
//
// --> FIN
//   - Closes the stream after sending both messages. The response is expected before finalization.
//
// The bundle should include imported data segments and their justifications as well as the work-package and extrinsic data.
func (h *WorkReportGuarantor) sendWorkPackage(
	ctx context.Context,
	g *peer.Peer,
	coreIndex uint16,
	imported []SegmentRootMapping,
	bundleBytes []byte,
) (*workPackageSharingResponse, error) {
	msg1, err := jam.Marshal(struct {
		CoreIndex          uint16
		SegmentRootMapping []SegmentRootMapping
	}{
		CoreIndex:          coreIndex,
		SegmentRootMapping: imported,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal first message: %w", err)
	}

	stream, err := g.ProtoConn.OpenStream(ctx, protocol.StreamKindWorkPackageShare)
	if err != nil {
		return nil, fmt.Errorf("Failed to open stream: %v", err)
	}

	// 1st: “CoreIndex ++ Segments-Root Mappings”
	if err = WriteMessageWithContext(ctx, stream, msg1); err != nil {
		return nil, fmt.Errorf("failed to send first message: %w", err)
	}

	// 2nd: “Work-Package Bundle”
	if err = WriteMessageWithContext(ctx, stream, bundleBytes); err != nil {
		return nil, fmt.Errorf("failed to send WP bundle: %w", err)
	}

	// Handle CE-134 response from the receiving guarantor
	msg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if err := stream.Close(); err != nil {
		return nil, fmt.Errorf("failed to close stream: %w", err)
	}

	var response workPackageSharingResponse
	if err := jam.Unmarshal(msg.Content, &response); err != nil {
		return nil, fmt.Errorf("failed to decode CE-134 response: %w", err)
	}

	return &response, nil
}

// CE-135:
// distribute guarantee to all current validators.
// If it’s the last core rotation in the epoch, also send it to next epoch validators.
//
// Guaranteed Work-Report = Work-Report ++ Slot ++ len++[Validator Index ++ Ed25519 Signature] (As in GP)
//
// Guarantor -> Validator
//
// --> Guaranteed Work-Report
// --> FIN
// <-- FIN
func (h *WorkReportGuarantor) distributeGuaranteedWorkReport(
	ctx context.Context,
	guarantee block.Guarantee,
) error {
	data, err := jam.Marshal(guarantee)
	if err != nil {
		return fmt.Errorf("failed to marshal guarantee: %w", err)
	}

	wg := &sync.WaitGroup{}

	for _, v := range h.recipientValidators() {
		wg.Add(1)
		go func(v *peer.Peer) {
			defer wg.Done()

			var valIndex uint16
			if v.ValidatorIndex != nil {
				valIndex = *v.ValidatorIndex
			}

			stream, err := v.ProtoConn.OpenStream(ctx, protocol.StreamKindWorkReportDist)
			if err != nil {
				log.Printf("failed to open stream to validator %v: %v", valIndex, err)
				return
			}

			if err := WriteMessageWithContext(ctx, stream, data); err != nil {
				log.Printf("failed to send guarantee to validator %v: %v", valIndex, err)
				return
			}

			err = stream.Close()
			if err != nil {
				log.Printf("failed to close stream to validator %v: %v", valIndex, err)
			}

			log.Printf("Sent guarantee to validator %v", valIndex)
		}(v)
	}

	wg.Wait()

	return nil
}

// Determine the correct set of validators to distribute work report
func (h *WorkReportGuarantor) recipientValidators() []*peer.Peer {
	var cur, next []*peer.Peer

	cur = h.convertValidatorsDataToPeers(h.state.ValidatorState.CurrentValidators)
	if !h.state.TimeslotIndex.IsLastCoreRotation() {

		return cur
	}

	// During the last core rotation of an epoch, work-reports must be distributed to both:
	// 1) all currently assigned validators and
	// 2) all validators assigned for the upcoming epoch
	next = h.convertValidatorsDataToPeers(h.state.ValidatorState.SafroleState.NextValidators)

	return mergePeers(cur, next)
}

// Transforms safrole.ValidatorsData to []*peer.Peer
func (h *WorkReportGuarantor) convertValidatorsDataToPeers(data safrole.ValidatorsData) []*peer.Peer {
	var peers []*peer.Peer
	for _, v := range data {
		if v == nil {
			continue
		}
		if p := h.peerSet.GetByEd25519Key(v.Ed25519); p != nil {
			peers = append(peers, p)
		}
	}
	return peers
}

// mergePeers returns the union of two peer slices ensuring no duplicate ValidatorIndex entries
func mergePeers(a, b []*peer.Peer) []*peer.Peer {
	exists := make(map[uint16]struct{})
	var merged []*peer.Peer

	for _, p := range a {
		merged = append(merged, p)
		if p.ValidatorIndex != nil {
			exists[*p.ValidatorIndex] = struct{}{}
		}
	}
	for _, p := range b {
		if p.ValidatorIndex != nil {
			if _, ok := exists[*p.ValidatorIndex]; !ok {
				merged = append(merged, p)
			}
		}
	}
	return merged
}
