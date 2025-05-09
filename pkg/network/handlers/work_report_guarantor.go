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
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/internal/work/results"
	"github.com/eigerco/strawberry/pkg/network/peer"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	// Total number of expected signed responses (local + 2 remote) to guarantee work report
	maxExpectedResults = 3
	// We need at least this amount of signatures to guarantee work report
	minSignaturesRequiredToGuarantee = 2
	// The third guarantor should be given a reasonable amount of time (e.g. two seconds) to produce
	// an additional signature before the guaranteed work-report is distrubuted
	maxWaitTimeForThirdGuarantor = time.Second * 2
	// maxWaitTimeForCollectingReports defines the maximum wait time to collect all work reports
	maxWaitTimeForCollectingReports = time.Second * 5
)

// WorkReportGuarantor handles CE-134 and CE-135:
// - CE-134: share a work-package with other guarantors, run local refinement, collect wr hashes signatures
// - CE-135: if enough signatures are gathered, broadcast the guaranteed work-report to validators
type WorkReportGuarantor struct {
	validatorIndex              uint16
	privateKey                  ed25519.PrivateKey
	guarantors                  []*peer.Peer
	mu                          sync.RWMutex
	auth                        authorization.AuthPVMInvoker
	refine                      refine.RefinePVMInvoker
	state                       *state.State
	peerSet                     *peer.PeerSet
	store                       *store.WorkReport
	workReportRequester         *WorkReportRequester
	workPackageSharingRequester *WorkPackageSharingRequester
}

// SegmentRootMapping It maps a work-package hash (h⊞) to the actual segment root (H).
type SegmentRootMapping struct {
	WorkPackageHash crypto.Hash // h⊞
	SegmentRoot     crypto.Hash // H
}

type guaranteeResponse struct {
	workReportHash crypto.Hash
	validatorIndex uint16
	ed25519Key     ed25519.PublicKey
	signature      crypto.Ed25519Signature
	err            error
}

type localReportResult struct {
	report         block.WorkReport
	workReportHash crypto.Hash
	signature      crypto.Ed25519Signature
	err            error
}

// signedWorkReport represents a guarantor signature over a work-report hash.
// - If Report is non-nil, it means this was the locally computed work-report and contains the full body.
// - Remote responses only contain hash + signature.
type signedWorkReport struct {
	WorkReportHash crypto.Hash
	Signature      crypto.Ed25519Signature
	ValidatorIndex uint16
	Report         *block.WorkReport // Only set if local and successful
}

func NewWorkReportGuarantor(
	validatorIndex uint16,
	privateKey ed25519.PrivateKey,
	auth authorization.AuthPVMInvoker,
	refine refine.RefinePVMInvoker,
	state state.State,
	peerSet *peer.PeerSet,
	store *store.WorkReport,
	requester *WorkReportRequester,
	workPackageSharingRequester *WorkPackageSharingRequester,
) *WorkReportGuarantor {
	return &WorkReportGuarantor{
		validatorIndex:              validatorIndex,
		privateKey:                  privateKey,
		auth:                        auth,
		refine:                      refine,
		state:                       &state,
		peerSet:                     peerSet,
		store:                       store,
		workReportRequester:         requester,
		workPackageSharingRequester: workPackageSharingRequester,
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

	if len(guarantors) == 0 {
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
	go h.startLocalRefinement(&wg, coreIndex, authOutput, bundle, segments, localResultCh)

	groupedWorkReports, err := h.collectSignedReports(ctx, remoteResultCh, localResultCh)
	if err != nil {
		return fmt.Errorf("failed to collect signed work reports: %w", err)
	}

	err = h.processWorkReports(ctx, groupedWorkReports)
	if err != nil {
		return fmt.Errorf("failed to process work reports: %w", err)
	}

	wg.Wait()

	return nil
}

// startLocalRefinement performs local refinement of a work-package in a separate goroutine.
//
// If successful, it computes the hash of the work-report and signs it
// The result (including a report, hash, and signature) is sent to the localResultCh channel
// If refinement fails or hashing fails, an error is sent instead
func (h *WorkReportGuarantor) startLocalRefinement(
	wg *sync.WaitGroup,
	coreIndex uint16,
	authOutput []byte,
	bundle work.PackageBundle,
	segments []SegmentRootMapping,
	localResultCh chan<- localReportResult,
) {
	defer wg.Done()

	workReport, err := results.ProduceWorkReport(h.refine, h.state.Services, authOutput, coreIndex, bundle, buildSegmentRootLookup(segments))
	if err != nil {
		localResultCh <- localReportResult{err: err}
		log.Printf("local refinement failed: %v", err)
		return
	}

	log.Println("local refinement finished")

	wrHash, err := workReport.Hash()
	if err != nil {
		localResultCh <- localReportResult{err: err}
		log.Printf("failed to compute work report hash: %v", err)
		return
	}

	localSig := ed25519.Sign(h.privateKey, wrHash[:])

	log.Printf("local work-report hash and signature:\n- Hash: %x\n- Signature: %x", wrHash, localSig)

	localResultCh <- localReportResult{
		report:         workReport,
		workReportHash: wrHash,
		signature:      crypto.Ed25519Signature(localSig),
	}
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

	if !g.IsValidator() {
		guaranteeCh <- guaranteeResponse{
			err: fmt.Errorf("missing validator index for peer %v", g),
		}
		log.Printf("Skipping peer with unknown validator index: %v", g)
		return
	}
	validatorIndex := *g.ValidatorIndex

	response, err := h.workPackageSharingRequester.SendRequest(ctx, g, coreIndex, segments, bundleBytes)
	if err != nil {
		guaranteeCh <- guaranteeResponse{err: err}
		log.Printf("Failed to complete work package exchange with peer %v: %v", validatorIndex, err)
		return
	}

	log.Printf("Received work-report hash and signature from peer %v:\n- Hash: %x\n- Signature: %x",
		validatorIndex, response.WorkReportHash, response.Signature)

	guaranteeCh <- guaranteeResponse{
		workReportHash: response.WorkReportHash,
		validatorIndex: validatorIndex,
		ed25519Key:     g.Ed25519Key,
		signature:      response.Signature,
	}
}

// processWorkReports constructs and distributes a block.Guarantee from a set of signed work-reports
//
// - Groups signatures by work-report hash and selects the first group with at least 2 signatures
// - If local refinement fails, remote signatures are still used, but the work-report body must eventually be fetched separately from a peer
// - Credentials (signatures) are sorted by validator index as required by the protocol
// - If no quorum group is found, returns an error without broadcasting anything
// - Credentials are sorted by validator index before constructing the guarantee.
func (h *WorkReportGuarantor) processWorkReports(
	ctx context.Context,
	groups map[crypto.Hash][]signedWorkReport,
) error {
	var winningGroup []signedWorkReport
	for _, sigs := range groups {
		if len(sigs) >= minSignaturesRequiredToGuarantee {
			winningGroup = sigs
			break
		}
	}

	if len(winningGroup) < minSignaturesRequiredToGuarantee {
		return fmt.Errorf("not enough matching signatures for any work-report hash")
	}

	var report *block.WorkReport

	var creds []block.CredentialSignature
	for _, s := range winningGroup {
		creds = append(creds, block.CredentialSignature{
			ValidatorIndex: s.ValidatorIndex,
			Signature:      s.Signature,
		})
		if s.Report != nil {
			// The full report is only available from the local refinement
			// remote responses only provide a hash + signature
			// If local refinement failed or wasn't available, s.Report will be nil.
			report = s.Report
		}
	}

	if report == nil {
		log.Println("local refinement failed or ignored, fetching full work report from remote peer")

		fetched, err := h.fetchWorkReportByHash(ctx, winningGroup[0].WorkReportHash)
		if err != nil {
			return err
		}
		report = fetched
	}

	// at this point we have a valid work-report and we should store it
	err := h.store.PutWorkReport(*report)
	if err != nil {
		log.Printf("failed to store work report: %v", err)
	}

	// sort by validator index (required by 11.25)
	sort.Slice(creds, func(i, j int) bool {
		return creds[i].ValidatorIndex < creds[j].ValidatorIndex
	})

	log.Printf("total number of credentials gathered to guarantee work report: %d", len(creds))

	guarantee := block.Guarantee{
		WorkReport:  *report,
		Timeslot:    jamtime.CurrentTimeslot(),
		Credentials: creds,
	}

	return h.distributeGuaranteedWorkReport(ctx, guarantee)
}

// fetchWorkReportByHash attempts to retrieve a full work-report from any available co-guarantor.
// It iterates over the known guarantors and sends a CE-136 request using the provided hash.
func (h *WorkReportGuarantor) fetchWorkReportByHash(ctx context.Context, hash crypto.Hash) (*block.WorkReport, error) {
	for _, p := range h.guarantors {
		stream, err := p.ProtoConn.OpenStream(ctx, protocol.StreamKindWorkReportRequest)
		if err != nil {
			log.Printf("failed to open stream to validator: %v", err)
			continue
		}
		fetched, err := h.workReportRequester.RequestWorkReport(ctx, stream, hash)
		if err != nil {
			log.Printf("failed to fetch work report from validator : %v", err)
			continue
		}
		return fetched, nil
	}

	return nil, fmt.Errorf("failed to retrieve work report")
}

// collectSignedReports gathers signed work-report hashes from both local refinement and remote guarantors.
//
//   - It waits for at least two successful responses (local or remote) that agree on the same hash
//   - Remote responses are accepted only if their Ed25519 signatures are valid.
//   - Once two matching hashes are received, start a timer for a possible third response
//   - A general timeout of (maxWaitTimeForCollectingReports) is applied to the entire collection process
//   - All signatures are grouped by hash to identify the largest group with matching work-report hashes
//   - Local failures are tolerated as long as enough remote responses are collected
//   - The function never returns an error for “no quorum” it simply returns the collected signatures
//     The caller must inspect the slice and decide whether a quorum exists
//   - Context cancellation causes an immediate exit
func (h *WorkReportGuarantor) collectSignedReports(
	ctx context.Context,
	remoteCh <-chan guaranteeResponse,
	localCh <-chan localReportResult,
) (map[crypto.Hash][]signedWorkReport, error) {
	var timer *time.Timer
	var totalResults uint
	var grouped = make(map[crypto.Hash][]signedWorkReport)
	var quorumReached bool

	ctx, cancel := context.WithTimeout(ctx, maxWaitTimeForCollectingReports)
	defer cancel()

	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case r := <-remoteCh:
			totalResults++
			if r.err != nil {
				log.Printf("remote refinement failed: %v", r.err)
				continue
			}

			if !ed25519.Verify(r.ed25519Key, r.workReportHash[:], r.signature[:]) {
				log.Printf("discarding invalid signature from guarantor with index %d", r.validatorIndex)
				continue
			}

			grouped[r.workReportHash] = append(grouped[r.workReportHash], signedWorkReport{
				ValidatorIndex: r.validatorIndex,
				Signature:      r.signature,
				WorkReportHash: r.workReportHash,
			})

		case l := <-localCh:
			totalResults++
			if l.err != nil {
				log.Printf("local refinement failed: %v", l.err)
				continue
			}

			grouped[l.workReportHash] = append(grouped[l.workReportHash], signedWorkReport{
				ValidatorIndex: h.validatorIndex,
				Signature:      l.signature,
				WorkReportHash: l.workReportHash,
				Report:         &l.report,
			})
		case <-ctx.Done():
			return grouped, ctx.Err()

		case <-safeTimerC(timer):
			log.Println("timer expired")
			// Timer expired
			return grouped, nil
		}

		// if all results arrived, return early
		if totalResults == maxExpectedResults {
			return grouped, nil
		}

		// Check if quorum has been reached for any hash to start the timer
		if timer == nil && !quorumReached {
			for _, signs := range grouped {
				if len(signs) == minSignaturesRequiredToGuarantee {
					log.Println("quorum reached, starting timer for optional third signature")
					timer = time.NewTimer(maxWaitTimeForThirdGuarantor)
					quorumReached = true
					break
				}
			}
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
			if v.IsValidator() {
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

	return peer.MergeValidators(cur, next)
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
