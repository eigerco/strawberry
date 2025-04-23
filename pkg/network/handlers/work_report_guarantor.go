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

	"github.com/quic-go/quic-go"

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
	minSignaturesRequiredForGuarantee = 2
	maxWaitTime                       = time.Second * 2
)

// WorkReportGuarantor handles CE-134 and CE-135:
// - CE-134: share a work-package with other guarantors, run local refinement, collect wr hashes signatures
// - CE-135: if enough signatures are gathered, broadcast the guaranteed work-report to validators
type WorkReportGuarantor struct {
	validatorIndex uint16
	privateKey     ed25519.PrivateKey
	guarantors     []*peer.Peer
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
	WorkReportHash crypto.Hash
	ValidatorIndex uint16
	Signature      crypto.Ed25519Signature
	Err            error
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

	if h.guarantors == nil {
		return errors.New("no guarantors set")
	}

	remoteResultCh := make(chan guaranteeResponse, len(h.guarantors))
	localResultCh := make(chan localReportResult, 1)

	// share work package with guarantors
	var wg sync.WaitGroup
	for _, g := range h.guarantors {
		wg.Add(1)
		go h.shareWorkPackage(ctx, &wg, g, remoteResultCh, segments, coreIndex, bundle)
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

		localResultCh <- localReportResult{report: workReport}
	}()

	h.processWorkReports(ctx, localResultCh, remoteResultCh)

	wg.Wait()

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
	bundle work.PackageBundle,
) {
	defer wg.Done()

	stream, err := g.ProtoConn.OpenStream(ctx, protocol.StreamKindWorkPackageShare)
	if err != nil {
		guaranteeCh <- guaranteeResponse{Err: err}
		log.Printf("Failed to open stream to peer %v: %v", g, err)
		return
	}

	err = h.sendWorkPackage(ctx, stream, coreIndex, segments, bundle)
	if err != nil {
		guaranteeCh <- guaranteeResponse{Err: err}
		log.Printf("Failed to share WP with peer %v: %v", g, err)
	}

	// Handle CE-134 response from the receiving guarantor
	msg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		guaranteeCh <- guaranteeResponse{Err: err}
		log.Printf("Failed to read response from peer %v: %v", g, err)
		return
	}

	var response struct {
		WorkReportHash crypto.Hash
		Signature      crypto.Ed25519Signature
	}
	if err := jam.Unmarshal(msg.Content, &response); err != nil {
		guaranteeCh <- guaranteeResponse{Err: err}
		log.Printf("Failed to decode CE-134 response from peer %v: %v", g.ValidatorIndex, err)
		return
	}

	var validatorIndex uint16
	if g.ValidatorIndex != nil {
		validatorIndex = *g.ValidatorIndex
	}

	log.Printf("Received work-report hash and signature from peer %v:\n- Hash: %x\n- Signature: %x",
		validatorIndex, response.WorkReportHash, response.Signature)

	guaranteeCh <- guaranteeResponse{
		WorkReportHash: response.WorkReportHash,
		ValidatorIndex: validatorIndex,
		Signature:      response.Signature,
	}
}

// Collect local refinement result and responses from other guarantors (via channel).
// Filter only matching hashes, add local signature, and construct the full Guarantee.
// If enough signatures are collected (>= 2) after the timeout (maxWaitTime), proceed to distribute it (CE-135).
func (h *WorkReportGuarantor) processWorkReports(
	ctx context.Context,
	localResultCh <-chan localReportResult,
	guaranteeRespCh <-chan guaranteeResponse,
) {
	localResult, remoteResponses, err := h.collectReports(ctx, guaranteeRespCh, localResultCh)
	if err != nil {
		log.Printf("local refinement failed: %v", err)

		return
	}
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
		if r.WorkReportHash != wrHash {
			log.Printf("ignoring mismatching work report hash from validator %d local=%x, remote=%x",
				r.ValidatorIndex, wrHash, r.WorkReportHash)
			continue
		}
		creds = append(creds, block.CredentialSignature{ValidatorIndex: r.ValidatorIndex, Signature: r.Signature})
	}

	localSig := ed25519.Sign(h.privateKey, wrHash[:])
	creds = append(creds, block.CredentialSignature{ValidatorIndex: h.validatorIndex, Signature: crypto.Ed25519Signature(localSig)})

	log.Printf("local work-report hash and signature:\n- Hash: %x\n- Signature: %x", wrHash, localSig)

	if len(creds) < minSignaturesRequiredForGuarantee {
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

// Wait up to 2 seconds for:
// - local refinement result
// - enough remote signed responses (2 total)
// Return when both conditions are met or timeout.
func (h *WorkReportGuarantor) collectReports(
	ctx context.Context,
	remoteCh <-chan guaranteeResponse,
	localCh <-chan localReportResult,
) (localReportResult, []guaranteeResponse, error) {
	var remoteResults []guaranteeResponse
	var localRes localReportResult

	localReceived := false

	ctx, cancel := context.WithTimeout(ctx, maxWaitTime)
	defer cancel()

	for {
		select {
		case l := <-localCh:
			localRes = l
			if l.err != nil {
				return l, remoteResults, l.err
			}
			localReceived = true

			if len(remoteResults) == minSignaturesRequiredForGuarantee {
				return localRes, remoteResults, nil
			}
		case r := <-remoteCh:
			if r.Err != nil {
				log.Printf("Remote response error: %v", r.Err)
				continue
			}
			remoteResults = append(remoteResults, r)
			if localReceived && len(remoteResults) == minSignaturesRequiredForGuarantee {
				return localRes, remoteResults, nil
			}
		case <-ctx.Done():
			return localRes, remoteResults, nil
		}
	}
}

// TODO: Build segment-root mappings based on historical data
func (h *WorkReportGuarantor) buildSegmentRootMapping(pkg work.PackageBundle) []SegmentRootMapping {
	return []SegmentRootMapping{}
}

// SendWorkPackage transmits the work-package bundle to a specific guarantor.
func (h *WorkReportGuarantor) sendWorkPackage(
	ctx context.Context,
	stream quic.Stream,
	coreIndex uint16,
	imported []SegmentRootMapping,
	bundle work.PackageBundle,
) error {
	msg1, err := jam.Marshal(struct {
		CoreIndex          uint16
		SegmentRootMapping []SegmentRootMapping
	}{
		CoreIndex:          coreIndex,
		SegmentRootMapping: imported,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal first message: %w", err)
	}

	// 1st: “CoreIndex ++ Segments-Root Mappings”
	if err = WriteMessageWithContext(ctx, stream, msg1); err != nil {
		return fmt.Errorf("failed to send first message: %w", err)
	}

	// 2nd: “Work-Package Bundle”
	bundleBytes, err := jam.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("failed to marshal WP bundle: %w", err)
	}
	if err = WriteMessageWithContext(ctx, stream, bundleBytes); err != nil {
		return fmt.Errorf("failed to send WP bundle: %w", err)
	}

	if err := stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}

	return nil
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
