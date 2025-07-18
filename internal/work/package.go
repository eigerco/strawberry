package work

import (
	"fmt"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/service"
)

// Package represents P (14.2 v0.5.4)
type Package struct {
	AuthorizationToken []byte                  // j ∈ B
	AuthorizerService  uint32                  // h ∈ N_S
	AuthCodeHash       crypto.Hash             // u ∈ H
	Parameterization   []byte                  // p ∈ B
	Context            block.RefinementContext // x ∈ X
	WorkItems          []Item                  // w ∈ ⟦I⟧
}

// ValidateLimits (14.4 v0.6.3)
func (wp *Package) ValidateLimits() error {
	if len(wp.WorkItems) > MaxNumberOfItems {
		return fmt.Errorf("exceeded maximum work items: %d/%d", len(wp.WorkItems), MaxNumberOfItems)
	}

	var totalExported, totalImported, totalExtrinsics uint16
	for _, w := range wp.WorkItems {
		totalExported += w.ExportedSegments
		totalImported += uint16(len(w.ImportedSegments))
		totalExtrinsics += uint16(len(w.Extrinsics))
	}

	if totalExported > MaxNumberOfExports {
		return fmt.Errorf("exceeded maximum exported segments: %d/%d", totalExported, MaxNumberOfExports)
	}
	if totalImported > MaxNumberOfImports {
		return fmt.Errorf("exceeded maximum imported segments: %d/%d", totalImported, MaxNumberOfImports)
	}

	if totalExtrinsics > MaxNumberOfExtrinsics {
		return fmt.Errorf("exceeded maximum extrinsics: %d/%d", totalExtrinsics, MaxNumberOfExtrinsics)
	}

	return nil
}

// ValidateSize (14.5 v0.5.4)
func (wp *Package) ValidateSize() error {
	totalSize := uint64(len(wp.AuthorizationToken)) + uint64(len(wp.Parameterization))

	for _, w := range wp.WorkItems {
		totalSize += w.Size()
	}

	if totalSize > MaxSizeOfEncodedWorkPackage {
		return fmt.Errorf("work-package size exceeds limit: %d/%d bytes", totalSize, MaxSizeOfEncodedWorkPackage)
	}

	return nil
}

// ValidateGas (14.7 v0.5.4)
func (wp *Package) ValidateGas() error {
	var totalAccumulate, totalRefine uint64
	for _, w := range wp.WorkItems {
		totalAccumulate += w.GasLimitAccumulate
		totalRefine += w.GasLimitRefine
	}

	if totalAccumulate >= common.MaxAllocatedGasAccumulation {
		return fmt.Errorf("accumulation gas exceeds limit GA: %d/%d", totalAccumulate, common.MaxAllocatedGasAccumulation)
	}
	if totalRefine >= MaxAllocatedGasRefine {
		return fmt.Errorf("refine gas exceeds limit GR: %d/%d", totalRefine, MaxAllocatedGasRefine)
	}

	return nil
}

// ComputeAuthorizerHashes (14.9 v0.5.4)
func (wp *Package) ComputeAuthorizerHashes(
	serviceState service.ServiceState,
) (authorizationCode []byte, impliedAuthorizerHash crypto.Hash, err error) {
	authorizationCode, err = wp.GetAuthorizationCode(serviceState)
	if err != nil {
		return nil, crypto.Hash{}, fmt.Errorf("failed to get authorization code: %w", err)
	}

	// pa = H(pc || p.p)
	impliedAuthorizerHash = crypto.HashData(append(authorizationCode, wp.Parameterization...))

	return authorizationCode, impliedAuthorizerHash, nil
}

// GetAuthorizationCode E(↕pm, pc) = Λ(δ[p.h], (p.x)^t, p.u) (14.9 v0.6.3)
func (wp *Package) GetAuthorizationCode(serviceState service.ServiceState) ([]byte, error) {
	// Retrieve the service account by authorizer service index p.h
	sa, exists := serviceState[block.ServiceId(wp.AuthorizerService)]
	if !exists {
		return nil, fmt.Errorf("service %d not found in service state", wp.AuthorizerService)
	}

	// E(↕pm, pc) = Λ(δ[p.h], (p.x)^t, p.u)
	authorizationCode := sa.LookupPreimage(block.ServiceId(wp.AuthorizerService), wp.Context.LookupAnchor.Timeslot, wp.AuthCodeHash)
	if authorizationCode == nil {
		return nil, fmt.Errorf("unable to find preimage for AuthCodeHash at given timeslot")
	}

	return authorizationCode, nil
}
