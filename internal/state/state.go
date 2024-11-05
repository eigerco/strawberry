package state

import (
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/validator"
)

// State represents the complete state of the system
type State struct {
	Services                 service.ServiceState               // Service accounts mapping (δ)
	PrivilegedServices       service.PrivilegedServices         // Privileged services (𝝌): services which hold some privileged status.
	ValidatorState           validator.ValidatorState           // Validator related state (κ, λ, ι, γ)
	EntropyPool              EntropyPool                        // On-chain Entropy pool (η): pool of entropy accumulators (also called randomness accumulators).
	CoreAuthorizersPool      CoreAuthorizersPool                // Core authorizers pool (α): authorization requirement which work done on that core must satisfy at the time of being reported on-chain.
	PendingAuthorizersQueues PendingAuthorizersQueues           // Pending Core authorizers queue (φ): the queue which fills core authorizations.
	CoreAssignments          CoreAssignments                    // Core assignments (ρ): each of the cores’ currently assigned report, the availability of whose work-package must yet be assured by a super-majority of validators. This is what each core is up to right now, tracks the work-reports which have been reported but not yet accumulated, the identities of the guarantors who reported them and the time at which it was reported.
	RecentBlocks             []BlockState                       // Block-related state (β): details of the most recent blocks. TODO: Maximum length: MaxRecentBlocks
	TimeslotIndex            jamtime.Timeslot                   // Time-related state (τ): the most recent block’s slot index.
	PastJudgements           Judgements                         // PastJudgements (ψ) - past judgements on work-reports and validators.
	ValidatorStatistics      validator.ValidatorStatisticsState // Validator statistics (π) - The activity statistics for the validators.
	AccumulationQueue        AccumulationQueue                  // Accumulation Queue (ϑ) - ready (i.e. available and/or audited) but not-yet-accumulated work-reports. Each of these were made available at most one epoch ago but have or had unfulfilled dependencies.
	AccumulationHistory      AccumulationHistory                // Accumulation history (ξ) - history of what has been accumulated for an epoch worth of work-reports. Mapping of work-package hash to segment-root.
}
