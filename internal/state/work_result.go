package state

import "github.com/eigerco/strawberry/internal/crypto"

// ErrorType represents the possible errors in the set J
type ErrorType int

const (
	NoError               ErrorType = iota // Represents no error, successful execution
	OutOfGas                               // Out-of-gas error
	UnexpectedTermination                  // Unexpected program termination.
	CodeNotAvailable                       // The service’s code was not available for lookup in state at the posterior state of the lookup-anchor block.
	CodeTooLarge                           // The code was available but was beyond the maximum size allowed S.
)

// WorkResult is the data conduit by which services’ states may be altered through the computation done within a work-package.
type WorkResult struct {
	ServiceId              ServiceId   // Service ID (s) - The index of the service whose state is to be altered and thus whose refine code was already executed.
	ServiceHashCode        crypto.Hash // Hash of the service code (c) - The hash of the code of the service at the time of being reported.
	PayloadHash            crypto.Hash // Hash of the payload (l) - The hash of the payload within the work item which was executed in the refine stage to give this result. Provided to the accumulation logic of the service later on.
	GasPrioritizationRatio uint64      // Gas prioritization ratio (g) - used when determining how much gas should be allocated to execute of this item’s accumulate. TODO: Is uint64 correct here?
	Output                 *[]byte     // Output of the work result (o) - An optional octet sequence in case it was successful.
	Error                  ErrorType   // Error type in case of failure.
}

// IsSuccessful checks if the work result is successful
func (wr WorkResult) IsSuccessful() bool {
	return wr.Error == NoError
}

// NewSuccessfulWorkResult creates a new successful WorkResult
func NewSuccessfulWorkResult(serviceId ServiceId, serviceHashCode, payloadHash crypto.Hash, gasPrioritizationRatio uint64, output []byte) WorkResult {
	return WorkResult{
		ServiceId:              serviceId,
		ServiceHashCode:        serviceHashCode,
		PayloadHash:            payloadHash,
		GasPrioritizationRatio: gasPrioritizationRatio,
		Output:                 &output,
		Error:                  NoError,
	}
}

// NewErrorWorkResult creates a new error WorkResult
func NewErrorWorkResult(serviceId ServiceId, serviceHashCode, payloadHash crypto.Hash, gasPrioritizationRatio uint64, errorType ErrorType) WorkResult {
	return WorkResult{
		ServiceId:              serviceId,
		ServiceHashCode:        serviceHashCode,
		PayloadHash:            payloadHash,
		GasPrioritizationRatio: gasPrioritizationRatio,
		Output:                 nil,
		Error:                  errorType,
	}
}
