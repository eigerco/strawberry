package state

import "github.com/eigerco/strawberry/internal/crypto"

type PendingAuthorizersQueues [TotalNumberOfCores][PendingAuthorizersQueueSize]crypto.Hash

type EntropyPool [EntropyPoolSize]crypto.Hash
type CoreAuthorizersPool [TotalNumberOfCores][]crypto.Hash // TODO: Maximum length per core: MaxAuthorizersPerCore

// Context is an intermediate value for state transition calculations
// TODO: Add relevant fields when state transitions are implemented
type Context struct {
	// Add relevant fields
}
