package protocol

import (
	"fmt"
	"strings"
)

const (
	// Protocol prefix for JAMNP-S
	protocolPrefix = "jamnp-s"

	// Current protocol version
	currentVersion = "0"

	// Builder suffix for builder connections
	builderSuffix = "builder"

	// Chain hash length in nibbles
	chainHashLength = 8
)

// ProtocolID represents a complete ALPN protocol identifier.
// Format: jamnp-s/<version>/<chain-hash>[/builder]
type ProtocolID struct {
	// Version is the protocol version (currently only "0")
	Version string
	// ChainHash is the 8-nibble chain identifier
	ChainHash string
	// IsBuilder indicates if this is a builder connection
	IsBuilder bool
}

// NewProtocolID creates a new ProtocolID with the specified chain hash and builder status.
// The version is automatically set to the current supported version.
func NewProtocolID(chainHash string, isBuilder bool) *ProtocolID {
	return &ProtocolID{
		Version:   currentVersion,
		ChainHash: chainHash,
		IsBuilder: isBuilder,
	}
}

// String converts the ProtocolID to its string representation.
// Format examples:
//   - Non-builder: "jamnp-s/0/deadbeef"
//   - Builder: "jamnp-s/0/deadbeef/builder"
func (p *ProtocolID) String() string {
	parts := []string{protocolPrefix, p.Version, p.ChainHash}
	if p.IsBuilder {
		parts = append(parts, builderSuffix)
	}
	return strings.Join(parts, "/")
}

// ParseProtocolID parses an ALPN protocol string into a ProtocolID.
// Validates:
//   - Correct format and number of parts
//   - Valid prefix
//   - Supported version
//   - Chain hash format (8 hex nibbles)
//   - Optional builder suffix
//
// Returns an error if any validation fails.
func ParseProtocolID(protocol string) (*ProtocolID, error) {
	parts := strings.Split(protocol, "/")

	// Validate basic format
	if len(parts) < 3 || len(parts) > 4 {
		return nil, fmt.Errorf("invalid protocol format: %s", protocol)
	}

	// Validate prefix
	if parts[0] != protocolPrefix {
		return nil, fmt.Errorf("invalid protocol prefix: %s", parts[0])
	}

	// Validate version
	if parts[1] != currentVersion {
		return nil, fmt.Errorf("unsupported protocol version: %s", parts[1])
	}

	// Validate chain hash format (8 hex nibbles)
	chainHash := parts[2]
	if len(chainHash) != chainHashLength {
		return nil, fmt.Errorf("invalid chain hash length: %s", chainHash)
	}
	for _, c := range chainHash {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, fmt.Errorf("invalid chain hash character: %c", c)
		}
	}

	// Check for builder suffix
	isBuilder := false
	if len(parts) == 4 {
		if strings.ToLower(parts[3]) != builderSuffix {
			return nil, fmt.Errorf("invalid protocol suffix: %s", parts[3])
		}

		isBuilder = true
	}

	return &ProtocolID{
		Version:   parts[1],
		ChainHash: chainHash,
		IsBuilder: isBuilder,
	}, nil
}

// ValidateALPNProtocol validates an ALPN protocol string according to JAMNP-S specification.
// This is a convenience wrapper around ParseProtocolID that only returns the error status.
func ValidateALPNProtocol(protocol string) error {
	_, err := ParseProtocolID(protocol)
	return err
}

// AcceptableProtocols returns all acceptable protocol strings for a given chain hash.
// Returns both builder and non-builder variants of the protocol identifier.
func AcceptableProtocols(chainHash string) []string {
	return []string{
		NewProtocolID(chainHash, false).String(),
		NewProtocolID(chainHash, true).String(),
	}
}
