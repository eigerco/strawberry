package protocol

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/quic-go/quic-go"
)

const (
	// UP (Unique Persistent) stream is 0
	StreamKindBlockAnnouncement StreamKind = 0

	// CE (Common Ephemeral) streams start from 128
	StreamKindBlockRequest        StreamKind = 128
	StreamKindStateRequest        StreamKind = 129
	StreamKindTicketDistP2P       StreamKind = 131
	StreamKindTicketDistBroadcast StreamKind = 132
	StreamKindWorkPackageSubmit   StreamKind = 133
	StreamKindWorkPackageShare    StreamKind = 134
	StreamKindWorkReportDist      StreamKind = 135
	StreamKindWorkReportRequest   StreamKind = 136
	StreamKindShardDist           StreamKind = 137
	StreamKindAuditShardRequest   StreamKind = 138
	StreamKindSegmentRequest      StreamKind = 139
	StreamKindSegmentRequestJust  StreamKind = 140
	StreamKindAssuranceDist       StreamKind = 141
	StreamKindPreimageAnnounce    StreamKind = 142
	StreamKindPreimageRequest     StreamKind = 143
	StreamKindAuditAnnouncement   StreamKind = 144
	StreamKindJudgmentPublish     StreamKind = 145
)

// StreamHandler processes individual QUIC streams within a connection
type StreamHandler interface {
	HandleStream(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error
}

// StreamKind represents the type of stream (Unique Persistent or Common Ephemeral)
type StreamKind byte

// JAMNPRegistry manages stream handlers for different protocol stream kinds
type JAMNPRegistry struct {
	mu       sync.RWMutex
	handlers map[StreamKind]StreamHandler
}

// NewJAMNPRegistry creates a new registry for stream handlers
func NewJAMNPRegistry() *JAMNPRegistry {
	return &JAMNPRegistry{
		handlers: make(map[StreamKind]StreamHandler),
	}
}

// ValidateKind checks if a given byte represents a valid stream kind
// Returns an error if the kind is outside the valid range
func (r *JAMNPRegistry) ValidateKind(kindByte byte) error {
	kind := StreamKind(kindByte)
	if kind < StreamKindBlockAnnouncement || kind > StreamKindJudgmentPublish {
		return fmt.Errorf("invalid stream kind: %d", kind)
	}
	return nil
}

// RegisterHandler associates a stream handler with a specific stream kind.
// When a stream of the registered kind is opened, the corresponding handler
// will be invoked to process it. This method is called during protocol
// initialization to set up handlers for supported stream kinds.
func (r *JAMNPRegistry) RegisterHandler(kind StreamKind, handler StreamHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[kind] = handler
}

// GetHandler retrieves the handler associated with a given stream kind byte
// Returns an error if no handler is registered for the kind
func (r *JAMNPRegistry) GetHandler(kind StreamKind) (StreamHandler, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	handler, ok := r.handlers[kind]
	if !ok {
		return nil, fmt.Errorf("no handler for kind %d", kind)
	}
	return handler, nil
}

// IsUniquePersistent determines if a stream kind is Unique Persistent (UP)
// Returns true for UP streams (values < 128) and false for Common Ephemeral (CE) streams
func (k StreamKind) IsUniquePersistent() bool {
	return k < 128
}
