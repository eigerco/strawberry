package transport

import "errors"

var (
	ErrInvalidCertificate = errors.New("invalid certificate")
	ErrConnectionExists   = errors.New("connection already exists")
	ErrStreamClosed       = errors.New("stream closed")
	ErrListenerFailed     = errors.New("failed to create QUIC listener")
	ErrDialFailed         = errors.New("failed to dial peer")
	ErrConnFailed         = errors.New("failed to establish connection")
)
