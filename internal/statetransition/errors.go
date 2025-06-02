package statetransition

import "errors"

var (
	ErrTimeslotOutOfRange   = errors.New("timeslot out of range")
	ErrWrongAssignment      = errors.New("wrong assignment")
	ErrBadSignature         = errors.New("bad signature")
	ErrBadAttestationParent = errors.New("bad attestation parent")
	ErrCoreNotEngaged       = errors.New("core not engaged")
	ErrBadValidatorIndex    = errors.New("bad validator index")
)
