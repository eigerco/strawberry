package statetransition

import "github.com/pkg/errors"

var (
	ErrTimeslotOutOfRange   = errors.New("timeslot out of range")
	ErrWrongAssignment      = errors.New("wrong assignment")
	ErrBadSignature         = errors.New("bad signature")
	ErrReportTimeout        = errors.New("report timeout")
	ErrBadAttestationParent = errors.New("bad attestation parent")
	ErrBadOrder             = errors.New("bad order")
	ErrCoreNotEngaged       = errors.New("core not engaged")
	ErrBadValidatorIndex    = errors.New("bad validator index")
)
