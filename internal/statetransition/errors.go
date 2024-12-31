package statetransition

import "github.com/pkg/errors"

var (
	ErrTimeslotOutOfRange   = errors.New("timeslot out of range")
	ErrWrongAssignment      = errors.New("wrong assignment")
	ErrBadSignature         = errors.New("bad_signature")
	ErrReportTimeout        = errors.New("report_timeout")
	ErrBadAttestationParent = errors.New("bad_attestation_parent")
	ErrBadOrder             = errors.New("bad_order")
	ErrCoreNotEngaged       = errors.New("core_not_engaged")
	ErrBadValidatorIndex    = errors.New("bad_validator_index")
)
