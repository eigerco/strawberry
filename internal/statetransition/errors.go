package statetransition

import "github.com/pkg/errors"

var (
	ErrTimeslotOutOfRange           = errors.New("timeslot out of range")
	ErrCredentialVerificationFailed = errors.New("credential verification failed")
)
