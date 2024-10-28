package polkavm

import "fmt"

// ErrPanic irregular program termination caused by some exceptional circumstance (☇)
type ErrPanic struct {
	msg  string
	args []any
}

func ErrPanicf(msg string, args ...any) *ErrPanic {
	return &ErrPanic{msg: msg, args: args}
}

func (e *ErrPanic) Error() string {
	return fmt.Sprintf("panic: "+e.msg, e.args...)
}

// ErrOutOfGas exhaustion of gas: (∞)
var ErrOutOfGas = fmt.Errorf("out of gas")

// ErrPageFault a page fault (attempt to access some address in RAM which is not accessible). This includes the address at fault. (F)
type ErrPageFault struct {
	Reason  string
	Address uint32
}

func (e *ErrPageFault) Error() string {
	return fmt.Sprintf("page fault %s: address=%d", e.Reason, e.Address)
}

// ErrHostCall an attempt at progressing a host-call (h)
var ErrHostCall = fmt.Errorf("host call")

// ErrHalt regular program termination (∎)
var ErrHalt = fmt.Errorf("halt")
