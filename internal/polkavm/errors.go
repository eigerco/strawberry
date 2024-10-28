package polkavm

import "fmt"

var (
	ErrOutOfGas        = fmt.Errorf("out of gas")
	ErrAccountNotFound = fmt.Errorf("account not found")
)
