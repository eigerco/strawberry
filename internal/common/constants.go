//go:build !integration

package common

const (
	NumberOfValidators = 1023
	TotalNumberOfCores = 341 // (C) Total number of cores in the system
	ValidatorsSuperMajority = (2 * NumberOfValidators / 3) + 1 // 2/3V + 1
)
