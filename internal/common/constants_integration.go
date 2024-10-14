//go:build integration

package common

const (
	NumberOfValidators = 6
	TotalNumberOfCores = 2
	ValidatorsSuperMajority = (2 * NumberOfValidators / 3) + 1
)
