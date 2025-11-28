//go:build tiny

package block

const (
	MaxTicketsPerBlock = 3 // `K` in the paper. The maximum number of tickets which may be submitted in a single extrinsic.
)
