package block

// Preimage represents a single preimage item in the extrinsic
type Preimage struct {
	ServiceIndex uint32 // s
	Data         []byte // p
}

type PreimageExtrinsic []Preimage
