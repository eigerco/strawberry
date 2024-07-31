package block

// PreimageItem represents a single preimage item in the extrinsic
type Preimage struct {
    ServiceIndex uint32
    Data         []byte
}

type PreimageExtrinsic []Preimage
