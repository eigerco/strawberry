package block

// Preimage represents a single preimage item in the extrinsic
type Preimage struct {
	ServiceIndex ServiceId // s
	Data         []byte    // p
}

// PreimageExtrinsic EP ∈ ⟦(NS , B)⟧ (eq. 12.38)
type PreimageExtrinsic []Preimage
