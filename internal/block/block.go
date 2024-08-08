package block

// Block represents the main block structure
type Block struct {
	Header    *Header
	Extrinsic *Extrinsic
}

// Extrinsic represents the block extrinsic data
type Extrinsic struct {
	ET *TicketExtrinsic
	EP *PreimageExtrinsic
	ED *DisputeExtrinsic
	EA *AssurancesExtrinsic
	EG *GuaranteesExtrinsic
}
