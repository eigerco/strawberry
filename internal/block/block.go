package block

// Block represents the main block structure
type Block struct {
	Header    Header
	Extrinsic Extrinsic
}

// Extrinsic represents the block extrinsic data
type Extrinsic struct {
	ET TicketExtrinsic
	ED DisputeExtrinsic
	EP PreimageExtrinsic
	EA AssurancesExtrinsic
	EG GuaranteesExtrinsic
}
