package block

import "github.com/eigerco/strawberry/pkg/serialization/codec/jam"

// Block represents the main block structure
type Block struct {
	Header    Header
	Extrinsic Extrinsic
}

// Extrinsic represents the block extrinsic data
type Extrinsic struct {
	ET TicketExtrinsic
	EP PreimageExtrinsic
	EG GuaranteesExtrinsic
	EA AssurancesExtrinsic
	ED DisputeExtrinsic
}

// Bytes returns the Jam encoded bytes of the block
func (b Block) Bytes() ([]byte, error) {
	bytes, err := jam.Marshal(b)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// BlockFromBytes unmarshals a block from Jam encoded bytes
func BlockFromBytes(data []byte) (Block, error) {
	var block Block
	if err := jam.Unmarshal(data, &block); err != nil {
		return Block{}, err
	}
	return block, nil
}
