package block

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

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

// Hash implements equations 5.4-5.6 in the graypaper (v0.6.4)
func (e Extrinsic) Hash() (crypto.Hash, error) {
	// This effectively holds H_#(a) in equation 5.4. (v0.6.4)
	var hashes struct {
		TicketsHash    crypto.Hash
		PreimagesHash  crypto.Hash
		GuaranteesHash crypto.Hash
		AssurancesHash crypto.Hash
		DisputesHash   crypto.Hash
	}

	// Encode and hash tickets. Standard serialization.
	ticketsBytes, err := jam.Marshal(e.ET)
	if err != nil {
		return crypto.Hash{}, err
	}
	hashes.TicketsHash = crypto.HashData(ticketsBytes)

	// Encode and hash preimages. Standard serialization.
	preimagesBytes, err := jam.Marshal(e.EP)
	if err != nil {
		return crypto.Hash{}, err
	}
	hashes.PreimagesHash = crypto.HashData(preimagesBytes)

	// Guarantees are encoded in a special way. The work report is hashed
	// instead of using the work report itself.
	// See equation 5.6 in the graypaper. (v0.6.4)
	guarantees := make([]struct {
		WorkReportHash crypto.Hash
		TimeSlot       jamtime.Timeslot
		Credentials    []CredentialSignature
	}, len(e.EG.Guarantees))

	for i, g := range e.EG.Guarantees {
		hash, err := g.WorkReport.Hash()
		if err != nil {
			return crypto.Hash{}, err
		}

		guarantees[i].WorkReportHash = hash
		guarantees[i].TimeSlot = g.Timeslot
		guarantees[i].Credentials = g.Credentials
	}

	guaranteesBytes, err := jam.Marshal(guarantees)
	if err != nil {
		return crypto.Hash{}, err
	}
	hashes.GuaranteesHash = crypto.HashData(guaranteesBytes)

	// Encode and hash assurances. Standard serialization.
	assurancesBytes, err := jam.Marshal(e.EA)
	if err != nil {
		return crypto.Hash{}, err
	}
	hashes.AssurancesHash = crypto.HashData(assurancesBytes)

	// Encode and hash disputes. Standard serialization.
	disputesBytes, err := jam.Marshal(e.ED)
	if err != nil {
		return crypto.Hash{}, err
	}
	hashes.DisputesHash = crypto.HashData(disputesBytes)

	// Encode all the hashes. E(H_#(a)) in equation 5.4 (v0.6.4)
	hashesBytes, err := jam.Marshal(hashes)
	if err != nil {
		return crypto.Hash{}, err
	}

	// Final hash of the hashes. H(E(H_#(a))) in equation 5.4 (v0.6.4)
	return crypto.HashData(hashesBytes), nil
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
