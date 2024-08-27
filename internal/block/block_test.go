package block

import (
	"crypto/rand"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
)

func Test_BlockEncodeDecode(t *testing.T) {
	h := Header{
		ParentHash:     randomHash(t),
		PriorStateRoot: randomHash(t),
		ExtrinsicHash:  randomHash(t),
		TimeSlotIndex:  123,
		EpochMarker: &EpochMarker{
			Keys: [NumberOfValidators]crypto.BandersnatchPublicKey{
				randomPublicKey(t),
				randomPublicKey(t),
			},
			Entropy: randomHash(t),
		},
		WinningTicketsMarker: [jamtime.TimeslotsPerEpoch]*Ticket{{
			Identifier: randomHash(t),
			EntryIndex: 112,
		},
			{
				Identifier: randomHash(t),
				EntryIndex: 222,
			}},
		Verdicts: []crypto.Hash{
			randomHash(t),
			randomHash(t),
		},
		OffendersMarkers: []crypto.Ed25519PublicKey{
			randomED25519PublicKey(t),
		},
		BlockAuthorIndex:   1,
		VRFSignature:       randomSignature(t),
		BlockSealSignature: randomSignature(t),
	}

	ticketProofs := []TicketProof{
		{
			EntryIndex: uint8(0),
			Proof:      randomTicketProof(t),
		},
	}
	ticketExtrinsic := &TicketExtrinsic{
		TicketProofs: ticketProofs,
	}

	preimageExtrinsic := &PreimageExtrinsic{
		{
			ServiceIndex: uint32(1),
			Data:         []byte("preimage data"),
		},
	}

	verdicts := []Verdict{
		{
			ReportHash: randomHash(t),
			EpochIndex: uint32(1),
			Judgments: []Judgment{
				{
					IsValid:        true,
					ValidatorIndex: uint16(2),
					Signature:      randomEd25519Signature(t),
				},
			},
		},
	}
	disputeExtrinsic := &DisputeExtrinsic{
		Verdicts: verdicts,
		Culprits: []Culprit{
			{
				ReportHash:                randomHash(t),
				ValidatorEd25519PublicKey: randomED25519PublicKey(t),
				Signature:                 randomEd25519Signature(t),
			},
		},
		Faults: []Fault{
			{
				ReportHash:                randomHash(t),
				IsValid:                   true,
				ValidatorEd25519PublicKey: randomED25519PublicKey(t),
				Signature:                 randomEd25519Signature(t),
			},
		},
	}

	assurancesExtrinsic := &AssurancesExtrinsic{
		{
			Anchor:         randomHash(t),
			Flag:           true,
			ValidatorIndex: uint16(1),
			Signature:      randomEd25519Signature(t),
		},
	}

	guaranteesExtrinsic := &GuaranteesExtrinsic{
		Guarantees: []Guarantee{
			{
				WorkReport: WorkReport{
					Specification: WorkPackageSpecification{
						Hash:        randomHash(t),
						Length:      uint32(100),
						ErasureRoot: randomHash(t),
						SegmentRoot: randomHash(t),
					},
					Context: RefinementContext{
						AnchorHeaderHash:         randomHash(t),
						AnchorPosteriorStateRoot: randomHash(t),
						AnchorPosteriorBeefyRoot: randomHash(t),
						LookupAnchorHeaderHash:   randomHash(t),
						LookupAnchorTimeslot:     125,
						PrerequisiteHash:         nil,
					},
					CoreIndex:      uint16(1),
					AuthorizerHash: randomHash(t),
					Output:         []byte("output data"),
					Results: []WorkResult{
						{
							ServiceIndex: uint32(1),
							CodeHash:     randomHash(t),
							PayloadHash:  randomHash(t),
							GasRatio:     uint64(10),
							Output: WorkResultOutput{
								Data:  []byte("work result data"),
								Error: NoError,
							},
						},
					},
				},
				Credentials: []CredentialSignature{
					{
						ValidatorIndex: uint32(1),
						Signature:      randomEd25519Signature(t),
					},
				},
				Timeslot: 200,
			},
		},
	}

	e := Extrinsic{
		ET: ticketExtrinsic,
		EP: preimageExtrinsic,
		ED: disputeExtrinsic,
		EA: assurancesExtrinsic,
		EG: guaranteesExtrinsic,
	}

	originalBlock := Block{
		Header:    &h,
		Extrinsic: &e,
	}

	serializer := serialization.NewSerializer(&codec.JAMCodec{})
	serialized, err := serializer.Encode(originalBlock)
	require.NoError(t, err)

	var deserializedBlock Block
	err = serializer.Decode(serialized, &deserializedBlock)
	require.NoError(t, err)

	assert.Equal(t, originalBlock, deserializedBlock)
}

func randomTicketProof(t *testing.T) [ticketProofSize]byte {
	var hash [ticketProofSize]byte
	_, err := rand.Read(hash[:])
	require.NoError(t, err)

	return hash
}

func randomEd25519Signature(t *testing.T) [crypto.Ed25519SignatureSize]byte {
	var hash [crypto.Ed25519SignatureSize]byte
	_, err := rand.Read(hash[:])
	require.NoError(t, err)

	return hash
}
