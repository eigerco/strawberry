package block

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

func Test_BlockEncodeDecode(t *testing.T) {
	h := Header{
		ParentHash:     testutils.RandomHash(t),
		PriorStateRoot: testutils.RandomHash(t),
		ExtrinsicHash:  testutils.RandomHash(t),
		TimeSlotIndex:  123,
		EpochMarker: &EpochMarker{
			Entropy: testutils.RandomHash(t),
		},
		WinningTicketsMarker: &WinningTicketMarker{
			Ticket{
				Identifier: testutils.RandomBandersnatchOutputHash(t),
				EntryIndex: 112,
			}, Ticket{
				Identifier: testutils.RandomBandersnatchOutputHash(t),
				EntryIndex: 222,
			}},
		OffendersMarkers: []ed25519.PublicKey{
			testutils.RandomED25519PublicKey(t),
		},
		BlockAuthorIndex:   1,
		VRFSignature:       testutils.RandomBandersnatchSignature(t),
		BlockSealSignature: testutils.RandomBandersnatchSignature(t),
	}

	for i := 0; i < common.NumberOfValidators; i++ {
		h.EpochMarker.Keys[i].Bandersnatch = testutils.RandomBandersnatchPublicKey(t)
		h.EpochMarker.Keys[i].Ed25519 = testutils.RandomED25519PublicKey(t)
	}

	ticketProofs := []TicketProof{
		{
			EntryIndex: uint8(0),
			Proof:      randomTicketProof(t),
		},
	}
	ticketExtrinsic := TicketExtrinsic{
		TicketProofs: ticketProofs,
	}

	preimageExtrinsic := PreimageExtrinsic{
		{
			ServiceIndex: uint32(1),
			Data:         []byte("preimage data"),
		},
	}

	verdicts := []Verdict{
		{
			ReportHash: testutils.RandomHash(t),
			EpochIndex: uint32(1),
			Judgements: [common.ValidatorsSuperMajority]Judgement{
				{
					IsValid:        true,
					ValidatorIndex: uint16(2),
					Signature:      testutils.RandomEd25519Signature(t),
				},
			},
		},
	}
	disputeExtrinsic := DisputeExtrinsic{
		Verdicts: verdicts,
		Culprits: []Culprit{
			{
				ReportHash:                testutils.RandomHash(t),
				ValidatorEd25519PublicKey: testutils.RandomED25519PublicKey(t),
				Signature:                 testutils.RandomEd25519Signature(t),
			},
		},
		Faults: []Fault{
			{
				ReportHash:                testutils.RandomHash(t),
				IsValid:                   true,
				ValidatorEd25519PublicKey: testutils.RandomED25519PublicKey(t),
				Signature:                 testutils.RandomEd25519Signature(t),
			},
		},
	}

	assurancesExtrinsic := AssurancesExtrinsic{
		{
			Anchor:         testutils.RandomHash(t),
			Bitfield:       [AvailBitfieldBytes]byte{1},
			ValidatorIndex: uint16(1),
			Signature:      testutils.RandomEd25519Signature(t),
		},
	}

	guaranteesExtrinsic := GuaranteesExtrinsic{
		Guarantees: []Guarantee{
			{
				WorkReport: WorkReport{
					WorkPackageSpecification: WorkPackageSpecification{
						WorkPackageHash:           testutils.RandomHash(t),
						AuditableWorkBundleLength: uint32(100),
						ErasureRoot:               testutils.RandomHash(t),
						SegmentRoot:               testutils.RandomHash(t),
					},
					RefinementContext: RefinementContext{
						Anchor:                  RefinementContextAnchor{HeaderHash: testutils.RandomHash(t)},
						LookupAnchor:            RefinementContextLookupAnchor{HeaderHash: testutils.RandomHash(t), Timeslot: 125},
						PrerequisiteWorkPackage: nil,
					},
					CoreIndex:      uint16(1),
					AuthorizerHash: testutils.RandomHash(t),
					Output:         []byte("output data"),
					WorkResults: []WorkResult{
						{
							ServiceId:              ServiceId(1),
							ServiceHashCode:        testutils.RandomHash(t),
							PayloadHash:            testutils.RandomHash(t),
							GasPrioritizationRatio: uint64(10),
							Output:                 WorkResultOutputOrError{[]byte{0x7, 0x8}},
						},
						{
							ServiceId:              ServiceId(2),
							ServiceHashCode:        testutils.RandomHash(t),
							PayloadHash:            testutils.RandomHash(t),
							GasPrioritizationRatio: uint64(20),
							Output:                 WorkResultOutputOrError{OutOfGas},
						},
						{
							ServiceId:              ServiceId(3),
							ServiceHashCode:        testutils.RandomHash(t),
							PayloadHash:            testutils.RandomHash(t),
							GasPrioritizationRatio: uint64(30),
							Output:                 WorkResultOutputOrError{UnexpectedTermination},
						},
						{
							ServiceId:              ServiceId(4),
							ServiceHashCode:        testutils.RandomHash(t),
							PayloadHash:            testutils.RandomHash(t),
							GasPrioritizationRatio: uint64(30),
							Output:                 WorkResultOutputOrError{InvalidNumberOfExports},
						},
						{
							ServiceId:              ServiceId(5),
							ServiceHashCode:        testutils.RandomHash(t),
							PayloadHash:            testutils.RandomHash(t),
							GasPrioritizationRatio: uint64(20),
							Output:                 WorkResultOutputOrError{CodeNotAvailable},
						},
						{
							ServiceId:              ServiceId(6),
							ServiceHashCode:        testutils.RandomHash(t),
							PayloadHash:            testutils.RandomHash(t),
							GasPrioritizationRatio: uint64(10),
							Output:                 WorkResultOutputOrError{CodeTooLarge},
						},
					},
					SegmentRootLookup: make(map[crypto.Hash]crypto.Hash),
				},
				Credentials: []CredentialSignature{
					{
						ValidatorIndex: uint16(1),
						Signature:      testutils.RandomEd25519Signature(t),
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
		Header:    h,
		Extrinsic: e,
	}

	serialized, err := jam.Marshal(originalBlock)
	require.NoError(t, err)

	var deserializedBlock Block
	err = jam.Unmarshal(serialized, &deserializedBlock)
	require.NoError(t, err)

	assert.Equal(t, originalBlock, deserializedBlock)
}

func randomTicketProof(t *testing.T) [ticketProofSize]byte {
	var hash [ticketProofSize]byte
	_, err := rand.Read(hash[:])
	require.NoError(t, err)

	return hash
}
