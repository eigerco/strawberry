package json

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
)

type Block struct {
	Header    Header    `json:"header"`
	Extrinsic Extrinsic `json:"extrinsic"`
}

func NewBlock(b block.Block) Block {
	return Block{
		Header:    NewHeader(b.Header),
		Extrinsic: NewExtrinsic(b.Extrinsic),
	}
}

func (b Block) To() block.Block {
	return block.Block{
		Header:    b.Header.To(),
		Extrinsic: b.Extrinsic.To(),
	}
}

func NewHeader(h block.Header) Header {
	newHeader := Header{
		Parent:          hashToHex(h.ParentHash),
		ParentStateRoot: hashToHex(h.PriorStateRoot),
		ExtrinsicHash:   hashToHex(h.ExtrinsicHash),
		Slot:            h.TimeSlotIndex,
		AuthorIndex:     h.BlockAuthorIndex,
		EntropySource:   bytesToHex(h.VRFSignature[:]),
		Seal:            bytesToHex(h.BlockSealSignature[:]),
		OffendersMark:   make([]string, len(h.OffendersMarkers)),
	}

	for i, offender := range h.OffendersMarkers {
		newHeader.OffendersMark[i] = bytesToHex(offender)
	}

	if h.EpochMarker != nil {
		epochMark := EpochMark{
			Entropy:        bytesToHex(h.EpochMarker.Entropy[:]),
			TicketsEntropy: bytesToHex(h.EpochMarker.TicketsEntropy[:]),
			Validators:     make([]EpochMarkValidator, len(h.EpochMarker.Keys)),
		}

		for i, key := range h.EpochMarker.Keys {
			epochMark.Validators[i] = EpochMarkValidator{
				Bandersnatch: bytesToHex(key.Bandersnatch[:]),
				Ed25519:      bytesToHex(key.Ed25519[:]),
			}
		}

		newHeader.EpochMark = &epochMark
	}

	if h.WinningTicketsMarker != nil {
		ticketsMark := make([]TicketBody, len(h.WinningTicketsMarker))

		for i, ticket := range h.WinningTicketsMarker {
			ticketsMark[i] = TicketBody{
				ID:      bytesToHex(ticket.Identifier[:]),
				Attempt: ticket.EntryIndex,
			}
		}

		newHeader.TicketsMark = &ticketsMark
	}

	return newHeader
}

func (h Header) To() block.Header {
	newHeader := block.Header{
		ParentHash:         hexToHash(h.Parent),
		PriorStateRoot:     hexToHash(h.ParentStateRoot),
		ExtrinsicHash:      hexToHash(h.ExtrinsicHash),
		TimeSlotIndex:      jamtime.Timeslot(h.Slot),
		BlockAuthorIndex:   h.AuthorIndex,
		VRFSignature:       crypto.BandersnatchSignature(hexToBytes(h.EntropySource)),
		BlockSealSignature: crypto.BandersnatchSignature(hexToBytes(h.Seal)),
		OffendersMarkers:   make([]ed25519.PublicKey, len(h.OffendersMark)),
	}

	for i, offender := range h.OffendersMark {
		newHeader.OffendersMarkers[i] = hexToBytes(offender)
	}

	if h.EpochMark != nil {
		epochMark := &block.EpochMarker{
			Entropy:        hexToHash(h.EpochMark.Entropy),
			TicketsEntropy: hexToHash(h.EpochMark.TicketsEntropy),
		}

		for i, v := range h.EpochMark.Validators {
			epochMark.Keys[i] = block.ValidatorKeys{
				Bandersnatch: hexToBandersnatch(v.Bandersnatch),
				Ed25519:      hexToBytes(v.Ed25519),
			}
		}

		newHeader.EpochMarker = epochMark
	}

	if h.TicketsMark != nil {
		ticketsMark := &block.WinningTicketMarker{}

		for i, t := range *h.TicketsMark {
			ticketsMark[i] = block.Ticket{
				Identifier: crypto.BandersnatchOutputHash(hexToBytes(t.ID)),
				EntryIndex: t.Attempt,
			}
		}

		newHeader.WinningTicketsMarker = ticketsMark
	}

	return newHeader
}

func NewExtrinsic(e block.Extrinsic) Extrinsic {
	newExtrinsic := Extrinsic{
		Tickets:    make([]TicketProof, len(e.ET.TicketProofs)),
		Preimages:  make([]Preimage, len(e.EP)),
		Guarantees: make([]Guarantee, len(e.EG.Guarantees)),
		Assurances: make([]Assurance, len(e.EA)),
		Disputes: Disputes{
			Verdicts: make([]Verdict, len(e.ED.Verdicts)),
			Culprits: make([]Culprit, len(e.ED.Culprits)),
			Faults:   make([]Fault, len(e.ED.Faults)),
		},
	}

	for i, ticket := range e.ET.TicketProofs {
		newExtrinsic.Tickets[i] = TicketProof{
			Attempt:   ticket.EntryIndex,
			Signature: bytesToHex(ticket.Proof[:]),
		}
	}

	for i, preimage := range e.EP {
		newExtrinsic.Preimages[i] = Preimage{
			Requester: preimage.ServiceIndex,
			Blob:      bytesToHex(preimage.Data),
		}
	}

	for i, guarantee := range e.EG.Guarantees {
		newGuarantee := Guarantee{
			Report:     NewWorkReport(guarantee.WorkReport),
			Slot:       jamtime.Timeslot(guarantee.Timeslot),
			Signatures: make([]GuaranteeSignature, len(guarantee.Credentials)),
		}

		for j, c := range guarantee.Credentials {
			newGuarantee.Signatures[j] = GuaranteeSignature{
				ValidatorIndex: uint16(c.ValidatorIndex),
				Signature:      bytesToHex(c.Signature[:]),
			}
		}

		newExtrinsic.Guarantees[i] = newGuarantee
	}

	for i, assurance := range e.EA {
		newExtrinsic.Assurances[i] = Assurance{
			Anchor:         hashToHex(assurance.Anchor),
			Bitfield:       bytesToHex(assurance.Bitfield[:]),
			ValidatorIndex: assurance.ValidatorIndex,
			Signature:      bytesToHex(assurance.Signature[:]),
		}
	}

	for i, verdict := range e.ED.Verdicts {
		newVerdict := Verdict{
			Target: hashToHex(verdict.ReportHash),
			Age:    verdict.EpochIndex,
			Votes:  make([]VerdictVote, len(verdict.Judgements)),
		}

		for j, judgement := range verdict.Judgements {
			newVerdict.Votes[j] = VerdictVote{
				Vote:      judgement.IsValid,
				Index:     judgement.ValidatorIndex,
				Signature: bytesToHex(judgement.Signature[:]),
			}
		}

		newExtrinsic.Disputes.Verdicts[i] = newVerdict
	}

	for i, culprit := range e.ED.Culprits {
		newExtrinsic.Disputes.Culprits[i] = Culprit{
			Target:    hashToHex(culprit.ReportHash),
			Key:       bytesToHex(culprit.ValidatorEd25519PublicKey),
			Signature: bytesToHex(culprit.Signature[:]),
		}
	}

	for i, fault := range e.ED.Faults {
		newExtrinsic.Disputes.Faults[i] = Fault{
			Target:    hashToHex(fault.ReportHash),
			Vote:      fault.IsValid,
			Key:       bytesToHex(fault.ValidatorEd25519PublicKey),
			Signature: bytesToHex(fault.Signature[:]),
		}
	}

	return newExtrinsic
}

func (e Extrinsic) To() block.Extrinsic {
	newExtrinsic := block.Extrinsic{
		ET: block.TicketExtrinsic{
			TicketProofs: make([]block.TicketProof, len(e.Tickets)),
		},
		EP: make([]block.Preimage, len(e.Preimages)),
		EG: block.GuaranteesExtrinsic{
			Guarantees: make([]block.Guarantee, len(e.Guarantees)),
		},
		EA: make([]block.Assurance, len(e.Assurances)),
		ED: block.DisputeExtrinsic{
			Verdicts: make([]block.Verdict, len(e.Disputes.Verdicts)),
			Culprits: make([]block.Culprit, len(e.Disputes.Culprits)),
			Faults:   make([]block.Fault, len(e.Disputes.Faults)),
		},
	}

	for i, ticket := range e.Tickets {
		newExtrinsic.ET.TicketProofs[i] = block.TicketProof{
			EntryIndex: ticket.Attempt,
			Proof:      crypto.RingVrfSignature(hexToBytes(ticket.Signature)),
		}
	}

	for i, preimage := range e.Preimages {
		newExtrinsic.EP[i] = block.Preimage{
			ServiceIndex: preimage.Requester,
			Data:         hexToBytes(preimage.Blob),
		}
	}
	for i, guarantee := range e.Guarantees {
		newGuarantee := block.Guarantee{
			WorkReport:  guarantee.Report.To(),
			Timeslot:    guarantee.Slot,
			Credentials: make([]block.CredentialSignature, len(guarantee.Signatures)),
		}

		for j, c := range guarantee.Signatures {
			newGuarantee.Credentials[j] = block.CredentialSignature{
				ValidatorIndex: c.ValidatorIndex,
				Signature:      crypto.Ed25519Signature(hexToBytes(c.Signature)),
			}
		}

		newExtrinsic.EG.Guarantees[i] = newGuarantee
	}

	for i, assurance := range e.Assurances {
		newExtrinsic.EA[i] = block.Assurance{
			Anchor:         hexToHash(assurance.Anchor),
			Bitfield:       [block.AvailBitfieldBytes]byte(hexToBytes(assurance.Bitfield)),
			ValidatorIndex: assurance.ValidatorIndex,
			Signature:      crypto.Ed25519Signature(hexToBytes(assurance.Signature)),
		}
	}

	for i, verdict := range e.Disputes.Verdicts {
		newVerdict := block.Verdict{
			ReportHash: hexToHash(verdict.Target),
			EpochIndex: verdict.Age,
		}

		for j, vote := range verdict.Votes {
			newVerdict.Judgements[j] = block.Judgement{
				IsValid:        vote.Vote,
				ValidatorIndex: vote.Index,
				Signature:      crypto.Ed25519Signature(hexToBytes(vote.Signature)),
			}
		}

		newExtrinsic.ED.Verdicts[i] = newVerdict
	}

	for i, culprit := range e.Disputes.Culprits {
		newExtrinsic.ED.Culprits[i] = block.Culprit{
			ReportHash:                hexToHash(culprit.Target),
			ValidatorEd25519PublicKey: hexToBytes(culprit.Key),
			Signature:                 crypto.Ed25519Signature(hexToBytes(culprit.Signature)),
		}
	}

	for i, fault := range e.Disputes.Faults {
		newExtrinsic.ED.Faults[i] = block.Fault{
			ReportHash:                hexToHash(fault.Target),
			IsValid:                   fault.Vote,
			ValidatorEd25519PublicKey: hexToBytes(fault.Key),
			Signature:                 crypto.Ed25519Signature(hexToBytes(fault.Signature)),
		}
	}

	return newExtrinsic
}

func DumpBlockSnapshot(b block.Block) string {
	blockBytes, err := json.MarshalIndent(NewBlock(b), "", "    ")
	if err != nil {
		panic(fmt.Sprintf("failed to marshal block: %v", err))
	}
	return string(blockBytes)
}

func RestoreBlockSnapshot(b []byte) block.Block {
	var newBlock Block
	err := json.Unmarshal(b, &newBlock)
	if err != nil {
		panic(fmt.Sprintf("failed to unmarshal block: %v", err))
	}
	return newBlock.To()
}

type Header struct {
	Parent          string           `json:"parent"`
	ParentStateRoot string           `json:"parent_state_root"`
	ExtrinsicHash   string           `json:"extrinsic_hash"`
	Slot            jamtime.Timeslot `json:"slot"`
	EpochMark       *EpochMark       `json:"epoch_mark"`
	TicketsMark     *[]TicketBody    `json:"tickets_mark"`
	OffendersMark   []string         `json:"offenders_mark"`
	AuthorIndex     uint16           `json:"author_index"`
	EntropySource   string           `json:"entropy_source"`
	Seal            string           `json:"seal"`
}

type EpochMark struct {
	Entropy        string               `json:"entropy"`
	TicketsEntropy string               `json:"tickets_entropy"`
	Validators     []EpochMarkValidator `json:"validators"`
}

type EpochMarkValidator struct {
	Bandersnatch string `json:"bandersnatch"`
	Ed25519      string `json:"ed25519"`
}

type Extrinsic struct {
	Tickets    []TicketProof `json:"tickets"`
	Preimages  []Preimage    `json:"preimages"`
	Guarantees []Guarantee   `json:"guarantees"`
	Assurances []Assurance   `json:"assurances"`
	Disputes   Disputes      `json:"disputes"`
}

type TicketProof struct {
	Attempt   uint8  `json:"attempt"`
	Signature string `json:"signature"`
}

type Preimage struct {
	Requester uint32 `json:"requester"`
	Blob      string `json:"blob"`
}

type Guarantee struct {
	Report     WorkReport           `json:"report"`
	Slot       jamtime.Timeslot     `json:"slot"`
	Signatures []GuaranteeSignature `json:"signatures"`
}

type GuaranteeSignature struct {
	ValidatorIndex uint16 `json:"validator_index"`
	Signature      string `json:"signature"`
}

type Assurance struct {
	Anchor         string `json:"anchor"`
	Bitfield       string `json:"bitfield"`
	ValidatorIndex uint16 `json:"validator_index"`
	Signature      string `json:"signature"`
}

type Disputes struct {
	Verdicts []Verdict `json:"verdicts"`
	Culprits []Culprit `json:"culprits"`
	Faults   []Fault   `json:"faults"`
}

type Verdict struct {
	Target string        `json:"target"`
	Age    uint32        `json:"age"`
	Votes  []VerdictVote `json:"votes"`
}

type VerdictVote struct {
	Vote      bool   `json:"vote"`
	Index     uint16 `json:"index"`
	Signature string `json:"signature"`
}

type Culprit struct {
	Target    string `json:"target"`
	Key       string `json:"key"`
	Signature string `json:"signature"`
}

type Fault struct {
	Target    string `json:"target"`
	Vote      bool   `json:"vote"`
	Key       string `json:"key"`
	Signature string `json:"signature"`
}
