package crypto

import (
	"io"

	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/crypto/ed25519"
)

type Ed25519Signature [Ed25519SignatureSize]byte

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (s *Ed25519Signature) UnmarshalJAM(r io.Reader) error {
	_, err := io.ReadFull(r, s[:])
	return err
}

type BlsKey [BLSSize]byte

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (b *BlsKey) UnmarshalJAM(r io.Reader) error {
	_, err := io.ReadFull(r, b[:])
	return err
}

type BandersnatchSeedKey [BandersnatchSize]byte
type BandersnatchPrivateKey [BandersnatchSize]byte

type BandersnatchPublicKey [BandersnatchSize]byte

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (b *BandersnatchPublicKey) UnmarshalJAM(r io.Reader) error {
	_, err := io.ReadFull(r, b[:])
	return err
}

func (b BandersnatchPublicKey) TicketOrKeyType() {}

type BandersnatchSignature [96]byte

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (s *BandersnatchSignature) UnmarshalJAM(r io.Reader) error {
	_, err := io.ReadFull(r, s[:])
	return err
}

type BandersnatchOutputHash [32]byte

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (h *BandersnatchOutputHash) UnmarshalJAM(r io.Reader) error {
	_, err := io.ReadFull(r, h[:])
	return err
}

type RingVrfSignature [VrfProofSize]byte

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (s *RingVrfSignature) UnmarshalJAM(r io.Reader) error {
	_, err := io.ReadFull(r, s[:])
	return err
}

type MetadataKey [MetadataSize]byte

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (m *MetadataKey) UnmarshalJAM(r io.Reader) error {
	_, err := io.ReadFull(r, m[:])
	return err
}

type RingCommitment [BandersnatchRingSize]byte

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (c *RingCommitment) UnmarshalJAM(r io.Reader) error {
	_, err := io.ReadFull(r, c[:])
	return err
}

type EpochKeys [constants.TimeslotsPerEpoch]BandersnatchPublicKey

func (e EpochKeys) TicketsOrKeysType() {}

type ValidatorKey struct {
	Bandersnatch BandersnatchPublicKey
	Ed25519      ed25519.PublicKey
	Bls          BlsKey
	Metadata     MetadataKey
}

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (vk *ValidatorKey) UnmarshalJAM(r io.Reader) error {
	if _, err := io.ReadFull(r, vk.Bandersnatch[:]); err != nil {
		return err
	}
	vk.Ed25519 = make([]byte, Ed25519PublicSize)
	if _, err := io.ReadFull(r, vk.Ed25519); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, vk.Bls[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, vk.Metadata[:]); err != nil {
		return err
	}
	return nil
}

func (vk ValidatorKey) IsEmpty() bool {
	return vk.Bandersnatch == BandersnatchPublicKey{} &&
		ed25519.IsEmpty(vk.Ed25519) &&
		vk.Bls == BlsKey{} &&
		vk.Metadata == MetadataKey{}
}
