package bandersnatch

import (
	"C"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/ebitengine/purego"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
)

var (
	initRingSize func(ring_size C.size_t) (cerr int)
	getRingSize  func() (ring_size uint)
	newSecret    func(seed []byte, seedLength C.size_t, secretOut []byte) (cerr int)
	secretPublic func(secret []byte, publicOut []byte) (cerr int)
	ietfVrfSign  func(
		secret []byte,
		vrfInputData []byte,
		vrfInputDataLen C.size_t,
		auxData []byte,
		auxDataLen C.size_t,
		signatureOut []byte,
	) (cerr int)
	ietfVrfVerify func(
		public []byte,
		vrfInputData []byte,
		vrfInputDataLen C.size_t,
		auxData []byte,
		auxDataLen C.size_t,
		signature []byte,
		outputHash []byte,
	) (cerr int)
	ietfVrfOutputHash         func(signature []byte, outputHashOut []byte) (cerr int)
	newRingVrfVerifier        func(publicKeys []byte, publicKeysLength C.size_t) (ringVrfVerifier unsafe.Pointer)
	freeRingVrfVerifier       func(ringVrfVerifier unsafe.Pointer)
	ringVrfVerifierCommitment func(ringVrfVerifier unsafe.Pointer, commitmentOut []byte) (cerr int)
	ringVrfVerifierVerify     func(
		ringVrfVerifier unsafe.Pointer,
		vrfInputData []byte,
		vrfInputDataLen C.size_t,
		auxData []byte,
		auxDataLen C.size_t,
		commitment []byte,
		signature []byte,
		outputHashOut []byte,
	) (cerr int)
	ringVrfOutputHash func(signature []byte, outputHashOut []byte) (cerr int)
	newRingVrfProver  func(secret []byte, publicKeys []byte, publicKeysLength C.size_t, proverIdx C.size_t) (ringVrfProver unsafe.Pointer)
	freeRingVrfProver func(ringVrfProver unsafe.Pointer)
	ringVrfProverSign func(
		ringVrfProver unsafe.Pointer,
		vrfInputData []byte,
		vrfInputDataLen C.size_t,
		auxData []byte,
		auxDataLen C.size_t,
		signatureOut []byte,
	) (cerr int)
)

func init() {
	// Load the Rust shared library in the init function
	libPath, err := getBandersnatchLibraryPath()
	if err != nil {
		fmt.Println("Failed to load bandersnatch library path:", err)
		os.Exit(1)
	}

	// Load the Rust shared library
	lib, err := purego.Dlopen(libPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		fmt.Println("Failed to load bandersnatch library:", err)
		os.Exit(1)
	}

	// Register the Rust FFI functions with Go using purego
	purego.RegisterLibFunc(&initRingSize, lib, "init_ring_size")
	purego.RegisterLibFunc(&getRingSize, lib, "get_ring_size")
	purego.RegisterLibFunc(&newSecret, lib, "new_secret")
	purego.RegisterLibFunc(&secretPublic, lib, "secret_public")
	purego.RegisterLibFunc(&secretPublic, lib, "secret_public")
	purego.RegisterLibFunc(&ietfVrfSign, lib, "ietf_vrf_sign")
	purego.RegisterLibFunc(&ietfVrfVerify, lib, "ietf_vrf_verify")
	purego.RegisterLibFunc(&ietfVrfOutputHash, lib, "ietf_vrf_output_hash")
	purego.RegisterLibFunc(&newRingVrfVerifier, lib, "new_ring_vrf_verifier")
	purego.RegisterLibFunc(&freeRingVrfVerifier, lib, "free_ring_vrf_verifier")
	purego.RegisterLibFunc(&ringVrfVerifierCommitment, lib, "ring_vrf_verifier_commitment")
	purego.RegisterLibFunc(&ringVrfVerifierVerify, lib, "ring_vrf_verifier_verify")
	purego.RegisterLibFunc(&ringVrfOutputHash, lib, "ring_vrf_output_hash")
	purego.RegisterLibFunc(&newRingVrfProver, lib, "new_ring_vrf_prover")
	purego.RegisterLibFunc(&freeRingVrfProver, lib, "free_ring_vrf_prover")
	purego.RegisterLibFunc(&ringVrfProverSign, lib, "ring_vrf_prover_sign")

	// Initialize the ring size, it's important that this runs before calling
	// any other functions, otherwise the ring size will initialize to a default
	// of 1023 on the Rust side. This allows us to switch between 1023 and 6 for
	// test vectors with build tags that control NumberOfValidators.
	err = InitRingSize(common.NumberOfValidators)
	if err != nil {
		panic(err)
	}
}

func getBandersnatchLibraryPath() (string, error) {
	tmpDir, err := os.MkdirTemp("", "strawberry-bandersnatch-lib-")
	if err != nil {
		return "", err
	}

	libPath := filepath.Join(tmpDir, rustLibraryName)
	err = os.WriteFile(libPath, rustLibraryBytes, 0755)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	return libPath, nil
}

// Initializes the ring size for ring related functions. The ring size
// influences the resulting KZG commitment. This must be called before any other
// ring functions or else the ring_size will initialize to 1023. Small test
// vectors use a ring size of 6. The ring size should match the number of
// validators constant.
func InitRingSize(size uint) error {
	result := initRingSize(C.size_t(size))
	if result != 0 {
		return errors.New("error initializing ring size")
	}
	return nil
}

// Get the initialized ring size.
func GetRingSize() uint {
	return getRingSize()
}

// Creates a new bandersnatch private key based on the provided seed.
func NewPrivateKeyFromSeed(seed crypto.BandersnatchSeedKey) (privateKey crypto.BandersnatchPrivateKey, err error) {
	result := newSecret(seed[:], C.size_t(len(seed)), privateKey[:])
	if result != 0 {
		return crypto.BandersnatchPrivateKey{}, errors.New("error generating private key")
	}
	return privateKey, nil
}

// Returns the public key for the given bandersnatch secret key.
func Public(secret crypto.BandersnatchPrivateKey) (publicKey crypto.BandersnatchPublicKey, err error) {
	result := secretPublic(secret[:], publicKey[:])
	if result != 0 {
		return crypto.BandersnatchPublicKey{}, errors.New("error generating private key")
	}
	return publicKey, nil
}

// Sign and produce a bandersnatch signature for the given secret key,
// vrfInputData and auxData. The output hash of the signature (Y function)
// depends soely on vrfInputData. The signature produces is not anonymous.
func Sign(
	secret crypto.BandersnatchPrivateKey,
	vrfInputData []byte,
	auxData []byte,
) (signature crypto.BandersnatchSignature, err error) {
	result := ietfVrfSign(
		secret[:],
		vrfInputData,
		C.size_t(len(vrfInputData)),
		auxData,
		C.size_t(len(auxData)),
		signature[:],
	)
	if result != 0 {
		return crypto.BandersnatchSignature{}, errors.New("error generating signature")
	}
	return signature, nil
}

// Verify a bandersnatch signature using the given public key, vrfInputData, and
// auxData. Returns a bool indicating whether the signature is valid along with
// an output hash if it is (Y function).
func Verify(
	public crypto.BandersnatchPublicKey,
	vrfInputData []byte,
	auxData []byte,
	signature crypto.BandersnatchSignature,
) (valid bool, outputHash crypto.BandersnatchOutputHash) {
	result := ietfVrfVerify(
		public[:],
		vrfInputData,
		C.size_t(len(vrfInputData)),
		auxData,
		C.size_t(len(auxData)),
		signature[:],
		outputHash[:],
	)
	if result != 0 {
		return false, crypto.BandersnatchOutputHash{}
	}
	return true, outputHash
}

// Takes a bandersnatch signature and produces it's corresponding output hash (Y
// function).  This is a way to go diretly from the signature to output hash.
func OutputHash(signature crypto.BandersnatchSignature) (outputHash crypto.BandersnatchOutputHash, err error) {
	result := ietfVrfOutputHash(signature[:], outputHash[:])
	if result != 0 {
		return crypto.BandersnatchOutputHash{}, errors.New("error getting output hash")
	}
	return outputHash, nil
}

// A container for the RingVrfVerifier opaque pointer coming from Rust's FFI.
type RingVrfVerifier struct{ ptr unsafe.Pointer }

// Creates a new RingVrfVerifier from a ring of bandersnatch public keys.
// Returns an opaque pointer from Rust FFI. Invalid bandersnatch public keys
// will become padding points on the ring.
func NewRingVerifier(publicKeys []crypto.BandersnatchPublicKey) (*RingVrfVerifier, error) {
	flatKeys := flattenPublicKeys(publicKeys)
	ptr := newRingVrfVerifier(flatKeys, C.size_t(len(flatKeys)))
	if ptr == nil {
		return nil, errors.New("unable to create RingVrfVerifier")
	}
	return &RingVrfVerifier{
		ptr: ptr,
	}, nil
}

// Frees the RingVrfVerifier on the Rust side. Must be called to avoid memory
// leaks.
func (r *RingVrfVerifier) Free() {
	if r != nil && r.ptr != nil {
		freeRingVrfVerifier(r.ptr)
		r.ptr = nil
	}
}

// We pass in a single []byte of public keys to Rust FFI for simplicity. This
// takes a slice of bandersnatch public keys and produces a flatten []byte of
// public keys.
func flattenPublicKeys(keys []crypto.BandersnatchPublicKey) []byte {
	result := make([]byte, len(keys)*len(crypto.BandersnatchPublicKey{}))
	for i, key := range keys {
		copy(result[i*len(crypto.BandersnatchPublicKey{}):], key[:])
	}
	return result
}

// Get the KZG commitment of the ring. This is used to verify ring signatures
// more efficiently. It's stored as gamma_z in SAFROLE state.
func (r *RingVrfVerifier) Commitment() (commitment crypto.RingCommitment, err error) {
	if r == nil || r.ptr == nil {
		return crypto.RingCommitment{}, errors.New("nil RingVrfVerifier")
	}

	result := ringVrfVerifierCommitment(r.ptr, commitment[:])
	if result != 0 {
		return crypto.RingCommitment{}, errors.New("error getting ring commitment")
	}

	return commitment, nil
}

// Verify a ring signature using the provided vrfInputData, auxData, KZG
// commitment. Returns a bool indicating success along with the bandersnatch
// output hash. This is used as the ticket ID/score. Notice that we have no idea
// who signed, only that the signature came from one of the ring members.
// TODO: make this a standalone function that can be used to verify a ring
// signature without the need to construct a ring verifier since it doesn't
// require the ring.
func (r *RingVrfVerifier) Verify(
	vrfInputData []byte,
	auxData []byte,
	commitment crypto.RingCommitment,
	signature crypto.RingVrfSignature,
) (valid bool, outputHash crypto.BandersnatchOutputHash) {
	if r == nil || r.ptr == nil {
		panic("nil RingVrfVerifier")
	}

	result := ringVrfVerifierVerify(
		r.ptr,
		vrfInputData,
		C.size_t(len(vrfInputData)),
		auxData,
		C.size_t(len(auxData)),
		commitment[:],
		signature[:],
		outputHash[:],
	)
	if result != 0 {
		return false, crypto.BandersnatchOutputHash{}
	}

	return true, outputHash
}

// A container for the RingVrfVProver opaque pointer coming from Rust's FFI.
type RingVrfProver struct{ ptr unsafe.Pointer }

// Creates a new RingVrfProver using the given secret key, public key ring, and
// the position of the secret key's public key within the ring. Invalid
// bandersnatch public keys will become padding points on the ring.
func NewRingProver(secret crypto.BandersnatchPrivateKey, publicKeys []crypto.BandersnatchPublicKey, proverIdx uint) (*RingVrfProver, error) {
	flatKeys := flattenPublicKeys(publicKeys)
	ptr := newRingVrfProver(secret[:], flatKeys, C.size_t(len(flatKeys)), C.size_t(proverIdx))
	if ptr == nil {
		return nil, errors.New("unable to create RingVrfProver")
	}
	return &RingVrfProver{ptr: ptr}, nil
}

// Frees the RingVrfProver on the Rust side. Must be called to avoid memory
// leaks.
func (r *RingVrfProver) Free() {
	if r != nil && r.ptr != nil {
		freeRingVrfProver(r.ptr)
		r.ptr = nil
	}
}

// Sign and produce a ring signature from the given vrfInputData and auxData.
// The signature produced is anonymous, it can be verified against the ring of
// public keys but without knowing which public key it is associated with. The
// output hash of the signature depends soley on vrfInputData. Used for ticket
// submission.
func (r *RingVrfProver) Sign(vrfInputData []byte, auxData []byte) (signature crypto.RingVrfSignature, err error) {
	if r == nil || r.ptr == nil {
		return crypto.RingVrfSignature{}, errors.New("nil RingVrfProver")
	}

	result := ringVrfProverSign(
		r.ptr,
		vrfInputData,
		C.size_t(len(vrfInputData)),
		auxData,
		C.size_t(len(auxData)),
		signature[:],
	)
	if result != 0 {
		return crypto.RingVrfSignature{}, errors.New("error generating signature")
	}

	return signature, nil
}
