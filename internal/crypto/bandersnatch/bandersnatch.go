package bandersnatch

import (
	"C"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/eigerco/strawberry/internal/crypto"
)

var (
	newPrivateKeyFromSeedFunc func(*C.uchar, C.size_t) unsafe.Pointer
	getPublicKeyFunc          func(unsafe.Pointer) unsafe.Pointer
	signDataFunc              func(unsafe.Pointer, unsafe.Pointer, uintptr) unsafe.Pointer
	verifySignatureFunc       func(unsafe.Pointer, unsafe.Pointer, unsafe.Pointer, uintptr) bool
	generateVrfProofFunc      func(unsafe.Pointer, unsafe.Pointer, uintptr, unsafe.Pointer, uintptr) *crypto.VrfProof
	verifyVrfProofFunc        func(unsafe.Pointer, unsafe.Pointer, unsafe.Pointer, uintptr, unsafe.Pointer, uintptr) bool
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
	purego.RegisterLibFunc(&newPrivateKeyFromSeedFunc, lib, "new_private_key_from_seed")
	purego.RegisterLibFunc(&getPublicKeyFunc, lib, "get_public_key")
	purego.RegisterLibFunc(&signDataFunc, lib, "sign_data")
	purego.RegisterLibFunc(&verifySignatureFunc, lib, "verify_signature")
	purego.RegisterLibFunc(&generateVrfProofFunc, lib, "generate_vrf_proof")
	purego.RegisterLibFunc(&verifyVrfProofFunc, lib, "verify_vrf_proof")
}

// PrivateKey represents a Bandersnatch private key.
type PrivateKey struct {
	ptr unsafe.Pointer
}

// VrfSignData represents the data needed for VRF signing
// nolint: unused
type VrfSignData struct {
	transcript []byte   // ⟨x ∈ Y⟩ Contextual data that influences the signature
	inputs     [][]byte // (m) Input data elements to be signed, can vary in size
}

// NewPrivateKeyFromSeed creates a new private key from a seed
func NewPrivateKeyFromSeed(seed crypto.BandersnatchSeedKey) (*PrivateKey, error) {
	seedPtr := unsafe.Pointer(&seed[0])
	ptr := newPrivateKeyFromSeedFunc((*C.uchar)(seedPtr), C.size_t(len(seed)))
	if ptr == nil {
		return nil, errors.New("failed to create private key")
	}
	return &PrivateKey{ptr: ptr}, nil
}

// Public returns the public key associated with the private key
func (pk *PrivateKey) Public() (crypto.BandersnatchPublicKey, error) {
	if pk.ptr == nil {
		return crypto.BandersnatchPublicKey{}, errors.New("invalid private key")
	}

	publicKeyPtr := getPublicKeyFunc(pk.ptr)

	if publicKeyPtr == nil {
		return crypto.BandersnatchPublicKey{}, errors.New("failed to retrieve public key")
	}

	// Convert the pointer to a Bandersnatch PublicKey array
	var publicKey crypto.BandersnatchPublicKey
	copy(publicKey[:], C.GoBytes(publicKeyPtr, C.int(len(publicKey))))

	return publicKey, nil
}

// Sign creates a Schnorr signature for the given data using the private key
func (pk *PrivateKey) Sign(data []byte) (crypto.BandersnatchSignature, error) {
	if pk.ptr == nil {
		return crypto.BandersnatchSignature{}, errors.New("invalid private key")
	}

	if len(data) == 0 {
		return crypto.BandersnatchSignature{}, errors.New("data to sign cannot be empty")
	}

	// Call Rust FFI to sign the data
	dataPtr := unsafe.Pointer(&data[0])
	signaturePtr := signDataFunc(pk.ptr, dataPtr, uintptr(len(data)))

	if signaturePtr == nil {
		return crypto.BandersnatchSignature{}, errors.New("failed to sign data")
	}

	// Copy the signature from the pointer
	var signature crypto.BandersnatchSignature
	signatureBytes := unsafe.Slice((*byte)(signaturePtr), 96)
	copy(signature[:], signatureBytes)

	return signature, nil
}

// VerifySignature verifies a bandersnatch signature against the given data and public key
func VerifySignature(signature crypto.BandersnatchSignature, data []byte, pubKey crypto.BandersnatchPublicKey) bool {
	signaturePtr := unsafe.Pointer(&signature[0])
	dataPtr := unsafe.Pointer(&data[0])
	publicKeyPtr := unsafe.Pointer(&pubKey[0])

	// Call the Rust FFI function to verify the signature
	return verifySignatureFunc(publicKeyPtr, signaturePtr, dataPtr, uintptr(len(data)))
}

// GenerateVrfProof generates a VRF proof for the given data and context using the private key
func (pk *PrivateKey) GenerateVrfProof(data, context []byte) (crypto.VrfProof, error) {
	if len(data) == 0 || len(context) == 0 {
		return crypto.VrfProof{}, errors.New("data or context cannot be empty")
	}

	// Call the Rust FFI function to generate the VRF proof
	dataPtr := unsafe.Pointer(&data[0])
	contextPtr := unsafe.Pointer(&context[0])
	vrfProofPtr := generateVrfProofFunc(pk.ptr, dataPtr, uintptr(len(data)), contextPtr, uintptr(len(context)))

	if vrfProofPtr == nil {
		return crypto.VrfProof{}, errors.New("failed to generate VRF proof")
	}

	// Convert the result to a Go crypto.VrfProof type
	var vrfProof crypto.VrfProof
	copy(vrfProof[:], C.GoBytes(unsafe.Pointer(vrfProofPtr), C.int(crypto.VrfProofSize)))

	return vrfProof, nil
}

// VerifyVrfProof verifies a VRF proof against the given data, context, and public key
func VerifyVrfProof(proof crypto.VrfProof, data, context []byte, pubKey crypto.BandersnatchPublicKey) bool {
	if len(data) == 0 || len(context) == 0 {
		return false
	}

	dataPtr := unsafe.Pointer(&data[0])
	contextPtr := unsafe.Pointer(&context[0])
	proofPtr := unsafe.Pointer(&proof[0])
	publicKeyPtr := unsafe.Pointer(&pubKey[0])

	return verifyVrfProofFunc(publicKeyPtr, proofPtr, dataPtr, uintptr(len(data)), contextPtr, uintptr(len(context)))
}

// RingVrfSign signs the data using ring VRF
func (pk *PrivateKey) RingVrfSign(data VrfSignData) (crypto.RingVrfSignature, error) {
	// FFI call to Rust code would populate signature using ring VRF logic
	return crypto.RingVrfSignature{}, nil
}

// RingVrfVerify verifies a ring VRF signature against the given data
func RingVrfVerify(signature crypto.RingVrfSignature, data VrfSignData) bool {
	// FFI call to Rust code to verify the ring VRF signature
	return true
}

// VerifyProof verifies a zero-knowledge proof for the provided VRF data
func VerifyProof(proof crypto.VrfProof, data VrfSignData) bool {
	// FFI call to Rust code to verify the proof
	// This verification checks if the proof shows valid knowledge of a secret as per the zk-SNARK setup
	return true
}

// GenerateVrfOutput derives the high-entropy hash output from a VRF proof
func GenerateVrfOutput(proof crypto.VrfProof) (crypto.VrfOutput, error) {
	// FFI call to Rust code to derive the VRF output from the proof
	return crypto.VrfOutput{}, nil
}

// GenerateRingCommitment generates a KZG commitment for a set of public keys.
func GenerateRingCommitment(pubKeys []crypto.BandersnatchPublicKey) (crypto.RingCommitment, error) {
	// FFI call to Rust code to generate the KZG commitment
	return crypto.RingCommitment{}, nil
}

func getBandersnatchLibraryPath() (string, error) {
	var ext string
	switch runtime.GOOS {
	case "darwin":
		ext = "dylib"
	case "linux":
		ext = "so"
	default:
		return "", fmt.Errorf("GOOS=%s is not supported", runtime.GOOS)
	}

	_, filePath, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("unable to retrieve the caller info")
	}

	baseDir := filepath.Dir(filePath)
	libPath := filepath.Join(baseDir, fmt.Sprintf("../../../bandersnatch/target/release/libbandersnatch.%s", ext))

	return libPath, nil
}
