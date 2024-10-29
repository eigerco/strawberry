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
	ringVrfVerifierCommitment func(ringVrfVerifier unsafe.Pointer, commitmentOut []byte)
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
	purego.RegisterLibFunc(&newSecret, lib, "new_secret")
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
}

func NewPrivateKeyFromSeed(seed crypto.BandersnatchSeedKey) (privateKey crypto.BandersnatchPrivateKey, err error) {
	result := newSecret(seed[:], C.size_t(len(seed)), privateKey[:])
	if result != 0 {
		return crypto.BandersnatchPrivateKey{}, errors.New("error generating private key")
	}
	return privateKey, nil
}

func Public(secret crypto.BandersnatchPrivateKey) (publicKey crypto.BandersnatchPublicKey, err error) {
	result := secretPublic(secret[:], publicKey[:])
	if result != 0 {
		return crypto.BandersnatchPublicKey{}, errors.New("error generating private key")
	}
	return publicKey, nil
}

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

func Verify(
	public crypto.BandersnatchPublicKey,
	vrfInput []byte,
	auxData []byte,
	signature crypto.BandersnatchSignature,
) (valid bool, outputHash crypto.BandersnatchOutputHash) {
	result := ietfVrfVerify(
		public[:],
		vrfInput,
		C.size_t(len(vrfInput)),
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

func OutputHash(signature crypto.BandersnatchSignature) (outputHash crypto.BandersnatchOutputHash, err error) {
	result := ietfVrfOutputHash(signature[:], outputHash[:])
	if result != 0 {
		return crypto.BandersnatchOutputHash{}, errors.New("error getting output hash")
	}
	return outputHash, nil
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
