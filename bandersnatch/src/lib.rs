// Adatped from https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/example/src/main.rs
use ark_vrf::reexports::ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::suites::bandersnatch;
use bandersnatch::{
    BandersnatchSha512Ell2, IetfProof, Input, Output, Public, RingProof, RingProofParams, Secret,
};
use libc::{c_int, size_t};
use std::ptr;
use std::slice;
use std::sync::OnceLock;

const DEFAULT_RING_SIZE: usize = 1023;
const SECRET_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 32;
const IETF_VRF_SIGNATURE_LENGTH: usize = 96;
const IETF_VRF_HASH_OUTPUT_LENGTH: usize = 32;
const RING_VRF_COMMITMENT_LENGTH: usize = 144;
const RING_VRF_SIGNATURE_LENGTH: usize = 784;
const RING_VRF_HASH_OUTPUT_LENGTH: usize = 32;

/// This is the non-anonymous IETF `Prove` procedure output as described in
/// section 2.2 of the Bandersnatch VRFs specification. The signature is
/// effectively the output and proof together.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct IetfVrfSignature {
    /// VRF output.
    output: Output,
    /// Proof.
    proof: IetfProof,
}

/// Construct VRF Input Point from arbitrary data (section 1.2).
fn vrf_input_point(vrf_input_data: &[u8]) -> Input {
    Input::new(vrf_input_data).unwrap()
}

/// Non-Anonymous VRF signature.
///
/// Used for ticket claiming during block production.  
///
/// Only vrf_input_data affects the VRF output.
fn ietf_vrf_sign_impl(secret: Secret, vrf_input_data: &[u8], aux_data: &[u8]) -> IetfVrfSignature {
    use ark_vrf::ietf::Prover as _;

    let input = vrf_input_point(vrf_input_data);
    let output = secret.output(input);

    let proof = secret.prove(input, output, aux_data);

    // Output and IETF Proof bundled together (as per section 2.2).
    IetfVrfSignature { output, proof }
}

/// Non-Anonymous VRF signature verification.
///
/// Used for ticket claim verification during block import.
///
/// On success returns the VRF output hash. This is used for the ticket ID /
/// score.
fn ietf_vrf_verify_impl(
    public: Public,
    vrf_input_data: &[u8],
    aux_data: &[u8],
    signature: IetfVrfSignature,
) -> Result<[u8; 32], ()> {
    use ark_vrf::ietf::Verifier as _;

    let input = vrf_input_point(vrf_input_data);
    let output = signature.output;

    public
        .verify(input, output, aux_data, &signature.proof)
        .map_err(|_| ())?;

    let mut vrf_output_hash = [0u8; IETF_VRF_HASH_OUTPUT_LENGTH];
    vrf_output_hash.copy_from_slice(&output.hash()[..IETF_VRF_HASH_OUTPUT_LENGTH]);
    Ok(vrf_output_hash)
}

/// This is the anonymous IETF `Prove` procedure output as described in section
/// 4.2 of the Bandersnatch VRFs specification. The signature is effectcively
/// the output and proof together.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct RingVrfSignature {
    // VRF output.
    output: Output,
    /// This contains both the Pedersen proof and actual ring proof.
    proof: RingProof,
}

static RING_SIZE: OnceLock<usize> = OnceLock::new();

/// Initialize the ring size. This has to be called before ring_context() in
/// order to take effect, otherwise it will default to DEFAULT_RING_SIZE.
fn init_ring_size_impl(size: usize) {
    let _ = RING_SIZE.set(size);
}

/// Get the current ring size which is set once. The ring size influences the
/// commitment generated.  Test vectors use a ring size of 6 and this produces a
/// different commitment compared to a ring size of 1023.
fn ring_size() -> usize {
    *RING_SIZE.get_or_init(|| DEFAULT_RING_SIZE)
}
/// "Static" ring context data.
fn ring_proof_params() -> &'static RingProofParams {
    static PARAMS: OnceLock<RingProofParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        use bandersnatch::PcsParams;
        static EMBEDDED_RAW_PCS_PARAMS: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/data/zcash-srs-2-11-uncompressed.bin"
        ));
        let pcs_params =
            PcsParams::deserialize_uncompressed_unchecked(&mut &EMBEDDED_RAW_PCS_PARAMS[..])
                .expect("Failed to deserialize PCS parameters");
        RingProofParams::from_pcs_params(ring_size(), pcs_params)
            .expect("Failed to construct RingContext from PCS parameters")
    })
}

/// Ring VRF Prover.
///
/// Used to create anonymous ring VRF signatures.
pub struct RingVrfProver {
    /// Prover's secret key.
    pub secret: Secret,
    /// Ring of public keys.
    pub ring: Vec<Public>,
    /// Position of the corresponding Prover's public key in the ring.
    pub prover_idx: usize,
}

impl RingVrfProver {
    /// Creates a new Ring VRF Prover with the given secret key, public key
    /// ring, and prover index.  The prover index is the position of the
    /// secret's public key in the ring.
    pub fn new(secret: Secret, ring: Vec<Public>, prover_idx: usize) -> Self {
        Self {
            prover_idx,
            secret,
            ring,
        }
    }

    /// Anonymous VRF signature.
    ///
    /// The signature produced could have come from any member of the ring. Used
    /// for tickets submission.
    ///
    /// Only vrf_input_data affects the VRF output.
    pub fn sign(&self, vrf_input_data: &[u8], aux_data: &[u8]) -> RingVrfSignature {
        use ark_vrf::ring::Prover as _;

        let input = vrf_input_point(vrf_input_data);
        let output = self.secret.output(input);

        // Backend currently requires the wrapped type (plain affine points).
        let pts: Vec<_> = self.ring.iter().map(|pk| pk.0).collect();

        // Proof construction
        let prover_key = ring_proof_params().prover_key(&pts);
        let prover = ring_proof_params().prover(prover_key, self.prover_idx);
        let proof = self.secret.prove(input, output, aux_data, &prover);

        // Output and Ring Proof bundled together (as per section 2.2).
        RingVrfSignature { output, proof }
    }
}

// This is the KZG commitment in the graypaper.
type RingCommitment = ark_vrf::ring::RingCommitment<BandersnatchSha512Ell2>;

/// Ring VRF Prover.
///
/// Used to verify anonymous ring VRF signatures.
pub struct RingVrfVerifier {
    /// Ring of public keys.
    pub ring: Vec<Public>,
}

impl RingVrfVerifier {
    /// Creates a new Ring VRF Verifier with the given ring of public keys.  The
    /// verifier can verify that a given signature came from one of the members
    /// of the ring, however it cannot tell which member.
    fn new(ring: Vec<Public>) -> Self {
        Self { ring }
    }

    /// Return the KZG commitment derived from the ring of public keys. This is
    /// expensive to compute but once it's computed it can be used to more
    /// quickly verify ring signatures.
    pub fn commitment(&self) -> RingCommitment {
        // Backend currently requires the wrapped type (plain affine points)
        let pts: Vec<_> = self.ring.iter().map(|pk| pk.0).collect();
        ring_proof_params().verifier_key(&pts).commitment()
    }
    /// Anonymous VRF signature verification.
    ///
    /// Verifies a signature came from one of the members of the ring. Used for
    /// tickets verification.
    ///
    /// Uses the hopefully precomputed KZG commitment as an argument which
    /// allows cheaper verification.
    ///
    /// On success returns the VRF output hash. This is used for the ticket ID /
    /// score.
    pub fn verify(
        &self,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        commitment: RingCommitment,
        signature: RingVrfSignature,
    ) -> Result<[u8; 32], ()> {
        use ark_vrf::ring::Verifier as _;

        let input = vrf_input_point(vrf_input_data);
        let output = signature.output;

        let ring_ctx = ring_proof_params();
        // The verifier key is reconstructed from the commitment and the
        // constant verifier key component of the SRS in order to verify some
        // proof.  As an alternative we can construct the verifier key using the
        // RingContext::verifier_key() method, but is more expensive.  In other
        // words, we prefer computing the commitment once, when the keyset
        // changes.
        let verifier_key = ring_ctx.verifier_key_from_commitment(commitment);
        let verifier = ring_ctx.verifier(verifier_key);
        Public::verify(input, output, aux_data, &signature.proof, &verifier).map_err(|_| ())?;

        let mut vrf_output_hash = [0u8; RING_VRF_HASH_OUTPUT_LENGTH];
        vrf_output_hash.copy_from_slice(&output.hash()[..RING_VRF_HASH_OUTPUT_LENGTH]);
        Ok(vrf_output_hash)
    }
}

/// Sets the initial ring size.
#[no_mangle]
pub unsafe extern "C" fn init_ring_size(ring_size: size_t) -> c_int {
    init_ring_size_impl(ring_size);

    0
}

/// Gets the ring size. This will either be the ring_size set by init_ring_size,
/// or else it will default to DEFAULT_RING_SIZE.
#[no_mangle]
pub unsafe extern "C" fn get_ring_size() -> size_t {
    ring_size()
}

/// Creates a new secret key from a provided seed byte array.
///
///
/// Writes the secret to the provided secret_out byte array which is expected to
/// have a length of SECRET_LENGTH.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn new_secret(
    seed: *const u8,
    seed_len: size_t,
    secret_out: *mut u8,
) -> c_int {
    if seed.is_null() || secret_out.is_null() {
        return -1;
    }

    let seed_slice = std::slice::from_raw_parts(seed, seed_len);
    let secret = Secret::from_seed(seed_slice);
    let mut secret_buf = [0u8; SECRET_KEY_LENGTH];

    if secret.serialize_compressed(&mut secret_buf[..]).is_err() {
        return -1;
    }

    ptr::copy_nonoverlapping(secret_buf.as_ptr(), secret_out, SECRET_KEY_LENGTH);

    0
}

/// Takes a secret key byte array and produces the corresponding public key.
///
/// The public key is written to the provided public_out byte array that should
/// have a length of PUBLIC_KEY_LENGTH.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn secret_public(secret: *const u8, public_out: *mut u8) -> c_int {
    if secret.is_null() || public_out.is_null() {
        return -1;
    }

    let secret_slice = std::slice::from_raw_parts(secret, SECRET_KEY_LENGTH);

    let secret = if let Ok(s) = Secret::deserialize_compressed(secret_slice) {
        s
    } else {
        return -1;
    };

    let public = secret.public();

    let mut public_buf = [0u8; PUBLIC_KEY_LENGTH];
    if public.serialize_compressed(&mut public_buf[..]).is_err() {
        return -1;
    }

    ptr::copy_nonoverlapping(public_buf.as_ptr(), public_out, PUBLIC_KEY_LENGTH);

    0
}

/// Produces a signature using the provided secret, vrf input data, and aux data
/// byte arrays.
///
/// The signature is written to the provided signature_out byte array which
/// should have a length of IETF_VRF_SIGNATURE_LENGTH.
///
/// The secret should have a length of SECRET_KEY_LENGTH.

/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn ietf_vrf_sign(
    secret: *const u8,
    vrf_input_data: *const u8,
    vrf_input_data_len: size_t,
    aux_data: *const u8,
    aux_data_len: size_t,
    signature_out: *mut u8,
) -> c_int {
    if secret.is_null() || vrf_input_data.is_null() || aux_data.is_null() || signature_out.is_null()
    {
        return -1;
    }

    let secret_slice = slice::from_raw_parts(secret, SECRET_KEY_LENGTH);
    let vrf_input_data = slice::from_raw_parts(vrf_input_data, vrf_input_data_len);
    let aux_data = slice::from_raw_parts(aux_data, aux_data_len);

    let secret = if let Ok(s) = Secret::deserialize_compressed(secret_slice) {
        s
    } else {
        return -1;
    };

    let signature = ietf_vrf_sign_impl(secret, vrf_input_data, aux_data);

    let mut signature_buf = [0u8; IETF_VRF_SIGNATURE_LENGTH];
    if signature
        .serialize_compressed(&mut signature_buf[..])
        .is_err()
    {
        return -1;
    }

    ptr::copy_nonoverlapping(signature_buf.as_ptr(), signature_out, signature_buf.len());

    0
}

/// Verifies a signature using the supplied public key, vrf_input_data, aux_data
/// and signature byte arrays.
///
/// Produces a VRF output hash on success.
///
/// The VRF output hash is written to the provided output_hash_out byte array
/// which should have a length of IETF_VRF_HASH_OUTPUT_LENGTH.
///
/// The public key should have length PUBLIC_KEY_LENGTH and the signature should
/// have length IETF_VRF_SIGNATURE_LENGTH
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn ietf_vrf_verify(
    public_key: *const u8,
    vrf_input_data: *const u8,
    vrf_input_data_len: size_t,
    aux_data: *const u8,
    aux_data_len: size_t,
    signature: *const u8,
    output_hash_out: *mut u8,
) -> c_int {
    if public_key.is_null()
        || vrf_input_data.is_null()
        || aux_data.is_null()
        || signature.is_null()
        || output_hash_out.is_null()
    {
        return -1;
    }

    let public_key_slice = std::slice::from_raw_parts(public_key, PUBLIC_KEY_LENGTH);
    let vrf_input_data_slice = std::slice::from_raw_parts(vrf_input_data, vrf_input_data_len);
    let aux_data_slice = std::slice::from_raw_parts(aux_data, aux_data_len);
    let signature_slice = std::slice::from_raw_parts(signature, IETF_VRF_SIGNATURE_LENGTH);

    let public = if let Ok(p) = Public::deserialize_compressed(public_key_slice) {
        p
    } else {
        return -1;
    };

    let signature = if let Ok(s) = IetfVrfSignature::deserialize_compressed(signature_slice) {
        s
    } else {
        return -1;
    };

    if let Ok(vrf_output_hash) =
        ietf_vrf_verify_impl(public, vrf_input_data_slice, aux_data_slice, signature)
    {
        std::ptr::copy_nonoverlapping(
            vrf_output_hash.as_ptr(),
            output_hash_out,
            IETF_VRF_HASH_OUTPUT_LENGTH,
        );
        0
    } else {
        return -1;
    }
}

/// Produces a VRF output hash from a given signature byte array.
///
/// The output hash is written to the output_hash_out byte array which should
/// have a length of IETF_VRF_HASH_OUTPUT_LENGTH.
///
/// The signature should have a length of IETF_VRF_SIGNATURE_LENGTH.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn ietf_vrf_output_hash(
    signature: *const u8,
    output_hash_out: *mut u8,
) -> c_int {
    if signature.is_null() || output_hash_out.is_null() {
        return -1;
    }

    let signature_slice = std::slice::from_raw_parts(signature, IETF_VRF_SIGNATURE_LENGTH);

    let signature = if let Ok(s) = IetfVrfSignature::deserialize_compressed(signature_slice) {
        s
    } else {
        return -1;
    };

    let output_hash = signature.output.hash();
    std::ptr::copy_nonoverlapping(
        output_hash.as_ptr(),
        output_hash_out,
        IETF_VRF_HASH_OUTPUT_LENGTH,
    );

    0
}

/// Creates a new RingVrfVerfier from the given public_keys byte array which is
/// returned as an opaque pointer.
///
/// The public_keys byte array is expected to be a flat array of concatenated
/// public keys each of length PUBLIC_KEY_LENGTH.
#[no_mangle]
pub unsafe extern "C" fn new_ring_vrf_verifier(
    public_keys: *const u8,
    public_keys_len: size_t,
) -> *mut RingVrfVerifier {
    if public_keys.is_null() || public_keys_len % PUBLIC_KEY_LENGTH != 0 {
        return std::ptr::null_mut();
    }

    let public_keys_slice = std::slice::from_raw_parts(public_keys, public_keys_len);
    let num_keys = public_keys_len / PUBLIC_KEY_LENGTH;

    let padding_point = Public::from(RingProofParams::padding_point());
    let ring: Vec<Public> = public_keys_slice
        .chunks(PUBLIC_KEY_LENGTH)
        // Invalid public keys become padding points.
        .map(|chunk| Public::deserialize_compressed(chunk).unwrap_or(padding_point))
        .collect();

    if ring.len() != num_keys {
        return std::ptr::null_mut();
    }

    Box::into_raw(Box::new(RingVrfVerifier::new(ring)))
}

/// Idempotently frees the boxed memory from a previously constructed
/// RingVrfVerifier. Accepts an opaque pointer to a RingVrfVerfier.
#[no_mangle]
pub unsafe extern "C" fn free_ring_vrf_verifier(verifier: *mut RingVrfVerifier) {
    if !verifier.is_null() {
        drop(Box::from_raw(verifier))
    }
}

/// Produces the KZG commitment from a given RingVrfVerifier opaque pointer.
///
/// Writes the commitment to the commitment_out byte array which should be length
/// RING_VRF_COMMITMENT_LENGTH.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn ring_vrf_verifier_commitment(
    verifier: *mut RingVrfVerifier,
    commitment_out: *mut u8,
) -> c_int {
    if verifier.is_null() || commitment_out.is_null() {
        return -1;
    }

    let commitment = (&*verifier).commitment();

    let mut commitment_buf = [0u8; RING_VRF_COMMITMENT_LENGTH];
    if commitment
        .serialize_compressed(&mut commitment_buf[..])
        .is_err()
    {
        return -1;
    }

    std::ptr::copy_nonoverlapping(
        commitment_buf.as_ptr(),
        commitment_out,
        RING_VRF_COMMITMENT_LENGTH,
    );

    0
}

/// Produces a VRF output hash from a given signature byte array.
///
/// The output hash is written to the output_hash_out byte array which should
/// have a length of RING_VRF_HASH_OUTPUT_LENGTH.
///
/// The signature should have a length of RING_VRF_SIGNATURE_LENGTH.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn ring_vrf_output_hash(
    signature: *const u8,
    output_hash_out: *mut u8,
) -> c_int {
    if signature.is_null() || output_hash_out.is_null() {
        return -1;
    }

    let signature_slice = std::slice::from_raw_parts(signature, RING_VRF_SIGNATURE_LENGTH);

    let signature = if let Ok(s) = RingVrfSignature::deserialize_compressed(signature_slice) {
        s
    } else {
        return -1;
    };

    let output_hash = signature.output.hash();
    std::ptr::copy_nonoverlapping(
        output_hash.as_ptr(),
        output_hash_out,
        RING_VRF_HASH_OUTPUT_LENGTH,
    );

    0
}

/// Verifies a signature using the supplied RingVrfVerifier opaque pointer along
/// with vrf_input_data, aux_data, commitment and signature byte arrays.
///
/// Produces a VRF output hash on success.
///
/// The VRF output hash is written to the provided output_hash_out byte array
/// which should have a length of RING_VRF_HASH_OUTPUT_LENGTH.
///
/// The commitment should have length RING_VRF_COMMITMENT_LENGTH and signature
/// should have length RING_VRF_SIGNATURE_LENGTH.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn ring_vrf_verifier_verify(
    verifier: *mut RingVrfVerifier,
    vrf_input_data: *const u8,
    vrf_input_data_len: size_t,
    aux_data: *const u8,
    aux_data_len: size_t,
    commitment: *const u8,
    signature: *const u8,
    output_hash_out: *mut u8,
) -> c_int {
    if verifier.is_null()
        || vrf_input_data.is_null()
        || aux_data.is_null()
        || commitment.is_null()
        || signature.is_null()
        || output_hash_out.is_null()
    {
        return -1;
    }

    let vrf_input_data = std::slice::from_raw_parts(vrf_input_data, vrf_input_data_len);
    let aux_data = std::slice::from_raw_parts(aux_data, aux_data_len);
    let commitment_slice = std::slice::from_raw_parts(commitment, RING_VRF_COMMITMENT_LENGTH);
    let signature_slice = std::slice::from_raw_parts(signature, RING_VRF_SIGNATURE_LENGTH);

    let commitment = if let Ok(c) = RingCommitment::deserialize_compressed(commitment_slice) {
        c
    } else {
        return -1;
    };

    let signature = if let Ok(s) = RingVrfSignature::deserialize_compressed(signature_slice) {
        s
    } else {
        return -1;
    };

    if let Ok(vrf_output_hash) =
        (&*verifier).verify(vrf_input_data, aux_data, commitment, signature)
    {
        std::ptr::copy_nonoverlapping(
            vrf_output_hash.as_ptr(),
            output_hash_out,
            RING_VRF_HASH_OUTPUT_LENGTH,
        );
        0
    } else {
        return -1;
    }
}

/// Creates a new RingVrfProver from the given secret and public_keys byte arrays
/// and a prover_idx. Returns an opaque pointer to a RingVrfProver.
///
/// The secret is expected to have a length of SECRET_KEY_LENGTH.

/// The public_keys byte array is expected to be a flat array of concatenated
/// public keys each of length PUBLIC_KEY_LENGTH.
#[no_mangle]
pub unsafe extern "C" fn new_ring_vrf_prover(
    secret: *const u8,
    public_keys: *const u8,
    public_keys_len: size_t,
    prover_idx: usize,
) -> *mut RingVrfProver {
    if secret.is_null() || public_keys.is_null() || public_keys_len % PUBLIC_KEY_LENGTH != 0 {
        return std::ptr::null_mut();
    }

    let secret_slice = std::slice::from_raw_parts(secret, SECRET_KEY_LENGTH);
    let public_keys_slice = std::slice::from_raw_parts(public_keys, public_keys_len);

    let secret = if let Ok(s) = Secret::deserialize_compressed(secret_slice) {
        s
    } else {
        return std::ptr::null_mut();
    };

    let num_keys = public_keys_len / PUBLIC_KEY_LENGTH;

    let padding_point = Public::from(RingProofParams::padding_point());
    let ring: Vec<Public> = public_keys_slice
        .chunks(PUBLIC_KEY_LENGTH)
        // Invalid public keys become padding points.
        .map(|chunk| Public::deserialize_compressed(chunk).unwrap_or(padding_point))
        .collect();

    if ring.len() != num_keys {
        return std::ptr::null_mut();
    }

    Box::into_raw(Box::new(RingVrfProver::new(secret, ring, prover_idx)))
}

/// Idempotently frees the boxed memory from a previously constructed
/// RingVrfProver. Accepts an opaque pointer to a RingVrfProver.
#[no_mangle]
pub unsafe extern "C" fn free_ring_vrf_prover(prover: *mut RingVrfProver) {
    if !prover.is_null() {
        drop(Box::from_raw(prover))
    }
}

/// Produces a signature using the provided RingVrfProver opaque pointer along
/// with secret, vrf input data, and aux data byte arrays.
///
/// The signature is written to the provided signature_out byte array which
/// should have a length of RING_VRF_SIGNATURE_LENGTH.
///
/// The secret should have a length of SECRET_KEY_LENGTH.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn ring_vrf_prover_sign(
    prover: *mut RingVrfProver,
    vrf_input_data: *const u8,
    vrf_input_data_len: size_t,
    aux_data: *const u8,
    aux_data_len: size_t,
    signature_out: *mut u8,
) -> c_int {
    if prover.is_null() || vrf_input_data.is_null() || aux_data.is_null() || signature_out.is_null()
    {
        return -1;
    }

    let prover = &*prover;
    let vrf_input_data = std::slice::from_raw_parts(vrf_input_data, vrf_input_data_len);
    let aux_data = std::slice::from_raw_parts(aux_data, aux_data_len);

    let signature = prover.sign(vrf_input_data, aux_data);

    let mut signature_buf = [0u8; RING_VRF_SIGNATURE_LENGTH];
    if signature
        .serialize_compressed(&mut signature_buf[..])
        .is_err()
    {
        return -1;
    }

    std::ptr::copy_nonoverlapping(signature_buf.as_ptr(), signature_out, signature_buf.len());

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandersnatch_vrf() {
        let mut ring: Vec<_> = (0..ring_size())
            .map(|i| Secret::from_seed(&i.to_le_bytes()).public())
            .collect();
        let prover_key_index: usize = 3;

        // NOTE: any key can be replaced with the padding point
        let padding_point = Public::from(RingProofParams::padding_point());
        ring[2] = padding_point;
        ring[7] = padding_point;

        let prover_secret = Secret::from_seed(&prover_key_index.to_le_bytes());

        let prover = RingVrfProver::new(prover_secret.clone(), ring.clone(), prover_key_index);

        let verifier = RingVrfVerifier::new(ring);

        let commitment = verifier.commitment();

        let vrf_input_data = b"foo";

        //--- Anonymous VRF

        let aux_data = b"bar";

        // Prover signs some data.
        let ring_signature = prover.sign(vrf_input_data, aux_data);

        // Verifier checks it without knowing who is the signer.
        let ring_vrf_output = verifier
            .verify(
                vrf_input_data,
                aux_data,
                commitment.clone(),
                ring_signature.clone(),
            )
            .unwrap();

        //--- Non anonymous VRF

        let other_aux_data = b"hello";

        // Prover signs the same vrf-input data (we want the output to match)
        // But different aux data.
        let ietf_signature =
            ietf_vrf_sign_impl(prover_secret.clone(), vrf_input_data, other_aux_data);

        // Verifier checks the signature knowing the signer identity.
        let ietf_vrf_output = ietf_vrf_verify_impl(
            prover_secret.clone().public(),
            vrf_input_data,
            other_aux_data,
            ietf_signature.clone(),
        )
        .unwrap();

        // Should match
        assert_eq!(ring_vrf_output, ietf_vrf_output);
    }
}
