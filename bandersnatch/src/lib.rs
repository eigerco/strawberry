use sp_core::bandersnatch::{Pair, Public, Signature,  SIGNING_CTX};
use sp_core::bandersnatch::vrf::{VrfSignData, VrfInput, VrfSignature};
use sp_core::crypto::{Pair as TraitPair, VrfPublic};
use sp_core::crypto::VrfSecret;
use std::slice;
use std::ptr;

const SEED_SERIALIZED_SIZE: usize = 32;

#[no_mangle]
pub extern "C" fn new_private_key_from_seed(seed_ptr: *const u8, seed_len: usize) -> *mut Pair {
    if seed_len != SEED_SERIALIZED_SIZE {
        return ptr::null_mut();
    }

    // Convert the seed from the pointer
    let seed_slice = unsafe { slice::from_raw_parts(seed_ptr, seed_len) };
    let seed_array = match <[u8; SEED_SERIALIZED_SIZE]>::try_from(seed_slice) {
        Ok(seed) => seed,
        Err(_) => return ptr::null_mut(),
    };

    // Generate the key pair from the seed
    let pair = match Pair::from_seed_slice(&seed_array) {
        Ok(p) => p,
        Err(_) => return ptr::null_mut(),
    };

    // Return a pointer to the Pair struct
    Box::into_raw(Box::new(pair))
}

#[no_mangle]
pub extern "C" fn get_public_key(pair_ptr: *mut Pair) -> *mut Public {
    let pair = unsafe { &*pair_ptr };
    let public = pair.public();
    Box::into_raw(Box::new(public))
}

#[no_mangle]
pub extern "C" fn sign_data(pair_ptr: *mut Pair, data_ptr: *const u8, data_len: usize) -> *mut Signature {
    if pair_ptr.is_null() || data_ptr.is_null() {
        return ptr::null_mut();
    }

    let pair = unsafe { &*pair_ptr };
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };

    // Create the VrfSignData context
    let sign_data = VrfSignData::new_unchecked(SIGNING_CTX, &[data], None);

    // Perform the signing operation
    let signature = pair.vrf_sign(&sign_data).signature;

    // Return a pointer to the signature
    Box::into_raw(Box::new(signature))
}

#[no_mangle]
pub extern "C" fn verify_signature(
    public_ptr: *const Public,
    signature_ptr: *const Signature,
    data_ptr: *const u8,
    data_len: usize
) -> bool {
    if public_ptr.is_null() || signature_ptr.is_null() || data_ptr.is_null() {
        return false; // Invalid input
    }

    let public = unsafe { &*public_ptr };
    let signature = unsafe { &*signature_ptr };
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };

    Pair::verify(signature, data, public)
}

#[no_mangle]
pub extern "C" fn generate_vrf_proof(
    pair_ptr: *mut Pair,
    data_ptr: *const u8,
    data_len: usize,
    context_ptr: *const u8,
    context_len: usize,
) -> *mut VrfSignature {
    let pair = unsafe { &*pair_ptr };
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };

    let context = extract_vrf_context(context_ptr, context_len);

    // Create a VRF sign context
    let sign_data = VrfSignData::new_unchecked(SIGNING_CTX, &[data], context.into_iter());

    // Sign the data to generate a VRF proof
    let vrf_signature = pair.vrf_sign(&sign_data);

    Box::into_raw(Box::new(vrf_signature))
}

#[no_mangle]
pub extern "C" fn verify_vrf_proof(
    public_ptr: *mut Public,
    proof_ptr: *mut VrfSignature,
    data_ptr: *const u8,
    data_len: usize,
    context_ptr: *const u8,
    context_len: usize,
) -> bool {
    let public = unsafe { &*public_ptr };
    let proof = unsafe { &*proof_ptr };
    let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };

    let context = extract_vrf_context(context_ptr, context_len);

    // Create the sign data context
    let sign_data = VrfSignData::new_unchecked(SIGNING_CTX, &[data], context.into_iter());

    // Verify the VRF proof
    public.vrf_verify(&sign_data, proof)
}

fn extract_vrf_context(context_ptr: *const u8, context_len: usize) -> Option<VrfInput> {
    if context_len > 0 {
        let context_data = unsafe { slice::from_raw_parts(context_ptr, context_len) };
        return Some(VrfInput::new(SIGNING_CTX, context_data));
    }

    None
}
