use libc::{c_int, size_t};
use std::slice;

const MAX_SHARDS: usize = 65535;

/// Reed-Solomon encode function for FFI
/// Takes sharded original data as byte array and produces recovery shards
/// Parameters:
/// - original_shards: number of original data shards
/// - original_shards_len: length of original_shards
/// - recovery_shards: number of recovery shards to generate
/// - original_shards: input byte array containing flattened shards
/// - shard_size: size of each shard in bytes
/// - recovery_shards_out: buffer to store generated and flattened recovery shards
/// - recovery_shards_out_len: length of recovery_shards_out
/// Returns 0 on success, -1 on error
#[no_mangle]
pub unsafe extern "C" fn reed_solomon_encode(
    original_shards_count: size_t,
    recovery_shards_count: size_t,
    shard_size: size_t,
    original_shards: *const u8,
    original_shards_len: size_t,
    recovery_shards_out: *mut u8,
    recovery_shards_out_len: size_t,
) -> c_int {
    match original_shards_count.checked_add(recovery_shards_count) {
        Some(sum) if sum <= MAX_SHARDS => {}
        _ => return -1,
    };

    if !(original_shards_count > 0 && recovery_shards_count > 0)
        || original_shards.is_null()
        || recovery_shards_out.is_null()
        || !(shard_size > 0 && shard_size % 2 == 0)
        || original_shards_len % shard_size != 0
        || original_shards_len / shard_size != original_shards_count
        || recovery_shards_out_len != recovery_shards_count * shard_size
    {
        return -1;
    }

    let original_shards =
        slice::from_raw_parts(original_shards, original_shards_count * shard_size)
            .chunks(shard_size);

    match reed_solomon_simd::encode(
        original_shards_count,
        recovery_shards_count,
        original_shards,
    ) {
        Ok(recovery) => {
            let output_slice =
                slice::from_raw_parts_mut(recovery_shards_out, recovery_shards_count * shard_size);

            for (i, shard) in recovery.iter().enumerate() {
                let start = i * shard_size;
                output_slice[start..start + shard_size].copy_from_slice(shard);
            }
            0
        }
        Err(_) => -1,
    }
}

/// Reed-Solomon decode function for FFI
/// Reconstructs original data shards from combination of original and recovery
/// shards. Note that only missing original shards are recovered. Any original
/// shards supplied are not recovered since we already have them.
/// Parameters:
/// - original_shards_count: number of original shards
/// - recovery_shards_count: number of recovery shards
/// - shard_size: size of each shard in bytes
/// - original_shards_data: original flattened shards
/// - original_shards_len: length of original_shards_data
/// - original_shards_indexes: indexes of original_shards_data
/// - recovery_shards_data: recovery flattened shards
/// - recovery_shards_len: length of recovery_shards_data
/// - recovery_shards_indexes: indexes of recovery_shard_data
/// - recovered_shards_out: buffer for recovered missing original shards
/// - recovered_shards_out_len: length of recovered_shards_out
/// - recovered_shards_indexes_out: buffer for indexes of recovered original shards
/// Returns 0 on success, -1 on error
#[no_mangle]
pub unsafe extern "C" fn reed_solomon_decode(
    original_shards_count: size_t,
    recovery_shards_count: size_t,
    shard_size: size_t,
    original_shards: *const u8,
    original_shards_len: size_t,
    original_shards_indexes: *const size_t,
    recovery_shards: *const u8,
    recovery_shards_len: size_t,
    recovery_shards_indexes: *const size_t,
    recovered_shards_out: *mut u8,
    recovered_shards_out_len: size_t,
    recovered_shards_indexes_out: *mut size_t,
) -> c_int {
    match original_shards_count.checked_add(recovery_shards_count) {
        Some(sum) if sum <= MAX_SHARDS => {}
        _ => return -1,
    };

    if original_shards.is_null()
        || original_shards_indexes.is_null()
        || recovery_shards.is_null()
        || recovery_shards_indexes.is_null()
        || recovered_shards_out.is_null()
        || recovered_shards_indexes_out.is_null()
        || !(original_shards_count > 0 && recovery_shards_count > 0)
        || !(shard_size > 0 && shard_size % 2 == 0)
        || original_shards_len % shard_size != 0
        || recovery_shards_len % shard_size != 0
        || recovery_shards_len % shard_size != 0
    // Expected recovered shards are original shards count - original shards
    // provided. Since we only get back missing original shards.
        || recovered_shards_out_len
            != shard_size * (original_shards_count - (original_shards_len / shard_size))
    {
        return -1;
    }

    // Create original shard pairs.
    let original_shards = slice::from_raw_parts(original_shards, original_shards_len);
    let original_shards_indexes =
        slice::from_raw_parts(original_shards_indexes, original_shards_len / shard_size);
    let original_inputs = original_shards_indexes
        .iter()
        .zip(original_shards.chunks(shard_size))
        .map(|(&idx, chunk)| (idx, chunk));

    // Create recovery shard pairs.
    let recovery_shards = slice::from_raw_parts(recovery_shards, recovery_shards_len);
    let recovery_shards_indexes =
        slice::from_raw_parts(recovery_shards_indexes, recovery_shards_len / shard_size);
    let recovery_inputs = recovery_shards_indexes
        .iter()
        .zip(recovery_shards.chunks(shard_size))
        .map(|(&idx, chunk)| (idx, chunk));

    match reed_solomon_simd::decode(
        original_shards_count,
        recovery_shards_count,
        original_inputs,
        recovery_inputs,
    ) {
        Ok(restored) => {
            let recovered_shards_out =
                slice::from_raw_parts_mut(recovered_shards_out, restored.len() * shard_size);

            let recovered_shards_indexes_out =
                slice::from_raw_parts_mut(recovered_shards_indexes_out, restored.len());

            for (i, (&shard_index, shard)) in restored.iter().enumerate() {
                let start = i * shard_size;
                recovered_shards_out[start..start + shard_size].copy_from_slice(shard);
                recovered_shards_indexes_out[i] = shard_index;
            }
            0
        }
        Err(_) => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn test_encode_success() {
        let original_shards_count = 2;
        let recovery_shards_count = 1;
        let shard_size = 4;

        let original_shards: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut recovery_shards_out: [u8; 4] = [0; 4];

        unsafe {
            let result = reed_solomon_encode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                original_shards.as_ptr(),
                original_shards.len(),
                recovery_shards_out.as_mut_ptr(),
                recovery_shards_out.len(),
            );

            assert_eq!(result, 0); // Success.
            assert_eq!(recovery_shards_out, [4, 4, 4, 12]);
        }
    }

    #[test]
    fn test_encode_minimum_shards() {
        let original_shards_count = 1;
        let recovery_shards_count = 1;
        let shard_size = 4;

        let original_shards: [u8; 4] = [1, 2, 3, 4];
        let mut recovery_shards_out: [u8; 4] = [0; 4];

        unsafe {
            let result = reed_solomon_encode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                original_shards.as_ptr(),
                original_shards.len(),
                recovery_shards_out.as_mut_ptr(),
                recovery_shards_out.len(),
            );

            assert_eq!(result, 0); // Success.
            assert_eq!(recovery_shards_out, [1, 2, 3, 4]);
        }
    }
    #[test]
    fn test_encode_invalid_shard_size() {
        let original_shards_count = 2;
        let recovery_shards_count = 1;
        let shard_size = 4;

        let original_shards: [u8; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9]; // Invalid shard size.
        let mut recovery_shards_out: [u8; 4] = [0; 4];

        unsafe {
            let result = reed_solomon_encode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                original_shards.as_ptr(),
                original_shards.len(),
                recovery_shards_out.as_mut_ptr(),
                recovery_shards_out.len(),
            );

            assert_eq!(result, -1);
        }
    }

    #[test]
    fn test_encode_mismatched_shard_count() {
        let original_shards_count = 3; // Invalid shard count.
        let recovery_shards_count = 1;
        let shard_size = 4;

        let original_shards: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut recovery_shards_out: [u8; 4] = [0; 4];

        unsafe {
            let result = reed_solomon_encode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                original_shards.as_ptr(),
                original_shards.len(),
                recovery_shards_out.as_mut_ptr(),
                recovery_shards_out.len(),
            );

            assert_eq!(result, -1);
        }
    }

    #[test]
    fn test_encode_null_pointer() {
        let original_shards_count = 2;
        let recovery_shards_count = 1;
        let shard_size = 4;

        let original_shards: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut recovery_shards_out: [u8; 4] = [0; 4];

        unsafe {
            // Test null pointer for original_shards.
            let result = reed_solomon_encode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                ptr::null(),
                original_shards.len(),
                recovery_shards_out.as_mut_ptr(),
                recovery_shards_out.len(),
            );
            assert_eq!(result, -1);

            // Test null pointer for recovery_shards_out.
            let result = reed_solomon_encode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                original_shards.as_ptr(),
                original_shards.len(),
                ptr::null_mut(),
                recovery_shards_out.len(),
            );
            assert_eq!(result, -1);
        }
    }

    #[test]
    fn test_decode_success() {
        let original_shards_count = 2;
        let recovery_shards_count = 1;
        let shard_size = 4;

        let original_shards: [u8; 4] = [5, 6, 7, 8];
        let original_shards_indexes: [usize; 1] = [1];

        let recovery_shards: [u8; 4] = [4, 4, 4, 12];
        let recovery_shards_indexes: [usize; 1] = [0];

        let mut recovered_shards_out: [u8; 4] = [0; 4];
        let mut recovered_shards_indexes_out: [usize; 1] = [0; 1];

        unsafe {
            let result = reed_solomon_decode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                original_shards.as_ptr(),
                original_shards.len(),
                original_shards_indexes.as_ptr(),
                recovery_shards.as_ptr(),
                recovery_shards.len(),
                recovery_shards_indexes.as_ptr(),
                recovered_shards_out.as_mut_ptr(),
                recovered_shards_out.len(),
                recovered_shards_indexes_out.as_mut_ptr(),
            );

            assert_eq!(result, 0); // Success
            assert_eq!(recovered_shards_out, [1, 2, 3, 4]);
            assert_eq!(recovered_shards_indexes_out, [0]);
        }
    }

    #[test]
    fn test_decode_invalid_shard_size() {
        let original_shards_count = 2;
        let recovery_shards_count = 1;
        let shard_size = 4;

        let original_shards: [u8; 5] = [5, 6, 7, 8, 9]; // Invalid shard size.
        let original_shards_indexes: [usize; 1] = [1];

        let recovery_shards: [u8; 4] = [4, 4, 4, 12];
        let recovery_shards_indexes: [usize; 1] = [0];

        let mut recovered_shards_out: [u8; 4] = [0; 4];
        let mut recovered_shards_indexes_out: [usize; 1] = [0; 1];

        unsafe {
            let result = reed_solomon_decode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                original_shards.as_ptr(),
                original_shards.len(),
                original_shards_indexes.as_ptr(),
                recovery_shards.as_ptr(),
                recovery_shards.len(),
                recovery_shards_indexes.as_ptr(),
                recovered_shards_out.as_mut_ptr(),
                recovered_shards_out.len(),
                recovered_shards_indexes_out.as_mut_ptr(),
            );

            assert_eq!(result, -1); // Failure due to invalid shard size.
        }
    }

    #[test]
    fn test_decode_mismatched_shard_count() {
        let original_shards_count = 3; // Incorrect count.
        let recovery_shards_count = 1;
        let shard_size = 4;

        let original_shards: [u8; 4] = [5, 6, 7, 8];
        let original_shards_indexes: [usize; 1] = [1];

        let recovery_shards: [u8; 4] = [4, 4, 4, 12];
        let recovery_shards_indexes: [usize; 1] = [0];

        let mut recovered_shards_out: [u8; 4] = [0; 4];
        let mut recovered_shards_indexes_out: [usize; 1] = [0; 1];

        unsafe {
            let result = reed_solomon_decode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                original_shards.as_ptr(),
                original_shards.len(),
                original_shards_indexes.as_ptr(),
                recovery_shards.as_ptr(),
                recovery_shards.len(),
                recovery_shards_indexes.as_ptr(),
                recovered_shards_out.as_mut_ptr(),
                recovered_shards_out.len(),
                recovered_shards_indexes_out.as_mut_ptr(),
            );

            assert_eq!(result, -1); // Failure due to mismatched shard count
        }
    }

    #[test]
    fn test_decode_minimum_shards() {
        let original_shards_count = 1;
        let recovery_shards_count = 1;
        let shard_size = 4;

        let recovery_shards: [u8; 4] = [1, 2, 3, 4];
        let recovery_shards_indexes: [usize; 1] = [0];

        let mut recovered_shards_out: [u8; 4] = [0; 4];
        let mut recovered_shards_indexes_out: [usize; 1] = [0; 1];

        unsafe {
            let result = reed_solomon_decode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                [].as_ptr(),
                0,
                [].as_ptr(),
                recovery_shards.as_ptr(),
                recovery_shards.len(),
                recovery_shards_indexes.as_ptr(),
                recovered_shards_out.as_mut_ptr(),
                recovered_shards_out.len(),
                recovered_shards_indexes_out.as_mut_ptr(),
            );

            assert_eq!(result, 0); // Success.
            assert_eq!(recovered_shards_out, [1, 2, 3, 4]);
            assert_eq!(recovered_shards_indexes_out, [0]);
        }
    }

    #[test]
    fn test_decode_null_pointer() {
        let original_shards_count = 2;
        let recovery_shards_count = 1;
        let shard_size = 4;

        let original_shards: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let original_shards_indexes: [usize; 2] = [0, 1];

        let recovery_shards: [u8; 4] = [9, 10, 11, 12];
        let recovery_shards_indexes: [usize; 1] = [2];

        let mut recovered_shards_out: [u8; 4] = [0; 4];
        let mut recovered_shards_indexes_out: [usize; 1] = [0; 1];

        unsafe {
            // Test null pointer for original_shards.
            let result = reed_solomon_decode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                ptr::null(),
                original_shards.len(),
                original_shards_indexes.as_ptr(),
                recovery_shards.as_ptr(),
                recovery_shards.len(),
                recovery_shards_indexes.as_ptr(),
                recovered_shards_out.as_mut_ptr(),
                recovered_shards_out.len(),
                recovered_shards_indexes_out.as_mut_ptr(),
            );
            assert_eq!(result, -1);

            // Test null pointer for original_shards_indexes.
            let result = reed_solomon_decode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                original_shards.as_ptr(),
                original_shards.len(),
                ptr::null(),
                recovery_shards.as_ptr(),
                recovery_shards.len(),
                recovery_shards_indexes.as_ptr(),
                recovered_shards_out.as_mut_ptr(),
                recovered_shards_out.len(),
                recovered_shards_indexes_out.as_mut_ptr(),
            );
            assert_eq!(result, -1);

            // Test null pointer for recovery_shards.
            let result = reed_solomon_decode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                original_shards.as_ptr(),
                original_shards.len(),
                original_shards_indexes.as_ptr(),
                ptr::null(),
                recovery_shards.len(),
                recovery_shards_indexes.as_ptr(),
                recovered_shards_out.as_mut_ptr(),
                recovered_shards_out.len(),
                recovered_shards_indexes_out.as_mut_ptr(),
            );
            assert_eq!(result, -1);

            // Test null pointer for recovery_shards_indexes.
            let result = reed_solomon_decode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                original_shards.as_ptr(),
                original_shards.len(),
                original_shards_indexes.as_ptr(),
                recovery_shards.as_ptr(),
                recovery_shards.len(),
                ptr::null(),
                recovered_shards_out.as_mut_ptr(),
                recovered_shards_out.len(),
                recovered_shards_indexes_out.as_mut_ptr(),
            );
            assert_eq!(result, -1);

            // Test null pointer for recovered_shards_out.
            let result = reed_solomon_decode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                original_shards.as_ptr(),
                original_shards.len(),
                original_shards_indexes.as_ptr(),
                recovery_shards.as_ptr(),
                recovery_shards.len(),
                recovery_shards_indexes.as_ptr(),
                ptr::null_mut(),
                recovered_shards_out.len(),
                recovered_shards_indexes_out.as_mut_ptr(),
            );
            assert_eq!(result, -1);

            // Test null pointer for recovered_shards_indexes_out.
            let result = reed_solomon_decode(
                original_shards_count,
                recovery_shards_count,
                shard_size,
                original_shards.as_ptr(),
                original_shards.len(),
                original_shards_indexes.as_ptr(),
                recovery_shards.as_ptr(),
                recovery_shards.len(),
                recovery_shards_indexes.as_ptr(),
                recovered_shards_out.as_mut_ptr(),
                recovered_shards_out.len(),
                ptr::null_mut(),
            );
            assert_eq!(result, -1);
        }
    }
}
