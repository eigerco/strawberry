use libc::{c_int, size_t};
use std::slice;

/// Reed-Solomon encode function for FFI
/// Takes sharded original data as byte array and produces recovery shards
/// Parameters:
/// - original_shards: number of original data shards
/// - recovery_shards: number of recovery shards to generate
/// - original_shards: input byte array containing flattened shards
/// - shard_size: size of each shard in bytes
/// - recovery_shards_out: buffer to store generated and flattened recovery shards
/// Returns 0 on success, -1 on error
#[no_mangle]
pub unsafe extern "C" fn reed_solomon_encode(
    original_shards_count: size_t,
    recovery_shards_count: size_t,
    shard_size: size_t,
    original_shards: *const u8,
    recovery_shards_out: *mut u8,
) -> c_int {
    let original_shards: Vec<_> = slice::from_raw_parts(
        original_shards,
        original_shards_count as usize * shard_size as usize,
    )
    .chunks(shard_size as usize)
    .collect();

    match reed_solomon_simd::encode(
        original_shards_count as usize,
        recovery_shards_count as usize,
        original_shards,
    ) {
        Ok(recovery) => {
            let output_slice = slice::from_raw_parts_mut(
                recovery_shards_out,
                recovery_shards_count as usize * shard_size as usize,
            );

            for (i, shard) in recovery.iter().enumerate() {
                let start = i * shard_size as usize;
                let end = start + shard_size as usize;
                output_slice[start..end].copy_from_slice(shard);
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
    recovered_shards_indexes_out: *mut size_t,
) -> c_int {
    // Create original shard pairs
    let orig_data = slice::from_raw_parts(original_shards, original_shards_len);
    let orig_indexes =
        slice::from_raw_parts(original_shards_indexes, original_shards_len / shard_size);
    let original_inputs = orig_indexes
        .iter()
        .zip(orig_data.chunks(shard_size))
        .map(|(&idx, chunk)| (idx, chunk));

    // Create recovery shard pairs
    let rec_data = slice::from_raw_parts(recovery_shards, recovery_shards_len);
    let rec_indexes =
        slice::from_raw_parts(recovery_shards_indexes, recovery_shards_len / shard_size);
    let recovery_inputs = rec_indexes
        .iter()
        .zip(rec_data.chunks(shard_size))
        .map(|(&idx, chunk)| (idx, chunk));

    match reed_solomon_simd::decode(
        original_shards_count,
        recovery_shards_count,
        original_inputs,
        recovery_inputs,
    ) {
        Ok(restored) => {
            let shards_recovered_out =
                slice::from_raw_parts_mut(recovered_shards_out, restored.len() * shard_size);

            let shards_recovered_indexes_out =
                slice::from_raw_parts_mut(recovered_shards_indexes_out, restored.len());

            for (i, (&shard_index, shard_data)) in restored.iter().enumerate() {
                let start = i * shard_size;
                let end = start + shard_size;
                shards_recovered_out[start..end].copy_from_slice(shard_data);
                shards_recovered_indexes_out[i] = shard_index;
            }
            0
        }
        Err(_) => -1,
    }
}
