//! Proof compression — RLE only (no external deps).
//! MAX_RLE_DECOMPRESSED_SIZE guards against decompression bombs.

use crate::core::errors::{Result, ZKGuardError};
use crate::utils::constants::MAX_RLE_DECOMPRESSED_SIZE;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    None,
    Rle,
}

/// Choose an algorithm based on data size.
pub fn select_algorithm(size: usize) -> CompressionAlgorithm {
    use crate::utils::constants::RLE_SIZE_THRESHOLD;
    if size > RLE_SIZE_THRESHOLD {
        CompressionAlgorithm::Rle
    } else {
        CompressionAlgorithm::None
    }
}

#[cfg(feature = "alloc")]
pub fn compress_rle(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let byte = data[i];
        let mut run = 1usize;
        while i + run < data.len() && data[i + run] == byte && run < 255 {
            run += 1;
        }
        out.push(run as u8);
        out.push(byte);
        i += run;
    }
    out
}

#[cfg(feature = "alloc")]
pub fn decompress_rle(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let run = data[i] as usize;
        let byte = data[i + 1];
        if out.len() + run > MAX_RLE_DECOMPRESSED_SIZE {
            return Err(ZKGuardError::ResourceLimitExceeded {
                reason: alloc::format!(
                    "RLE decompressed size would exceed {} bytes",
                    MAX_RLE_DECOMPRESSED_SIZE
                ),
            });
        }
        for _ in 0..run {
            out.push(byte);
        }
        i += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rle_round_trip() {
        let data = alloc::vec![1u8, 1, 1, 2, 3, 3];
        let compressed = compress_rle(&data);
        let decompressed = decompress_rle(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_rle_decompression_bomb() {
        // 2 bytes that claim to expand to 255 bytes each, repeated many times
        let pairs = 1 + MAX_RLE_DECOMPRESSED_SIZE / 255;
        let mut bomb = alloc::vec![];
        for _ in 0..pairs {
            bomb.push(255u8);
            bomb.push(0u8);
        }
        assert!(decompress_rle(&bomb).is_err());
    }
}
