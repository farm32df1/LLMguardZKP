pub mod merkle;

pub use merkle::{MerklePath, MerkleTree};

use crate::core::errors::{Result, ZKGuardError};
use crate::utils::constants::DOMAIN_PROOF_INTEGRITY;
use crate::utils::constants::MAX_BATCH_SIZE;
use crate::utils::hash::poseidon_hash;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// A set of STARK proofs aggregated under a single Merkle root.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct ProofBatch {
    pub proof_hashes: Vec<[u8; 32]>,
    pub merkle_root: [u8; 32],
}

#[cfg(feature = "alloc")]
impl ProofBatch {
    /// Build a batch from raw proof byte slices.
    pub fn new(proofs: &[&[u8]]) -> Result<Self> {
        if proofs.is_empty() {
            return Err(ZKGuardError::BatchError {
                reason: "empty batch".into(),
            });
        }
        if proofs.len() > MAX_BATCH_SIZE {
            return Err(ZKGuardError::ResourceLimitExceeded {
                reason: alloc::format!("batch size {} > {}", proofs.len(), MAX_BATCH_SIZE),
            });
        }
        let leaves: Vec<[u8; 32]> = proofs
            .iter()
            .map(|p| poseidon_hash(p, DOMAIN_PROOF_INTEGRITY))
            .collect();
        let tree = MerkleTree::new(leaves.clone())?;
        Ok(Self {
            proof_hashes: leaves,
            merkle_root: tree.root()?,
        })
    }

    pub fn len(&self) -> usize {
        self.proof_hashes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.proof_hashes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_creation() {
        let data: Vec<alloc::vec::Vec<u8>> = (0..4).map(|i| alloc::vec![i; 32]).collect();
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let batch = ProofBatch::new(&refs).unwrap();
        assert_eq!(batch.len(), 4);
    }

    #[test]
    fn test_empty_batch_error() {
        assert!(ProofBatch::new(&[]).is_err());
    }
}
