//! Core types: Proof, Witness (zeroize on drop), PublicInputs, CommittedPublicInputs

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A STARK proof. Contains serialized proof bytes and version tag.
/// No epoch field — MTD has been removed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof {
    #[cfg(feature = "alloc")]
    pub data: Vec<u8>,
    pub version: u8,
}

impl Default for Proof {
    fn default() -> Self {
        Self {
            #[cfg(feature = "alloc")]
            data: Vec::new(),
            version: 1,
        }
    }
}

impl Proof {
    #[cfg(feature = "alloc")]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, version: 1 }
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Secret witness data.  Memory is zeroed on drop via zeroize.
/// Never implement `Clone` — prevents accidental copies of secret data.
#[derive(Default)]
pub struct Witness {
    #[cfg(feature = "alloc")]
    pub data: Vec<u64>,
}

impl core::fmt::Debug for Witness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Witness")
            .field("len", &self.data.len())
            .field("data", &"<redacted>")
            .finish()
    }
}

impl Zeroize for Witness {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl ZeroizeOnDrop for Witness {}

impl Drop for Witness {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Witness {
    #[cfg(feature = "alloc")]
    pub fn new(data: Vec<u64>) -> Self {
        Self { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    #[cfg(feature = "alloc")]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        use crate::utils::hash::bytes_to_fields;
        Self {
            data: bytes_to_fields(bytes),
        }
    }
}

/// Public inputs passed alongside a proof during verification.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicInputs {
    #[cfg(feature = "alloc")]
    pub data: Vec<u64>,
}

impl PublicInputs {
    #[cfg(feature = "alloc")]
    pub fn new(data: Vec<u64>) -> Self {
        Self { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

pub type FieldElement = u64;
pub type HashDigest = [u8; 32];

/// Privacy-preserving commitment to public values.
///
/// `commitment = Poseidon2(public_values_bytes || salt, DOMAIN_PV_COMMIT)`
///
/// Only the commitment needs to reach the verifier — the actual values and
/// salt can stay private.  Erasing the salt makes the commitment irreversible
/// (useful for GDPR "right to erasure").
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CommittedPublicInputs {
    pub commitment: HashDigest,
    pub value_count: u32,
}

impl CommittedPublicInputs {
    /// Commit to `public_values` using `salt`.
    #[cfg(feature = "alloc")]
    pub fn commit(public_values: &[u64], salt: &[u8; 32]) -> Self {
        use crate::utils::constants::DOMAIN_PV_COMMIT;
        use crate::utils::hash::poseidon_hash;

        let mut data = Vec::with_capacity(public_values.len() * 8 + 32);
        for &v in public_values {
            data.extend_from_slice(&v.to_le_bytes());
        }
        data.extend_from_slice(salt);

        Self {
            commitment: poseidon_hash(&data, DOMAIN_PV_COMMIT),
            value_count: public_values.len() as u32,
        }
    }

    /// Returns `true` iff `public_values` and `salt` reproduce this commitment.
    /// Uses constant-time comparison to prevent timing side-channels.
    #[cfg(feature = "alloc")]
    pub fn verify(&self, public_values: &[u64], salt: &[u8; 32]) -> bool {
        if public_values.len() as u32 != self.value_count {
            return false;
        }
        let recomputed = Self::commit(public_values, salt);
        crate::utils::hash::constant_time_eq_fixed(&self.commitment, &recomputed.commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_proof_default() {
        let p = Proof::default();
        assert!(p.is_empty());
        assert_eq!(p.version, 1);
    }

    #[test]
    fn test_witness_zeroize() {
        let mut w = Witness::new(vec![1, 2, 3]);
        w.zeroize();
        for &v in &w.data {
            assert_eq!(v, 0);
        }
    }

    #[test]
    fn test_committed_round_trip() {
        let vals = vec![1u64, 1, 2, 3, 5];
        let salt = [7u8; 32];
        let c = CommittedPublicInputs::commit(&vals, &salt);
        assert!(c.verify(&vals, &salt));
        assert!(!c.verify(&[9u64], &salt));
        assert!(!c.verify(&vals, &[0u8; 32]));
    }

    #[test]
    fn test_committed_deterministic() {
        let vals = vec![42u64];
        let salt = [1u8; 32];
        assert_eq!(
            CommittedPublicInputs::commit(&vals, &salt),
            CommittedPublicInputs::commit(&vals, &salt)
        );
    }
}
