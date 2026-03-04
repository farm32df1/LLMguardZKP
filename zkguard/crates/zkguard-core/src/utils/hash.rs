//! Poseidon2 hash on Goldilocks field (2^64 − 2^32 + 1)
//!
//! Parameters (confirmed from Plonky3 source):
//!   width = 16, rate = 8, capacity = 8, S-box = x^7
//!   128-bit security from capacity side

use crate::core::types::{FieldElement, HashDigest};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use p3_field::{AbstractField, PrimeField64};
use p3_goldilocks::{DiffusionMatrixGoldilocks, Goldilocks};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::Permutation;

type F = Goldilocks;
type Perm = Poseidon2<F, Poseidon2ExternalMatrixGeneral, DiffusionMatrixGoldilocks, 16, 7>;

/// Return a reference to the singleton Poseidon2 permutation.
/// Initialized exactly once via `OnceLock`; subsequent calls are lock-free reads.
#[cfg(feature = "std")]
fn get_poseidon2() -> &'static Perm {
    use std::sync::OnceLock;
    static PERM: OnceLock<Perm> = OnceLock::new();
    PERM.get_or_init(|| {
        use crate::utils::constants::ZKGUARD_POSEIDON2_SEED;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        let mut rng = ChaCha20Rng::seed_from_u64(ZKGUARD_POSEIDON2_SEED);
        Perm::new_from_rng_128(
            Poseidon2ExternalMatrixGeneral,
            DiffusionMatrixGoldilocks,
            &mut rng,
        )
    })
}

/// Fallback for no-std: rebuild permutation each call.
#[cfg(not(feature = "std"))]
fn get_poseidon2() -> Perm {
    use crate::utils::constants::ZKGUARD_POSEIDON2_SEED;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    let mut rng = ChaCha20Rng::seed_from_u64(ZKGUARD_POSEIDON2_SEED);
    Perm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixGoldilocks,
        &mut rng,
    )
}

/// Convert up to 8 bytes into a Goldilocks field element (little-endian, mod p).
pub fn bytes_to_field(bytes: &[u8]) -> FieldElement {
    let mut v = 0u64;
    for (i, &b) in bytes.iter().take(8).enumerate() {
        v |= (b as u64) << (i * 8);
    }
    v % F::ORDER_U64
}

pub fn field_to_bytes(fe: FieldElement) -> [u8; 8] {
    fe.to_le_bytes()
}

/// Split `bytes` into 8-byte chunks and convert each to a field element.
#[cfg(feature = "alloc")]
pub fn bytes_to_fields(bytes: &[u8]) -> Vec<FieldElement> {
    bytes.chunks(8).map(bytes_to_field).collect()
}

/// Poseidon2 sponge hash with domain separation.
///
/// ```text
/// state ← [0; 16]
/// state ← Permute(domain absorbed into first RATE positions)
/// for each RATE-wide chunk of data:
///     state[..RATE] += chunk_as_field_elements
///     state ← Permute(state)
/// output ← first 4 field elements → 32 bytes (little-endian)
/// ```
pub fn poseidon_hash(data: &[u8], domain: &[u8]) -> HashDigest {
    use crate::utils::constants::{POSEIDON_RATE, POSEIDON_WIDTH};
    const WIDTH: usize = POSEIDON_WIDTH;
    const RATE: usize = POSEIDON_RATE;

    let perm = get_poseidon2();
    let mut state = [F::zero(); WIDTH];

    // 1. Domain absorption
    for (i, chunk) in domain.chunks(8).enumerate() {
        if i >= RATE {
            break;
        }
        state[i] = F::from_canonical_u64(bytes_to_field(chunk));
    }
    perm.permute_mut(&mut state);

    // 2. Data absorption
    for chunk in data.chunks(8 * RATE) {
        for (i, piece) in chunk.chunks(8).enumerate() {
            if i >= RATE {
                break;
            }
            state[i] += F::from_canonical_u64(bytes_to_field(piece));
        }
        perm.permute_mut(&mut state);
    }

    // 3. Squeeze 32 bytes from first 4 field elements
    let mut out = [0u8; 32];
    for i in 0..4 {
        let bytes = state[i].as_canonical_u64().to_le_bytes();
        out[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    out
}

/// Combine two 32-byte digests into one (zero heap allocation).
pub fn combine_hashes(left: &HashDigest, right: &HashDigest, domain: &[u8]) -> HashDigest {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    poseidon_hash(&buf, domain)
}

/// Derive a deterministic salt: `Poseidon2(seed || nonce, DOMAIN_PV_SALT)`.
#[cfg(feature = "alloc")]
pub fn derive_salt(seed: &[u8], nonce: &[u8]) -> HashDigest {
    let mut data = Vec::with_capacity(seed.len() + nonce.len());
    data.extend_from_slice(seed);
    data.extend_from_slice(nonce);
    poseidon_hash(&data, crate::utils::constants::DOMAIN_PV_SALT)
}

/// Constant-time equality for fixed-size byte arrays (prevents timing leaks).
pub fn constant_time_eq_fixed<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    let mut r = 0u8;
    for i in 0..N {
        r |= a[i] ^ b[i];
    }
    r == 0
}

/// Constant-time equality for variable-length slices.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_eq = a.len() == b.len();
    let max = a.len().max(b.len());
    let mut r = 0u8;
    for i in 0..max {
        let x = if i < a.len() { a[i] } else { 0 };
        let y = if i < b.len() { b[i] } else { 0 };
        r |= x ^ y;
    }
    len_eq && r == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let h1 = poseidon_hash(b"data", b"domain");
        let h2 = poseidon_hash(b"data", b"domain");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_domain_separation() {
        let h1 = poseidon_hash(b"data", b"ZKGUARD::A");
        let h2 = poseidon_hash(b"data", b"ZKGUARD::B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3];
        let c = [1u8, 2, 4];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[]));
    }

    #[test]
    fn test_bytes_to_field_mod_p() {
        let large = [0xFF; 8];
        let f = bytes_to_field(&large);
        assert!(f < F::ORDER_U64);
    }

    #[test]
    fn test_avalanche() {
        let d1 = [0u8; 32];
        let mut d2 = [0u8; 32];
        d2[0] = 1;
        let h1 = poseidon_hash(&d1, b"test");
        let h2 = poseidon_hash(&d2, b"test");
        let diff: u32 = h1
            .iter()
            .zip(h2.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        assert!(diff >= 64, "avalanche: only {diff} bits changed");
    }
}
