//! Constants — cryptographic parameters and domain separation tags
//!
//! All magic numbers and thresholds are centralized here so that every module
//! references a single source of truth.

// ── Size limits ──────────────────────────────────────────────────────────────
/// Minimum accepted proof byte size (DoS guard against trivially small payloads).
pub const MIN_PROOF_SIZE: usize = 1024;
/// Maximum accepted proof byte size (DoS guard, 1 MB).
pub const MAX_PROOF_SIZE: usize = 1024 * 1024;
pub const MIN_WITNESS_SIZE: usize = 4;
pub const MAX_WITNESS_SIZE: usize = 1024 * 1024;
/// RLE decompression bomb guard (10 MB).
pub const MAX_RLE_DECOMPRESSED_SIZE: usize = 10 * 1024 * 1024;
pub const MIN_PUBLIC_INPUTS_SIZE: usize = 1;
pub const MAX_PUBLIC_INPUTS_SIZE: usize = 256;
pub const MAX_BATCH_SIZE: usize = 1000;

// ── Poseidon2 parameters ─────────────────────────────────────────────────────
/// Deterministic seed for Poseidon2 permutation matrix generation.
/// ASCII "ZKGUARD2" = 0x5A4B47554152443_2 → kept compatible with zkpmtd seed
/// to maintain proof portability if needed.
pub const ZKGUARD_POSEIDON2_SEED: u64 = 0x5A4B_4755_4152_4432;
/// Poseidon2 state width (= rate + capacity).
pub const POSEIDON_WIDTH: usize = 16;
/// Poseidon2 absorption rate (elements per permutation call).
pub const POSEIDON_RATE: usize = 8;
/// Squeeze output size in bytes (4 field elements × 8 bytes).
pub const POSEIDON_OUTPUT_SIZE: usize = 32;

// ── STARK / FRI parameters ────────────────────────────────────────────────────
// 128-bit soundness: log_blowup=2 (2 bits/query) × 60 queries = 120 bits + 8 PoW bits
pub const FRI_FOLDING_FACTOR: usize = 4;
/// log2 of the blowup factor for FRI.
pub const FRI_LOG_BLOWUP: usize = 2;
/// Number of FRI query repetitions.
pub const FRI_NUM_QUERIES: usize = 60;
/// Proof-of-work grinding bits for FRI.
pub const FRI_POW_BITS: usize = 8;

// ── STARK config validation bounds ───────────────────────────────────────────
pub const SECURITY_BITS_MIN: usize = 80;
pub const SECURITY_BITS_MAX: usize = 256;
pub const FRI_QUERIES_MIN: usize = 20;
pub const FRI_QUERIES_MAX: usize = 500;
pub const GRINDING_BITS_MAX: usize = 30;
pub const TRACE_HEIGHT_MIN: usize = 64;

// ── Compression ──────────────────────────────────────────────────────────────
/// Data size threshold above which RLE compression is applied.
pub const RLE_SIZE_THRESHOLD: usize = 512;

// ── Handle / key parameters ──────────────────────────────────────────────────
/// Size of the opaque handle identifier in bytes.
pub const HANDLE_ID_BYTES: usize = 16;
/// Maximum number of entries allowed in a vault file (DoS guard).
pub const MAX_VAULT_ENTRIES: usize = 10_000;
/// Size of the binding buffer: HANDLE_ID_BYTES + POSEIDON_OUTPUT_SIZE.
pub const HANDLE_BINDING_SIZE: usize = HANDLE_ID_BYTES + POSEIDON_OUTPUT_SIZE;

// ── Vault encryption parameters ─────────────────────────────────────────────
/// Argon2id salt length in bytes.
pub const VAULT_ARGON2_SALT_LEN: usize = 32;
/// Argon2id default memory cost in KiB (64 MiB).
pub const VAULT_ARGON2_M_COST: u32 = 65_536;
/// Argon2id default time cost (iterations).
pub const VAULT_ARGON2_T_COST: u32 = 3;
/// Argon2id default parallelism.
pub const VAULT_ARGON2_P_COST: u32 = 1;
/// AES-256-GCM nonce length in bytes (96 bits).
pub const VAULT_AES_NONCE_LEN: usize = 12;
/// AES-256 key length in bytes.
pub const VAULT_AES_KEY_LEN: usize = 32;
/// Maximum encrypted vault file size (16 MiB, DoS guard).
pub const MAX_ENCRYPTED_VAULT_SIZE: usize = 16 * 1024 * 1024;

// ── Scanner / entropy parameters ─────────────────────────────────────────────
/// Shannon entropy threshold for unknown-format key detection.
pub const ENTROPY_THRESHOLD: f64 = 4.5;
/// Minimum token length considered for entropy scanning.
pub const ENTROPY_MIN_TOKEN_LEN: usize = 40;
/// Maximum token length considered for entropy scanning.
pub const ENTROPY_MAX_TOKEN_LEN: usize = 200;

// ── KeyCommitAir parameters ──────────────────────────────────────────────────
/// Trace width for the key commitment AIR circuit: [value, eval, alpha_power].
pub const KEY_COMMIT_WIDTH: usize = 3;
/// Maximum number of field elements in a key commitment proof.
pub const MAX_KEY_ELEMENTS: usize = 512;

// ── Domain separation tags (NIST SP 800-185) ─────────────────────────────────
// Every Poseidon2 call uses a distinct domain tag to prevent cross-context
// hash collisions.  All tags start with "ZKGUARD::" for namespacing.

pub const DOMAIN_PROOF_GENERATION: &[u8] = b"ZKGUARD::ProofGeneration";
pub const DOMAIN_PROOF_VERIFICATION: &[u8] = b"ZKGUARD::ProofVerification";
pub const DOMAIN_MERKLE: &[u8] = b"ZKGUARD::Merkle";
pub const DOMAIN_COMMITMENT: &[u8] = b"ZKGUARD::Commitment";

// Committed public value domains
pub const DOMAIN_PV_COMMIT: &[u8] = b"ZKGUARD::PV::Commit";
pub const DOMAIN_PV_SALT: &[u8] = b"ZKGUARD::PV::Salt";
pub const DOMAIN_BINDING: &[u8] = b"ZKGUARD::Binding";

// Privacy / credential domains
pub const DOMAIN_CREDENTIAL: &[u8] = b"ZKGUARD::Privacy::Credential";
pub const DOMAIN_IDENTITY: &[u8] = b"ZKGUARD::Privacy::Identity";
pub const DOMAIN_FINANCIAL: &[u8] = b"ZKGUARD::Privacy::Financial";

// LLM guard domains  (used only when feature = "llm-guard")
pub const DOMAIN_KEY_COMMIT: &[u8] = b"ZKGUARD::LLMGuard::KeyCommit";
pub const DOMAIN_KEY_HANDLE: &[u8] = b"ZKGUARD::LLMGuard::Handle";
pub const DOMAIN_AUDIT_ENTRY: &[u8] = b"ZKGUARD::LLMGuard::AuditEntry";

// Vault encryption domain
pub const DOMAIN_VAULT_ENCRYPT: &[u8] = b"ZKGUARD::LLMGuard::VaultEncrypt";

// Internal utility domains
pub const DOMAIN_COMPRESSION_CHECKSUM: &[u8] = b"ZKGUARD::CompressionChecksum";
pub const DOMAIN_PROOF_INTEGRITY: &[u8] = b"ZKGUARD::ProofIntegrity";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_constants_ordered() {
        const { assert!(MIN_PROOF_SIZE < MAX_PROOF_SIZE) };
        const { assert!(MIN_WITNESS_SIZE < MAX_WITNESS_SIZE) };
        const { assert!(MIN_PUBLIC_INPUTS_SIZE < MAX_PUBLIC_INPUTS_SIZE) };
    }

    #[test]
    fn test_derived_constants_consistent() {
        const { assert!(HANDLE_BINDING_SIZE == HANDLE_ID_BYTES + POSEIDON_OUTPUT_SIZE) };
        const { assert!(SECURITY_BITS_MIN <= SECURITY_BITS_MAX) };
        const { assert!(FRI_QUERIES_MIN <= FRI_QUERIES_MAX) };
        const { assert!(POSEIDON_WIDTH == POSEIDON_RATE * 2) }; // capacity = rate
    }

    #[test]
    fn test_domain_tags_unique() {
        let tags: &[&[u8]] = &[
            DOMAIN_PROOF_GENERATION,
            DOMAIN_PROOF_VERIFICATION,
            DOMAIN_MERKLE,
            DOMAIN_COMMITMENT,
            DOMAIN_PV_COMMIT,
            DOMAIN_PV_SALT,
            DOMAIN_BINDING,
            DOMAIN_CREDENTIAL,
            DOMAIN_IDENTITY,
            DOMAIN_FINANCIAL,
            DOMAIN_KEY_COMMIT,
            DOMAIN_KEY_HANDLE,
            DOMAIN_AUDIT_ENTRY,
            DOMAIN_VAULT_ENCRYPT,
            DOMAIN_COMPRESSION_CHECKSUM,
            DOMAIN_PROOF_INTEGRITY,
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(
                    tags[i],
                    tags[j],
                    "Duplicate domain tag: {:?}",
                    core::str::from_utf8(tags[i]).unwrap_or("?")
                );
            }
        }
    }
}
