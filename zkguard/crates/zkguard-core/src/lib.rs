//! **zkguard** — ZK-based credential protection for LLM workflows
//!
//! Prevents API keys and secrets from appearing in LLM context windows
//! by replacing them with opaque `{{ZKGUARD:<id>}}` tokens backed by
//! Poseidon2 commitments.  The actual key material lives exclusively in a
//! local `SecretVault` and is zeroed from memory when no longer needed.
//!
//! # Core primitives
//!
//! | Component | What it does |
//! |-----------|--------------|
//! | [`CommittedPublicInputs`] | Poseidon2 commitment to arbitrary data + salt |
//! | [`StarkProver`] / [`StarkVerifier`] | Plonky3 STARK proof system |
//! | [`SecretVault`] | In-memory zeroize-on-drop key store |
//! | [`ContextSanitizer`] | Scans + redacts API keys in LLM prompts |
//!
//! # Quick start
//!
//! ```rust,ignore
//! // Requires: features = ["llm-guard"]
//! use zkguard::llm_guard::ContextSanitizer;
//!
//! let mut guard = ContextSanitizer::new();
//! let safe = guard.sanitize("Call Claude with sk-ant-api03-...").unwrap();
//! // safe.content = "Call Claude with {{ZKGUARD:a3f2...}}"
//! // The real key is in the vault — never in the string sent to the LLM.
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

#[cfg(feature = "alloc")]
extern crate alloc;

// ── Modules ───────────────────────────────────────────────────────────────────

pub mod batching;
pub mod core;
pub mod stark;
pub mod utils;

#[cfg(feature = "llm-guard")]
pub mod llm_guard;

// ── Top-level re-exports ──────────────────────────────────────────────────────

pub use crate::core::errors::{Result, ZKGuardError};
pub use crate::core::traits::{Prover, Verifier};
pub use crate::core::types::{CommittedPublicInputs, Proof, PublicInputs, Witness};

pub use crate::stark::{StarkConfig, StarkProof, StarkProver, StarkVerifier};

pub use crate::batching::ProofBatch;

#[cfg(feature = "llm-guard")]
pub use crate::llm_guard::{
    ApiProvider, ContextSanitizer, ContextScanner, DetectedKey, HandleId, KeyHandle, SecretVault,
};

#[cfg(feature = "vault-encrypt")]
pub use crate::llm_guard::{
    load_vault_encrypted, migrate_vault_to_encrypted, save_vault_encrypted, VaultEncryptionParams,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_nonempty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_committed_public_inputs_smoke() {
        let vals = alloc::vec![1u64, 2, 3];
        let salt = [0u8; 32];
        let c = CommittedPublicInputs::commit(&vals, &salt);
        assert!(c.verify(&vals, &salt));
    }
}
