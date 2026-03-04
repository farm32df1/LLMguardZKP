//! KeyHandle — opaque reference to an API key stored in the vault.
//!
//! The LLM only ever sees a `KeyHandle`. The actual key bytes never
//! leave the `SecretVault`.

use crate::core::errors::{Result, ZKGuardError};
use crate::core::types::CommittedPublicInputs;
use crate::utils::constants::{DOMAIN_KEY_HANDLE, HANDLE_BINDING_SIZE, HANDLE_ID_BYTES};
use crate::utils::hash::poseidon_hash;

/// Opaque identifier embedded in LLM context as `{{ZKGUARD:<hex>}}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandleId(pub [u8; HANDLE_ID_BYTES]);

impl HandleId {
    /// Generate a fresh random handle ID using OS CSPRNG.
    #[cfg(feature = "std")]
    pub fn random() -> Result<Self> {
        let mut bytes = [0u8; HANDLE_ID_BYTES];
        getrandom::getrandom(&mut bytes).map_err(|e| ZKGuardError::VaultError {
            reason: alloc::format!("getrandom failed: {}", e),
        })?;
        Ok(Self(bytes))
    }

    pub fn to_hex(&self) -> alloc::string::String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = alloc::string::String::with_capacity(HANDLE_ID_BYTES * 2);
        for &b in &self.0 {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0xf) as usize] as char);
        }
        s
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        // Hex strings are always ASCII, so byte length == char count.
        // Reject non-ASCII input early to prevent char boundary panics.
        if s.len() != HANDLE_ID_BYTES * 2 || !s.is_ascii() {
            return None;
        }
        let mut bytes = [0u8; HANDLE_ID_BYTES];
        for i in 0..HANDLE_ID_BYTES {
            bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// Context token inserted into LLM prompts instead of the real key.
    pub fn to_token(&self) -> alloc::string::String {
        alloc::format!("{{{{ZKGUARD:{}}}}}", self.to_hex())
    }
}

/// ZK commitment-backed reference to a secret API key.
///
/// - `id`         — what the LLM sees (opaque token)
/// - `commitment` — Poseidon2 commitment to the key (public, verifiable)
///
/// The commitment lets anyone verify (without the key) that a specific
/// operation was authorised by whoever registered that key.
#[derive(Debug, Clone)]
pub struct KeyHandle {
    pub(crate) id: HandleId,
    /// `Poseidon2(key_bytes || salt, DOMAIN_KEY_COMMIT)`
    pub(crate) commitment: CommittedPublicInputs,
    /// Poseidon2 binding hash of (id || commitment) — prevents forgery.
    pub(crate) handle_hash: [u8; 32],
}

impl KeyHandle {
    /// Build the binding buffer (id || commitment) on the stack.
    fn binding_data(
        id: &HandleId,
        commitment: &CommittedPublicInputs,
    ) -> [u8; HANDLE_BINDING_SIZE] {
        let mut data = [0u8; HANDLE_BINDING_SIZE];
        data[..HANDLE_ID_BYTES].copy_from_slice(&id.0);
        data[HANDLE_ID_BYTES..HANDLE_BINDING_SIZE].copy_from_slice(&commitment.commitment);
        data
    }

    /// The opaque handle identifier.
    pub fn id(&self) -> &HandleId {
        &self.id
    }

    /// The Poseidon2 commitment to the key material.
    pub fn commitment(&self) -> &CommittedPublicInputs {
        &self.commitment
    }

    pub(crate) fn new(id: HandleId, commitment: CommittedPublicInputs) -> Self {
        let handle_hash = poseidon_hash(&Self::binding_data(&id, &commitment), DOMAIN_KEY_HANDLE);
        Self {
            id,
            commitment,
            handle_hash,
        }
    }

    /// Returns the context token to embed in LLM prompts.
    pub fn to_token(&self) -> alloc::string::String {
        self.id.to_token()
    }

    /// Verify that this handle's binding hash is self-consistent.
    /// Detects handle tampering (e.g., commitment field modified in memory).
    pub fn is_valid(&self) -> bool {
        let expected = poseidon_hash(
            &Self::binding_data(&self.id, &self.commitment),
            DOMAIN_KEY_HANDLE,
        );
        crate::utils::hash::constant_time_eq_fixed(&self.handle_hash, &expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_commitment() -> CommittedPublicInputs {
        CommittedPublicInputs::commit(&[1u64, 2, 3], &[42u8; 32])
    }

    #[test]
    fn test_handle_id_hex_roundtrip() {
        let id = HandleId([0x01; 16]);
        let hex = id.to_hex();
        assert_eq!(HandleId::from_hex(&hex), Some(id));
    }

    #[test]
    fn test_handle_token_format() {
        let id = HandleId([0xAB; 16]);
        let token = id.to_token();
        assert!(token.starts_with("{{ZKGUARD:"));
        assert!(token.ends_with("}}"));
    }

    #[test]
    fn test_handle_is_valid() {
        let id = HandleId([0x01; 16]);
        let c = dummy_commitment();
        let h = KeyHandle::new(id, c);
        assert!(h.is_valid());
    }

    #[test]
    fn test_handle_tamper_detected() {
        let id = HandleId([0x01; 16]);
        let c = dummy_commitment();
        let mut h = KeyHandle::new(id, c);
        // Tamper with commitment bytes
        h.commitment.commitment[0] ^= 0xFF;
        assert!(!h.is_valid());
    }
}
