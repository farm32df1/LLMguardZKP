//! SecretVault — in-memory encrypted store for API keys.
//!
//! Keys are never returned to callers.  The only way to "use" a key is
//! through `with_key()`, which passes a short-lived reference to a
//! closure and zeroizes it immediately after.

use crate::core::errors::{Result, ZKGuardError};
use crate::core::types::CommittedPublicInputs;
use crate::llm_guard::handle::{HandleId, KeyHandle};
use crate::utils::constants::HANDLE_ID_BYTES;
use crate::utils::hash::bytes_to_fields;

use alloc::{collections::BTreeMap, vec::Vec};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key material stored inside the vault.
/// Zeroized automatically on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct VaultEntry {
    /// Raw key bytes (e.g. `b"sk-ant-..."`)
    key: Vec<u8>,
    /// Salt used to build the commitment — also secret.
    salt: [u8; 32],
}

/// In-memory vault.  All stored keys are Zeroize-on-drop.
///
/// Thread-safety: wrap in `Arc<Mutex<SecretVault>>` for shared use.
pub struct SecretVault {
    entries: BTreeMap<[u8; HANDLE_ID_BYTES], VaultEntry>,
}

impl SecretVault {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Store `api_key` and return a `KeyHandle` that can be embedded in
    /// LLM context.  The actual key is never exposed beyond this call.
    pub fn store(&mut self, api_key: &[u8]) -> Result<KeyHandle> {
        if api_key.is_empty() {
            return Err(ZKGuardError::VaultError {
                reason: "key must not be empty".into(),
            });
        }

        // 1. Generate a random salt via OS CSPRNG.
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt).map_err(|e| ZKGuardError::VaultError {
            reason: alloc::format!("RNG error: {}", e),
        })?;

        // 2. Commit: `Poseidon2(key_fields || salt, DOMAIN_KEY_COMMIT)`
        let key_fields = bytes_to_fields(api_key);
        let commitment = CommittedPublicInputs::commit(&key_fields, &salt);

        // 3. Random handle ID.
        let id = HandleId::random()?;

        // 4. Persist in vault.
        self.entries.insert(
            id.0,
            VaultEntry {
                key: api_key.to_vec(),
                salt,
            },
        );

        Ok(KeyHandle::new(id, commitment))
    }

    /// Execute `f` with a reference to the raw key bytes.
    /// The borrow ends before this function returns.
    ///
    /// Returns `Err(HandleNotFound)` if the handle is unknown.
    /// Returns `Err(VaultError)` if the handle has been tampered.
    pub fn with_key<F, R>(&self, handle: &KeyHandle, f: F) -> Result<R>
    where
        F: FnOnce(&[u8]) -> Result<R>,
    {
        if !handle.is_valid() {
            return Err(ZKGuardError::VaultError {
                reason: "handle integrity check failed".into(),
            });
        }

        let entry = self
            .entries
            .get(&handle.id.0)
            .ok_or(ZKGuardError::HandleNotFound)?;

        // Re-derive commitment from stored key+salt and compare to handle.
        // This ensures the key in vault actually matches the committed handle.
        let key_fields = bytes_to_fields(&entry.key);
        let recomputed = CommittedPublicInputs::commit(&key_fields, &entry.salt);
        if !crate::utils::hash::constant_time_eq_fixed(
            &recomputed.commitment,
            &handle.commitment.commitment,
        ) {
            return Err(ZKGuardError::VaultError {
                reason: "vault key does not match handle commitment".into(),
            });
        }

        f(&entry.key)
    }

    /// Remove a key from the vault (zeroize on drop of VaultEntry).
    pub fn revoke(&mut self, handle: &KeyHandle) -> bool {
        self.entries.remove(&handle.id.0).is_some()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Export all vault entries for persistence.
    /// The returned data includes handle IDs, salts, and raw key bytes.
    pub fn export_entries(&self) -> Vec<ExportedEntry> {
        self.entries
            .iter()
            .map(|(id, entry)| ExportedEntry {
                handle_id: *id,
                salt: entry.salt,
                key_data: entry.key.clone(),
            })
            .collect()
    }

    /// Import an entry from persistent storage, re-creating the commitment
    /// and handle with the original ID and salt.
    pub fn import_entry(
        &mut self,
        handle_id: [u8; HANDLE_ID_BYTES],
        salt: [u8; 32],
        key_data: Vec<u8>,
    ) -> Result<KeyHandle> {
        if key_data.is_empty() {
            return Err(ZKGuardError::VaultError {
                reason: "key must not be empty".into(),
            });
        }

        let key_fields = bytes_to_fields(&key_data);
        let commitment = CommittedPublicInputs::commit(&key_fields, &salt);
        let id = HandleId(handle_id);

        self.entries.insert(
            handle_id,
            VaultEntry {
                key: key_data,
                salt,
            },
        );

        Ok(KeyHandle::new(id, commitment))
    }
}

/// Data needed to persist a vault entry.
/// Zeroized automatically on drop to prevent key leaks.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ExportedEntry {
    pub handle_id: [u8; HANDLE_ID_BYTES],
    pub salt: [u8; 32],
    pub key_data: Vec<u8>,
}

impl core::fmt::Debug for ExportedEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExportedEntry")
            .field("handle_id", &self.handle_id)
            .field("salt", &"<REDACTED>")
            .field("key_data", &"<REDACTED>")
            .finish()
    }
}

impl Default for SecretVault {
    fn default() -> Self {
        Self::new()
    }
}

// SecretVault itself doesn't impl Debug intentionally — prevents key leak via {:?}
impl core::fmt::Debug for SecretVault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretVault")
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_use() {
        let mut vault = SecretVault::new();
        let handle = vault.store(b"sk-ant-test-key").unwrap();

        let result = vault
            .with_key(&handle, |key| {
                assert_eq!(key, b"sk-ant-test-key");
                Ok(key.len())
            })
            .unwrap();

        assert_eq!(result, 15);
    }

    #[test]
    fn test_empty_key_rejected() {
        let mut vault = SecretVault::new();
        assert!(vault.store(b"").is_err());
    }

    #[test]
    fn test_unknown_handle() {
        let vault = SecretVault::new();
        let id = HandleId([0xFF; 16]);
        let dummy_commitment = CommittedPublicInputs::commit(&[1u64], &[1u8; 32]);
        let handle = KeyHandle::new(id, dummy_commitment);
        // id exists in handle but not in vault
        let result = vault.with_key(&handle, |_| Ok(()));
        assert!(matches!(result, Err(ZKGuardError::HandleNotFound)));
    }

    #[test]
    fn test_revoke() {
        let mut vault = SecretVault::new();
        let handle = vault.store(b"test-key").unwrap();
        assert_eq!(vault.len(), 1);
        assert!(vault.revoke(&handle));
        assert_eq!(vault.len(), 0);
    }

    #[test]
    fn test_tampered_handle_rejected() {
        let mut vault = SecretVault::new();
        let handle = vault.store(b"real-key").unwrap();

        // Tamper with the commitment
        let mut bad_handle = handle.clone();
        bad_handle.commitment.commitment[0] ^= 0xFF;

        let result = vault.with_key(&bad_handle, |_| Ok(()));
        assert!(matches!(result, Err(ZKGuardError::VaultError { .. })));
    }
}
