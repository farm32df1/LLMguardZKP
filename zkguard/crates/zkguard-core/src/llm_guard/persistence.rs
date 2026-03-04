//! PersistentVault — on-disk storage for SecretVault.
//!
//! Saves and loads vault entries to/from a file. Each entry is stored
//! with a Poseidon2 integrity MAC so tampering is detectable.
//!
//! **Security note**: Keys are stored in plaintext on disk. This is
//! suitable for development and single-user environments. For production,
//! combine with OS-level encryption (macOS Keychain, dm-crypt, etc.).
//!
//! File format (version 1):
//! ```text
//! [4 bytes] magic: "ZKGV"
//! [1 byte]  version: 0x01
//! [4 bytes] entry count (little-endian u32)
//! For each entry:
//!   [16 bytes] handle_id
//!   [32 bytes] salt
//!   [4 bytes]  key_len (little-endian u32)
//!   [key_len]  key_data
//!   [32 bytes] integrity MAC = poseidon_hash(handle_id || salt || key_data, DOMAIN_KEY_COMMIT)
//! ```

use crate::core::errors::{Result, ZKGuardError};
use crate::llm_guard::vault::SecretVault;
use crate::utils::constants::{DOMAIN_KEY_COMMIT, HANDLE_ID_BYTES, MAX_VAULT_ENTRIES};
use crate::utils::hash::poseidon_hash;

use std::io::Read;
use std::path::Path;
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"ZKGV";
const VERSION: u8 = 0x01;

/// Save the vault to a file.
///
/// **Warning**: Keys are stored in plaintext. Use OS-level disk encryption
/// for production environments.
pub fn save_vault(vault: &SecretVault, path: &Path) -> Result<usize> {
    let entries = vault.export_entries();

    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.push(VERSION);
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());

    for entry in &entries {
        buf.extend_from_slice(&entry.handle_id);
        buf.extend_from_slice(&entry.salt);
        buf.extend_from_slice(&(entry.key_data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&entry.key_data);

        // Integrity MAC
        let mac = compute_mac(&entry.handle_id, &entry.salt, &entry.key_data);
        buf.extend_from_slice(&mac);
    }

    let count = entries.len();

    // Write file with restrictive permissions (owner-only read/write)
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| ZKGuardError::SerializationError {
                reason: format!("file create: {}", e),
            })?;
        std::io::Write::write_all(&mut file, &buf).map_err(|e| {
            ZKGuardError::SerializationError {
                reason: format!("file write: {}", e),
            }
        })?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &buf).map_err(|e| ZKGuardError::SerializationError {
            reason: format!("file write: {}", e),
        })?;
    }

    // Zeroize the serialization buffer (contains plaintext keys)
    buf.zeroize();

    Ok(count)
}

/// Load a vault from a file.
///
/// Verifies the integrity MAC of each entry during loading.
/// Returns an error if the file is corrupted or tampered.
pub fn load_vault(path: &Path) -> Result<SecretVault> {
    let data = std::fs::read(path).map_err(|e| ZKGuardError::SerializationError {
        reason: format!("file read: {}", e),
    })?;

    let mut cursor = &data[..];

    // Magic
    let mut magic = [0u8; 4];
    cursor
        .read_exact(&mut magic)
        .map_err(|e| ZKGuardError::SerializationError {
            reason: format!("read magic: {}", e),
        })?;
    if &magic != MAGIC {
        return Err(ZKGuardError::SerializationError {
            reason: "invalid file magic (expected ZKGV)".into(),
        });
    }

    // Version
    let mut ver = [0u8; 1];
    cursor
        .read_exact(&mut ver)
        .map_err(|e| ZKGuardError::SerializationError {
            reason: format!("read version: {}", e),
        })?;
    if ver[0] != VERSION {
        return Err(ZKGuardError::SerializationError {
            reason: format!("unsupported version: {}", ver[0]),
        });
    }

    // Entry count
    let mut count_bytes = [0u8; 4];
    cursor
        .read_exact(&mut count_bytes)
        .map_err(|e| ZKGuardError::SerializationError {
            reason: format!("read count: {}", e),
        })?;
    let count = u32::from_le_bytes(count_bytes) as usize;

    if count > MAX_VAULT_ENTRIES {
        return Err(ZKGuardError::SerializationError {
            reason: format!(
                "entry count {} exceeds maximum {}",
                count, MAX_VAULT_ENTRIES
            ),
        });
    }

    let mut vault = SecretVault::new();

    for i in 0..count {
        // Handle ID
        let mut handle_id = [0u8; HANDLE_ID_BYTES];
        cursor
            .read_exact(&mut handle_id)
            .map_err(|e| ZKGuardError::SerializationError {
                reason: format!("entry {}: read handle_id: {}", i, e),
            })?;

        // Salt
        let mut salt = [0u8; 32];
        cursor
            .read_exact(&mut salt)
            .map_err(|e| ZKGuardError::SerializationError {
                reason: format!("entry {}: read salt: {}", i, e),
            })?;

        // Key data length
        let mut key_len_bytes = [0u8; 4];
        cursor
            .read_exact(&mut key_len_bytes)
            .map_err(|e| ZKGuardError::SerializationError {
                reason: format!("entry {}: read key_len: {}", i, e),
            })?;
        let key_len = u32::from_le_bytes(key_len_bytes) as usize;

        if key_len > 1024 * 1024 {
            return Err(ZKGuardError::SerializationError {
                reason: format!("entry {}: key_len too large: {}", i, key_len),
            });
        }

        // Key data
        let mut key_data = vec![0u8; key_len];
        cursor
            .read_exact(&mut key_data)
            .map_err(|e| ZKGuardError::SerializationError {
                reason: format!("entry {}: read key_data: {}", i, e),
            })?;

        // Integrity MAC
        let mut stored_mac = [0u8; 32];
        cursor
            .read_exact(&mut stored_mac)
            .map_err(|e| ZKGuardError::SerializationError {
                reason: format!("entry {}: read mac: {}", i, e),
            })?;

        // Verify MAC
        let expected_mac = compute_mac(&handle_id, &salt, &key_data);
        if !crate::utils::hash::constant_time_eq_fixed(&expected_mac, &stored_mac) {
            return Err(ZKGuardError::SerializationError {
                reason: format!(
                    "entry {}: integrity MAC mismatch (file corrupted or tampered)",
                    i
                ),
            });
        }

        // Import into vault
        vault.import_entry(handle_id, salt, key_data)?;
    }

    Ok(vault)
}

/// Compute the integrity MAC for a vault entry.
fn compute_mac(handle_id: &[u8; HANDLE_ID_BYTES], salt: &[u8; 32], key_data: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(HANDLE_ID_BYTES + 32 + key_data.len());
    input.extend_from_slice(handle_id);
    input.extend_from_slice(salt);
    input.extend_from_slice(key_data);
    poseidon_hash(&input, DOMAIN_KEY_COMMIT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_and_load_vault() {
        let mut vault = SecretVault::new();
        let handle1 = vault.store(b"sk-ant-api03-test-key").unwrap();
        let handle2 = vault.store(b"AKIAIOSFODNN7EXAMPLE").unwrap();
        assert_eq!(vault.len(), 2);

        let tmp = std::env::temp_dir().join("zkguard_test_vault.bin");
        let saved = save_vault(&vault, &tmp).unwrap();
        assert_eq!(saved, 2);

        let loaded = load_vault(&tmp).unwrap();
        assert_eq!(loaded.len(), 2);

        // Verify we can still access keys
        let result = loaded
            .with_key(&handle1, |key| {
                assert_eq!(key, b"sk-ant-api03-test-key");
                Ok(key.len())
            })
            .unwrap();
        assert_eq!(result, 21);

        let result = loaded
            .with_key(&handle2, |key| {
                assert_eq!(key, b"AKIAIOSFODNN7EXAMPLE");
                Ok(key.len())
            })
            .unwrap();
        assert_eq!(result, 20);

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_load_corrupted_file() {
        let mut vault = SecretVault::new();
        vault.store(b"test-key").unwrap();

        let tmp = std::env::temp_dir().join("zkguard_test_corrupt.bin");
        save_vault(&vault, &tmp).unwrap();

        // Corrupt the file
        let mut data = std::fs::read(&tmp).unwrap();
        if let Some(byte) = data.last_mut() {
            *byte ^= 0xFF;
        }
        std::fs::write(&tmp, &data).unwrap();

        let result = load_vault(&tmp);
        assert!(result.is_err());

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_load_invalid_magic() {
        let tmp = std::env::temp_dir().join("zkguard_test_badmagic.bin");
        std::fs::write(&tmp, b"XXXX\x01\x00\x00\x00\x00").unwrap();

        let result = load_vault(&tmp);
        assert!(result.is_err());

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_save_empty_vault() {
        let vault = SecretVault::new();
        let tmp = std::env::temp_dir().join("zkguard_test_empty.bin");
        let saved = save_vault(&vault, &tmp).unwrap();
        assert_eq!(saved, 0);

        let loaded = load_vault(&tmp).unwrap();
        assert_eq!(loaded.len(), 0);

        std::fs::remove_file(&tmp).ok();
    }
}
