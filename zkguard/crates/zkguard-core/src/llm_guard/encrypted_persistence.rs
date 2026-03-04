//! EncryptedVault — AES-256-GCM encrypted on-disk storage for SecretVault.
//!
//! Password-based encryption using Argon2id for key derivation and
//! AES-256-GCM for authenticated encryption.
//!
//! **Security properties**:
//! - Keys at rest are encrypted (AES-256-GCM, ~128-bit security)
//! - Key derivation resists GPU/ASIC attacks (Argon2id, 64 MiB memory)
//! - Authenticated encryption detects tampering (GCM tag)
//! - Plaintext buffers are zeroized after use
//! - File permissions set to 0600 on Unix
//!
//! File format (version 2):
//! ```text
//! [4 bytes]  magic: "ZKGE" (Guard Encrypted)
//! [1 byte]   version: 0x02
//! [32 bytes] argon2id salt
//! [4 bytes]  argon2id memory cost in KiB (little-endian u32)
//! [4 bytes]  argon2id time cost (little-endian u32)
//! [4 bytes]  argon2id parallelism (little-endian u32)
//! [12 bytes] AES-256-GCM nonce
//! [rest]     AES-256-GCM ciphertext + 16-byte auth tag
//!            (plaintext = same format as v1 vault body)
//! ```

use crate::core::errors::{Result, ZKGuardError};
use crate::llm_guard::vault::SecretVault;
use crate::utils::constants::{
    DOMAIN_KEY_COMMIT, HANDLE_ID_BYTES, MAX_ENCRYPTED_VAULT_SIZE, MAX_VAULT_ENTRIES,
    VAULT_AES_KEY_LEN, VAULT_AES_NONCE_LEN, VAULT_ARGON2_M_COST, VAULT_ARGON2_P_COST,
    VAULT_ARGON2_SALT_LEN, VAULT_ARGON2_T_COST,
};
use crate::utils::hash::poseidon_hash;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use std::path::Path;
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"ZKGE";
const VERSION: u8 = 0x02;

/// Header size: magic(4) + version(1) + salt(32) + m_cost(4) + t_cost(4) + p_cost(4) + nonce(12) = 61
const HEADER_SIZE: usize = 4 + 1 + VAULT_ARGON2_SALT_LEN + 4 + 4 + 4 + VAULT_AES_NONCE_LEN;

/// Argon2id parameters for key derivation.
/// Callers can customize these for different security/performance trade-offs.
#[derive(Debug, Clone)]
pub struct VaultEncryptionParams {
    /// Memory cost in KiB (default: 64 MiB = 65536 KiB).
    pub m_cost: u32,
    /// Time cost / iterations (default: 3).
    pub t_cost: u32,
    /// Parallelism (default: 1).
    pub p_cost: u32,
}

impl Default for VaultEncryptionParams {
    fn default() -> Self {
        Self {
            m_cost: VAULT_ARGON2_M_COST,
            t_cost: VAULT_ARGON2_T_COST,
            p_cost: VAULT_ARGON2_P_COST,
        }
    }
}

/// Derive an AES-256 key from a password using Argon2id.
fn derive_key(
    password: &[u8],
    salt: &[u8; VAULT_ARGON2_SALT_LEN],
    params: &VaultEncryptionParams,
) -> Result<[u8; VAULT_AES_KEY_LEN]> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            params.m_cost,
            params.t_cost,
            params.p_cost,
            Some(VAULT_AES_KEY_LEN),
        )
        .map_err(|e| ZKGuardError::VaultError {
            reason: format!("argon2 params: {}", e),
        })?,
    );

    let mut key = [0u8; VAULT_AES_KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| ZKGuardError::VaultError {
            reason: format!("argon2 key derivation failed: {}", e),
        })?;

    Ok(key)
}

/// Serialize vault entries to the v1 body format (without file magic/version).
fn serialize_vault_body(vault: &SecretVault) -> Vec<u8> {
    let entries = vault.export_entries();
    let mut buf = Vec::new();

    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());

    for entry in &entries {
        buf.extend_from_slice(&entry.handle_id);
        buf.extend_from_slice(&entry.salt);
        buf.extend_from_slice(&(entry.key_data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&entry.key_data);

        // Integrity MAC (same as v1 — double protection layer)
        let mac = compute_mac(&entry.handle_id, &entry.salt, &entry.key_data);
        buf.extend_from_slice(&mac);
    }

    buf
}

/// Deserialize vault entries from the v1 body format.
fn deserialize_vault_body(data: &[u8]) -> Result<SecretVault> {
    use std::io::Read;
    let mut cursor = data;

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
                    "entry {}: integrity MAC mismatch (data corrupted or tampered)",
                    i
                ),
            });
        }

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

/// Save the vault to an encrypted file.
///
/// Uses Argon2id for password-based key derivation and AES-256-GCM for
/// authenticated encryption. The password should be at least 8 bytes.
///
/// # Security
///
/// - The encryption key is derived from the password + random salt
/// - A fresh random nonce is generated for each save
/// - The plaintext buffer is zeroized immediately after encryption
/// - File permissions are set to 0600 on Unix
pub fn save_vault_encrypted(
    vault: &SecretVault,
    path: &Path,
    password: &[u8],
    params: &VaultEncryptionParams,
) -> Result<usize> {
    if password.is_empty() {
        return Err(ZKGuardError::VaultError {
            reason: "encryption password must not be empty".into(),
        });
    }

    // Generate random salt and nonce
    let mut argon_salt = [0u8; VAULT_ARGON2_SALT_LEN];
    getrandom::getrandom(&mut argon_salt).map_err(|e| ZKGuardError::VaultError {
        reason: format!("RNG error (salt): {}", e),
    })?;

    let mut nonce_bytes = [0u8; VAULT_AES_NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| ZKGuardError::VaultError {
        reason: format!("RNG error (nonce): {}", e),
    })?;

    // Derive encryption key
    let mut aes_key = derive_key(password, &argon_salt, params)?;

    // Serialize vault body (plaintext)
    let mut plaintext = serialize_vault_body(vault);
    let entry_count = vault.len();

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| ZKGuardError::VaultError {
        reason: format!("AES init: {}", e),
    })?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext =
        cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| ZKGuardError::VaultError {
                reason: format!("AES-GCM encrypt: {}", e),
            })?;

    // Zeroize sensitive material
    plaintext.zeroize();
    aes_key.zeroize();

    // Build file
    let mut file_buf = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    file_buf.extend_from_slice(MAGIC);
    file_buf.push(VERSION);
    file_buf.extend_from_slice(&argon_salt);
    file_buf.extend_from_slice(&params.m_cost.to_le_bytes());
    file_buf.extend_from_slice(&params.t_cost.to_le_bytes());
    file_buf.extend_from_slice(&params.p_cost.to_le_bytes());
    file_buf.extend_from_slice(&nonce_bytes);
    file_buf.extend_from_slice(&ciphertext);

    // Write file with restrictive permissions
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
        std::io::Write::write_all(&mut file, &file_buf).map_err(|e| {
            ZKGuardError::SerializationError {
                reason: format!("file write: {}", e),
            }
        })?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &file_buf).map_err(|e| ZKGuardError::SerializationError {
            reason: format!("file write: {}", e),
        })?;
    }

    Ok(entry_count)
}

/// Load a vault from an encrypted file.
///
/// Derives the decryption key from the password using the stored Argon2id
/// parameters, then decrypts and verifies the vault contents.
///
/// Returns `Err` if the password is wrong, the file is corrupted, or tampered.
pub fn load_vault_encrypted(path: &Path, password: &[u8]) -> Result<SecretVault> {
    let data = std::fs::read(path).map_err(|e| ZKGuardError::SerializationError {
        reason: format!("file read: {}", e),
    })?;

    if data.len() > MAX_ENCRYPTED_VAULT_SIZE {
        return Err(ZKGuardError::SerializationError {
            reason: format!(
                "file size {} exceeds maximum {}",
                data.len(),
                MAX_ENCRYPTED_VAULT_SIZE
            ),
        });
    }

    if data.len() < HEADER_SIZE + 16 {
        // minimum: header + GCM tag (16 bytes)
        return Err(ZKGuardError::SerializationError {
            reason: "file too small to be a valid encrypted vault".into(),
        });
    }

    // Parse header
    let mut offset = 0;

    // Magic
    if &data[offset..offset + 4] != MAGIC {
        return Err(ZKGuardError::SerializationError {
            reason: "invalid file magic (expected ZKGE)".into(),
        });
    }
    offset += 4;

    // Version
    if data[offset] != VERSION {
        return Err(ZKGuardError::SerializationError {
            reason: format!(
                "unsupported version: {} (expected {})",
                data[offset], VERSION
            ),
        });
    }
    offset += 1;

    // Argon2id salt
    let mut argon_salt = [0u8; VAULT_ARGON2_SALT_LEN];
    argon_salt.copy_from_slice(&data[offset..offset + VAULT_ARGON2_SALT_LEN]);
    offset += VAULT_ARGON2_SALT_LEN;

    // Argon2id params
    let m_cost = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let t_cost = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let p_cost = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    offset += 4;

    // Validate Argon2 params (sanity checks)
    if !(1024..=4_194_304).contains(&m_cost) {
        // 1 MiB to 4 GiB
        return Err(ZKGuardError::SerializationError {
            reason: format!("argon2 m_cost out of range: {}", m_cost),
        });
    }
    if !(1..=100).contains(&t_cost) {
        return Err(ZKGuardError::SerializationError {
            reason: format!("argon2 t_cost out of range: {}", t_cost),
        });
    }
    if !(1..=255).contains(&p_cost) {
        return Err(ZKGuardError::SerializationError {
            reason: format!("argon2 p_cost out of range: {}", p_cost),
        });
    }

    // AES-256-GCM nonce
    let mut nonce_bytes = [0u8; VAULT_AES_NONCE_LEN];
    nonce_bytes.copy_from_slice(&data[offset..offset + VAULT_AES_NONCE_LEN]);
    offset += VAULT_AES_NONCE_LEN;

    // Remaining data is ciphertext + auth tag
    let ciphertext = &data[offset..];

    // Derive decryption key
    let params = VaultEncryptionParams {
        m_cost,
        t_cost,
        p_cost,
    };
    let mut aes_key = derive_key(password, &argon_salt, &params)?;

    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| ZKGuardError::VaultError {
        reason: format!("AES init: {}", e),
    })?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut plaintext =
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| ZKGuardError::VaultError {
                reason: "decryption failed: wrong password or corrupted file".into(),
            })?;

    // Zeroize key immediately
    aes_key.zeroize();

    // Deserialize vault body
    let vault = deserialize_vault_body(&plaintext);

    // Zeroize plaintext
    plaintext.zeroize();

    vault
}

/// Migrate a plaintext vault (v1) to encrypted format (v2).
///
/// Reads the existing plaintext vault file, encrypts it with the given
/// password, and writes the encrypted version to the output path.
pub fn migrate_vault_to_encrypted(
    plaintext_path: &Path,
    encrypted_path: &Path,
    password: &[u8],
    params: &VaultEncryptionParams,
) -> Result<usize> {
    let vault = crate::llm_guard::persistence::load_vault(plaintext_path)?;
    save_vault_encrypted(&vault, encrypted_path, password, params)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Use fast Argon2 params for tests (avoid slow CI).
    fn test_params() -> VaultEncryptionParams {
        VaultEncryptionParams {
            m_cost: 1024, // 1 MiB (minimum for tests)
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn test_save_and_load_encrypted_vault() {
        let mut vault = SecretVault::new();
        let h1 = vault.store(b"sk-ant-api03-test-key-ENCRYPTED").unwrap();
        let h2 = vault.store(b"AKIAIOSFODNN7ENCRYPTED").unwrap();
        assert_eq!(vault.len(), 2);

        let tmp = std::env::temp_dir().join("zkguard_test_encrypted_vault.bin");
        let password = b"test-password-2024";

        let saved = save_vault_encrypted(&vault, &tmp, password, &test_params()).unwrap();
        assert_eq!(saved, 2);

        // Verify file is not plaintext
        let raw = std::fs::read(&tmp).unwrap();
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(!raw_str.contains("sk-ant-api03"));
        assert!(!raw_str.contains("AKIA"));

        // Load and verify
        let loaded = load_vault_encrypted(&tmp, password).unwrap();
        assert_eq!(loaded.len(), 2);

        let result = loaded
            .with_key(&h1, |key| {
                assert_eq!(key, b"sk-ant-api03-test-key-ENCRYPTED");
                Ok(key.len())
            })
            .unwrap();
        assert_eq!(result, 31);

        let result = loaded
            .with_key(&h2, |key| {
                assert_eq!(key, b"AKIAIOSFODNN7ENCRYPTED");
                Ok(key.len())
            })
            .unwrap();
        assert_eq!(result, 22);

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_wrong_password_fails() {
        let mut vault = SecretVault::new();
        vault.store(b"secret-key").unwrap();

        let tmp = std::env::temp_dir().join("zkguard_test_wrong_pw.bin");
        save_vault_encrypted(&vault, &tmp, b"correct-password", &test_params()).unwrap();

        let result = load_vault_encrypted(&tmp, b"wrong-password");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("wrong password") || err_msg.contains("decryption failed"),
            "unexpected error: {}",
            err_msg
        );

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_corrupted_encrypted_file() {
        let mut vault = SecretVault::new();
        vault.store(b"test-key").unwrap();

        let tmp = std::env::temp_dir().join("zkguard_test_corrupt_enc.bin");
        save_vault_encrypted(&vault, &tmp, b"password", &test_params()).unwrap();

        // Corrupt the ciphertext (last byte before auth tag)
        let mut data = std::fs::read(&tmp).unwrap();
        let mid = data.len() / 2;
        data[mid] ^= 0xFF;
        std::fs::write(&tmp, &data).unwrap();

        let result = load_vault_encrypted(&tmp, b"password");
        assert!(result.is_err());

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_empty_password_rejected() {
        let vault = SecretVault::new();
        let tmp = std::env::temp_dir().join("zkguard_test_empty_pw.bin");
        let result = save_vault_encrypted(&vault, &tmp, b"", &test_params());
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_empty_vault() {
        let vault = SecretVault::new();
        let tmp = std::env::temp_dir().join("zkguard_test_enc_empty.bin");
        let password = b"password";

        let saved = save_vault_encrypted(&vault, &tmp, password, &test_params()).unwrap();
        assert_eq!(saved, 0);

        let loaded = load_vault_encrypted(&tmp, password).unwrap();
        assert_eq!(loaded.len(), 0);

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let tmp = std::env::temp_dir().join("zkguard_test_bad_magic_enc.bin");
        // Write a file with wrong magic but correct minimum size
        let mut data = vec![0u8; HEADER_SIZE + 32];
        data[..4].copy_from_slice(b"XXXX");
        std::fs::write(&tmp, &data).unwrap();

        let result = load_vault_encrypted(&tmp, b"password");
        assert!(result.is_err());

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_file_too_small_rejected() {
        let tmp = std::env::temp_dir().join("zkguard_test_small_enc.bin");
        std::fs::write(&tmp, b"ZKGE\x02").unwrap();

        let result = load_vault_encrypted(&tmp, b"password");
        assert!(result.is_err());

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_migrate_plaintext_to_encrypted() {
        let mut vault = SecretVault::new();
        let handle = vault.store(b"migration-test-key").unwrap();

        let v1_path = std::env::temp_dir().join("zkguard_test_migrate_v1.bin");
        let v2_path = std::env::temp_dir().join("zkguard_test_migrate_v2.bin");

        // Save as plaintext v1
        crate::llm_guard::persistence::save_vault(&vault, &v1_path).unwrap();

        // Migrate to encrypted v2
        let count = migrate_vault_to_encrypted(&v1_path, &v2_path, b"migration-pw", &test_params())
            .unwrap();
        assert_eq!(count, 1);

        // Load encrypted and verify
        let loaded = load_vault_encrypted(&v2_path, b"migration-pw").unwrap();
        assert_eq!(loaded.len(), 1);
        loaded
            .with_key(&handle, |key| {
                assert_eq!(key, b"migration-test-key");
                Ok(())
            })
            .unwrap();

        std::fs::remove_file(&v1_path).ok();
        std::fs::remove_file(&v2_path).ok();
    }

    #[test]
    fn test_file_not_plaintext_readable() {
        let mut vault = SecretVault::new();
        vault
            .store(b"sk-ant-api03-AAAA-very-long-key-here-for-testing")
            .unwrap();

        let tmp = std::env::temp_dir().join("zkguard_test_not_plaintext.bin");
        save_vault_encrypted(&vault, &tmp, b"password123", &test_params()).unwrap();

        // Try to load as plaintext v1 — should fail
        let result = crate::llm_guard::persistence::load_vault(&tmp);
        assert!(
            result.is_err(),
            "encrypted vault should not load as plaintext"
        );

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_custom_argon2_params() {
        let mut vault = SecretVault::new();
        vault.store(b"custom-params-key").unwrap();

        let tmp = std::env::temp_dir().join("zkguard_test_custom_params.bin");
        let params = VaultEncryptionParams {
            m_cost: 2048, // 2 MiB
            t_cost: 2,
            p_cost: 1,
        };

        save_vault_encrypted(&vault, &tmp, b"password", &params).unwrap();

        // Params are stored in the file, so load should work without specifying them
        let loaded = load_vault_encrypted(&tmp, b"password").unwrap();
        assert_eq!(loaded.len(), 1);

        std::fs::remove_file(&tmp).ok();
    }
}
