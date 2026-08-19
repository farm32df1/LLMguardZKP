//! TokenMap — maps dummy proxy tokens (zkg-...) to vault handles.
//!
//! When a user registers an API key with `zkguard key add`, the key is stored
//! in the encrypted vault and a dummy token (`zkg-<provider>-<hex>`) is issued.
//! The proxy server uses this map to resolve dummy tokens back to real keys
//! at request time, so the real key never leaves the local machine.
//!
//! ```text
//! App sends: "x-api-key: zkg-anthropic-a1b2c3d4"
//!     → TokenMap::with_resolved_key → closure receives &[u8] ref to real key
//!     → proxy builds HeaderValue inside closure, forwards request
//!     → closure returns → header + borrow dropped → no owned copy escapes
//! ```
//!
//! Security contract: the real key is **never** returned to callers as an
//! owned `String` or `Vec<u8>`. The only way to touch it is through a closure
//! whose borrow ends before the function returns, mirroring
//! [`crate::llm_guard::vault::SecretVault::with_key`].

use crate::core::errors::{Result, ZKGuardError};
use crate::llm_guard::handle::KeyHandle;
use crate::llm_guard::vault::SecretVault;
use crate::utils::constants::HANDLE_ID_BYTES;

use alloc::{collections::BTreeMap, string::String, vec::Vec};

/// Prefix for all zkguard dummy tokens.
pub const TOKEN_PREFIX: &str = "zkg-";

/// Maps dummy proxy tokens to vault handle IDs.
///
/// Persisted alongside the vault so the proxy can resolve tokens across restarts.
pub struct TokenMap {
    /// `"zkg-anthropic-a1b2c3..."` → `HandleId` bytes
    mapping: BTreeMap<String, [u8; HANDLE_ID_BYTES]>,
    /// Reverse: `HandleId` → provider name (for display in `key list`)
    providers: BTreeMap<[u8; HANDLE_ID_BYTES], String>,
}

impl TokenMap {
    pub fn new() -> Self {
        Self {
            mapping: BTreeMap::new(),
            providers: BTreeMap::new(),
        }
    }

    /// Register an API key in the vault and issue a dummy token.
    ///
    /// Returns `(dummy_token, KeyHandle)`.
    /// The dummy token format: `zkg-<provider>-<handle_hex_prefix>`
    pub fn register(
        &mut self,
        vault: &mut SecretVault,
        api_key: &[u8],
        provider: &str,
    ) -> Result<(String, KeyHandle)> {
        if api_key.is_empty() {
            return Err(ZKGuardError::VaultError {
                reason: "API key must not be empty".into(),
            });
        }

        let handle = vault.store(api_key)?;

        let hex = handle.id().to_hex();
        let short_hex = &hex[..16.min(hex.len())];
        let dummy_token =
            alloc::format!("{}{}-{}", TOKEN_PREFIX, provider.to_lowercase(), short_hex);

        self.mapping.insert(dummy_token.clone(), handle.id().0);
        self.providers
            .insert(handle.id().0, provider.to_lowercase());

        Ok((dummy_token, handle))
    }

    /// Resolve a dummy token and run `f` with a short-lived borrow of the
    /// real key bytes.
    ///
    /// The key never leaves the vault's memory allocation: no clone, no
    /// owned String, no intermediate copy. Whatever the closure returns
    /// is what the caller gets back — so wrap the consuming work (e.g.
    /// building an HTTP `HeaderValue`) inside the closure.
    pub fn with_resolved_key<F, R>(&self, dummy_token: &str, vault: &SecretVault, f: F) -> Result<R>
    where
        F: FnOnce(&[u8]) -> Result<R>,
    {
        let handle_id_bytes = self
            .mapping
            .get(dummy_token)
            .ok_or(ZKGuardError::HandleNotFound)?;
        vault.with_key_by_id(handle_id_bytes, f)
    }

    /// Check if a token string looks like a zkguard dummy token.
    pub fn is_zkguard_token(token: &str) -> bool {
        token.starts_with(TOKEN_PREFIX)
    }

    /// Whether this exact dummy token is registered.
    pub fn contains(&self, dummy_token: &str) -> bool {
        self.mapping.contains_key(dummy_token)
    }

    /// Remove a token by provider name.
    /// Returns true if a matching token was found and removed.
    pub fn remove_by_provider(&mut self, vault: &mut SecretVault, provider: &str) -> bool {
        let provider_lower = provider.to_lowercase();
        let mut removed = false;

        let ids_to_remove: Vec<[u8; HANDLE_ID_BYTES]> = self
            .providers
            .iter()
            .filter(|(_, p)| **p == provider_lower)
            .map(|(id, _)| *id)
            .collect();

        for id in &ids_to_remove {
            self.providers.remove(id);
            self.mapping.retain(|_, v| v != id);
            vault.revoke_by_id(id);
            removed = true;
        }

        removed
    }

    /// List all registered tokens with their provider names.
    /// Returns `Vec<(dummy_token, provider)>`.
    pub fn list(&self) -> Vec<(String, String)> {
        self.mapping
            .iter()
            .map(|(token, id)| {
                let provider = self
                    .providers
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".into());
                (token.clone(), provider)
            })
            .collect()
    }

    /// Number of registered tokens.
    pub fn len(&self) -> usize {
        self.mapping.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mapping.is_empty()
    }

    /// Serialize the token map to bytes for persistence.
    ///
    /// Layout: `[u32 count]` then for each entry
    /// `[u32 token_len][token_bytes][16 handle_id][u32 provider_len][provider_bytes]`.
    ///
    /// The file contains **no** secret material — only opaque `zkg-*` labels,
    /// handle IDs, and provider names. Real key bytes live exclusively in the
    /// encrypted vault file next to this map.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let count = self.mapping.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());

        for (token, id) in &self.mapping {
            let token_bytes = token.as_bytes();
            buf.extend_from_slice(&(token_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(token_bytes);
            buf.extend_from_slice(id);

            let provider = self
                .providers
                .get(id)
                .cloned()
                .unwrap_or_else(|| "unknown".into());
            let provider_bytes = provider.as_bytes();
            buf.extend_from_slice(&(provider_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(provider_bytes);
        }

        buf
    }

    /// Deserialize the token map from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(ZKGuardError::VaultError {
                reason: "token map data too short".into(),
            });
        }

        let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let mut offset = 4;
        let mut mapping = BTreeMap::new();
        let mut providers = BTreeMap::new();

        for _ in 0..count {
            if offset + 4 > data.len() {
                return Err(ZKGuardError::VaultError {
                    reason: "truncated token map".into(),
                });
            }
            let token_len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + token_len > data.len() {
                return Err(ZKGuardError::VaultError {
                    reason: "truncated token map".into(),
                });
            }
            let token =
                String::from_utf8(data[offset..offset + token_len].to_vec()).map_err(|_| {
                    ZKGuardError::VaultError {
                        reason: "invalid UTF-8 in token".into(),
                    }
                })?;
            offset += token_len;

            if offset + HANDLE_ID_BYTES > data.len() {
                return Err(ZKGuardError::VaultError {
                    reason: "truncated token map".into(),
                });
            }
            let mut id = [0u8; HANDLE_ID_BYTES];
            id.copy_from_slice(&data[offset..offset + HANDLE_ID_BYTES]);
            offset += HANDLE_ID_BYTES;

            if offset + 4 > data.len() {
                return Err(ZKGuardError::VaultError {
                    reason: "truncated token map".into(),
                });
            }
            let provider_len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + provider_len > data.len() {
                return Err(ZKGuardError::VaultError {
                    reason: "truncated token map".into(),
                });
            }
            let provider = String::from_utf8(data[offset..offset + provider_len].to_vec())
                .map_err(|_| ZKGuardError::VaultError {
                    reason: "invalid UTF-8 in provider".into(),
                })?;
            offset += provider_len;

            mapping.insert(token, id);
            providers.insert(id, provider);
        }

        Ok(Self { mapping, providers })
    }
}

impl Default for TokenMap {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for TokenMap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TokenMap")
            .field("token_count", &self.mapping.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_resolve_via_closure() {
        let mut vault = SecretVault::new();
        let mut map = TokenMap::new();

        let (token, _handle) = map
            .register(&mut vault, b"sk-ant-api03-test-key-1234", "anthropic")
            .unwrap();

        assert!(token.starts_with("zkg-anthropic-"));
        assert_eq!(map.len(), 1);

        let echoed_len = map
            .with_resolved_key(&token, &vault, |key_bytes| {
                assert_eq!(key_bytes, b"sk-ant-api03-test-key-1234");
                Ok(key_bytes.len())
            })
            .unwrap();
        assert_eq!(echoed_len, 26);
    }

    #[test]
    fn test_is_zkguard_token() {
        assert!(TokenMap::is_zkguard_token("zkg-anthropic-abc123"));
        assert!(TokenMap::is_zkguard_token("zkg-openai-def456"));
        assert!(!TokenMap::is_zkguard_token("sk-ant-api03-real-key"));
        assert!(!TokenMap::is_zkguard_token("Bearer sk-1234"));
    }

    #[test]
    fn test_contains() {
        let mut vault = SecretVault::new();
        let mut map = TokenMap::new();
        let (token, _) = map
            .register(&mut vault, b"sk-ant-api03-key1", "anthropic")
            .unwrap();
        assert!(map.contains(&token));
        assert!(!map.contains("zkg-anthropic-deadbeef"));
    }

    #[test]
    fn test_multiple_providers() {
        let mut vault = SecretVault::new();
        let mut map = TokenMap::new();

        let (t1, _) = map
            .register(&mut vault, b"sk-ant-api03-key1", "anthropic")
            .unwrap();
        let (t2, _) = map
            .register(&mut vault, b"sk-openai-key2", "openai")
            .unwrap();

        assert!(t1.starts_with("zkg-anthropic-"));
        assert!(t2.starts_with("zkg-openai-"));
        assert_eq!(map.len(), 2);

        map.with_resolved_key(&t1, &vault, |k| {
            assert_eq!(k, b"sk-ant-api03-key1");
            Ok(())
        })
        .unwrap();
        map.with_resolved_key(&t2, &vault, |k| {
            assert_eq!(k, b"sk-openai-key2");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_remove_by_provider() {
        let mut vault = SecretVault::new();
        let mut map = TokenMap::new();

        let (token, _) = map
            .register(&mut vault, b"sk-ant-api03-key1", "anthropic")
            .unwrap();
        map.register(&mut vault, b"sk-openai-key2", "openai")
            .unwrap();

        assert_eq!(map.len(), 2);
        assert!(map.remove_by_provider(&mut vault, "anthropic"));
        assert_eq!(map.len(), 1);
        assert_eq!(vault.len(), 1);

        let err = map.with_resolved_key(&token, &vault, |_| Ok(()));
        assert!(err.is_err());
    }

    #[test]
    fn test_list() {
        let mut vault = SecretVault::new();
        let mut map = TokenMap::new();

        map.register(&mut vault, b"key1", "anthropic").unwrap();
        map.register(&mut vault, b"key2", "openai").unwrap();

        let list = map.list();
        assert_eq!(list.len(), 2);
        assert!(list.iter().any(|(_, p)| p == "anthropic"));
        assert!(list.iter().any(|(_, p)| p == "openai"));
    }

    #[test]
    fn test_empty_key_rejected() {
        let mut vault = SecretVault::new();
        let mut map = TokenMap::new();

        assert!(map.register(&mut vault, b"", "anthropic").is_err());
    }

    #[test]
    fn test_unknown_token_not_found() {
        let vault = SecretVault::new();
        let map = TokenMap::new();

        let err = map.with_resolved_key("zkg-fake-token", &vault, |_| Ok(()));
        assert!(err.is_err());
    }

    #[test]
    fn test_serialization_roundtrip_no_secrets() {
        let mut vault = SecretVault::new();
        let mut map = TokenMap::new();

        let (t1, _) = map
            .register(&mut vault, b"key-anthropic", "anthropic")
            .unwrap();
        map.register(&mut vault, b"key-openai", "openai").unwrap();

        let bytes = map.to_bytes();

        // The serialized token map must not contain raw key bytes — those
        // live only in the encrypted vault file.
        assert!(!bytes
            .windows(b"key-anthropic".len())
            .any(|w| w == b"key-anthropic"));
        assert!(!bytes.windows(b"key-openai".len()).any(|w| w == b"key-openai"));

        let restored = TokenMap::from_bytes(&bytes).unwrap();
        assert_eq!(restored.len(), 2);
        restored
            .with_resolved_key(&t1, &vault, |k| {
                assert_eq!(k, b"key-anthropic");
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn test_corrupted_bytes_rejected() {
        assert!(TokenMap::from_bytes(&[]).is_err());
        assert!(TokenMap::from_bytes(&[0xFF, 0xFF, 0xFF, 0xFF]).is_err());
    }
}
