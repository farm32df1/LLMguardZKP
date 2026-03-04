pub mod audit;
pub mod handle;
pub mod persistence;
pub mod sanitizer;
pub mod scanner;
pub mod vault;

#[cfg(feature = "vault-encrypt")]
pub mod encrypted_persistence;

#[cfg(feature = "llm-proxy")]
pub mod proxy;

#[cfg(feature = "proxy-server")]
pub mod proxy_server;

pub use audit::{AuditEntry, AuditEvent, AuditLog};
pub use handle::{HandleId, KeyHandle};
pub use persistence::{load_vault, save_vault};
pub use sanitizer::{ContextSanitizer, RedactionRecord, SanitizedText};
pub use scanner::{ApiProvider, ContextScanner, DetectedKey};
pub use vault::SecretVault;

#[cfg(feature = "vault-encrypt")]
pub use encrypted_persistence::{
    load_vault_encrypted, migrate_vault_to_encrypted, save_vault_encrypted, VaultEncryptionParams,
};

#[cfg(feature = "llm-proxy")]
pub use proxy::{LlmProvider, LlmProxy, LlmRequest, LlmResponse};

#[cfg(feature = "proxy-server")]
pub use proxy_server::{start_proxy_server, ProxyConfig};
