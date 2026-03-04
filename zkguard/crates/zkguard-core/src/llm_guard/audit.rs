//! AuditLog — records security-relevant events for key lifecycle tracking.
//!
//! Every vault operation (store, access, revoke) generates a tamper-evident
//! audit entry hashed with `DOMAIN_AUDIT_ENTRY` for integrity verification.

use crate::utils::constants::DOMAIN_AUDIT_ENTRY;
use crate::utils::hash::{constant_time_eq_fixed, poseidon_hash};

use alloc::{string::String, vec::Vec};

/// Type of audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEvent {
    /// A key was stored in the vault.
    KeyStored,
    /// A key was accessed via `with_key()`.
    KeyAccessed,
    /// A key was revoked from the vault.
    KeyRevoked,
    /// A text was sanitized (keys redacted).
    TextSanitized,
    /// Tokens in LLM output were processed.
    TokensProcessed,
    /// A STARK proof was generated.
    ProofGenerated,
    /// A STARK proof was verified.
    ProofVerified,
}

impl AuditEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeyStored => "KEY_STORED",
            Self::KeyAccessed => "KEY_ACCESSED",
            Self::KeyRevoked => "KEY_REVOKED",
            Self::TextSanitized => "TEXT_SANITIZED",
            Self::TokensProcessed => "TOKENS_PROCESSED",
            Self::ProofGenerated => "PROOF_GENERATED",
            Self::ProofVerified => "PROOF_VERIFIED",
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::KeyStored => 0,
            Self::KeyAccessed => 1,
            Self::KeyRevoked => 2,
            Self::TextSanitized => 3,
            Self::TokensProcessed => 4,
            Self::ProofGenerated => 5,
            Self::ProofVerified => 6,
        }
    }
}

/// A single audit log entry with integrity hash.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Event type.
    pub event: AuditEvent,
    /// Human-readable detail (e.g. handle ID hex, key count).
    pub detail: String,
    /// Poseidon2 hash chaining this entry to the previous one.
    /// `hash = Poseidon2(DOMAIN_AUDIT_ENTRY, [seq, event, prev_hash, detail_hash])`.
    pub integrity_hash: [u8; 32],
}

/// Append-only audit log with hash-chain integrity.
///
/// Each entry's `integrity_hash` includes the previous entry's hash,
/// forming a tamper-evident chain (similar to a blockchain).
#[derive(Debug)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    /// Hash of the latest entry (used to chain the next one).
    latest_hash: [u8; 32],
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            latest_hash: [0u8; 32],
        }
    }

    /// Record an audit event.
    pub fn record(&mut self, event: AuditEvent, detail: String) {
        let seq = self.entries.len() as u64;

        // Build the hash input: [seq_bytes, event_byte, prev_hash, detail_hash]
        let detail_hash = poseidon_hash(detail.as_bytes(), DOMAIN_AUDIT_ENTRY);

        let mut hash_input = Vec::with_capacity(8 + 1 + 32 + 32);
        hash_input.extend_from_slice(&seq.to_le_bytes());
        hash_input.push(event.as_u8());
        hash_input.extend_from_slice(&self.latest_hash);
        hash_input.extend_from_slice(&detail_hash);

        let integrity_hash = poseidon_hash(&hash_input, DOMAIN_AUDIT_ENTRY);

        let entry = AuditEntry {
            seq,
            event,
            detail,
            integrity_hash,
        };

        self.latest_hash = integrity_hash;
        self.entries.push(entry);
    }

    /// Get all entries.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Verify the integrity of the entire audit chain.
    /// Returns `true` if all entries are consistent.
    pub fn verify_integrity(&self) -> bool {
        let mut prev_hash = [0u8; 32];

        for entry in &self.entries {
            let detail_hash = poseidon_hash(entry.detail.as_bytes(), DOMAIN_AUDIT_ENTRY);

            let mut hash_input = Vec::with_capacity(8 + 1 + 32 + 32);
            hash_input.extend_from_slice(&entry.seq.to_le_bytes());
            hash_input.push(entry.event.as_u8());
            hash_input.extend_from_slice(&prev_hash);
            hash_input.extend_from_slice(&detail_hash);

            let expected = poseidon_hash(&hash_input, DOMAIN_AUDIT_ENTRY);

            if !constant_time_eq_fixed(&expected, &entry.integrity_hash) {
                return false;
            }

            prev_hash = entry.integrity_hash;
        }

        true
    }

    /// Get the latest hash (chain head).
    pub fn latest_hash(&self) -> &[u8; 32] {
        &self.latest_hash
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_basic() {
        let mut log = AuditLog::new();
        assert!(log.is_empty());

        log.record(AuditEvent::KeyStored, "handle=abc123".into());
        assert_eq!(log.len(), 1);
        assert_eq!(log.entries()[0].event, AuditEvent::KeyStored);
        assert_eq!(log.entries()[0].seq, 0);
    }

    #[test]
    fn test_audit_log_chain() {
        let mut log = AuditLog::new();
        log.record(AuditEvent::KeyStored, "key1".into());
        log.record(AuditEvent::KeyAccessed, "key1".into());
        log.record(AuditEvent::KeyRevoked, "key1".into());

        assert_eq!(log.len(), 3);

        // Each entry should have a different hash
        let h0 = log.entries()[0].integrity_hash;
        let h1 = log.entries()[1].integrity_hash;
        let h2 = log.entries()[2].integrity_hash;
        assert_ne!(h0, h1);
        assert_ne!(h1, h2);
        assert_ne!(h0, h2);
    }

    #[test]
    fn test_audit_log_integrity_valid() {
        let mut log = AuditLog::new();
        log.record(AuditEvent::KeyStored, "store1".into());
        log.record(AuditEvent::TextSanitized, "2 keys".into());
        log.record(AuditEvent::ProofGenerated, "fibonacci".into());
        log.record(AuditEvent::ProofVerified, "valid".into());

        assert!(log.verify_integrity());
    }

    #[test]
    fn test_audit_log_integrity_tampered() {
        let mut log = AuditLog::new();
        log.record(AuditEvent::KeyStored, "store1".into());
        log.record(AuditEvent::KeyAccessed, "access1".into());

        // Tamper with an entry
        log.entries[0].detail = "tampered".into();

        assert!(!log.verify_integrity());
    }

    #[test]
    fn test_audit_event_str() {
        assert_eq!(AuditEvent::KeyStored.as_str(), "KEY_STORED");
        assert_eq!(AuditEvent::ProofVerified.as_str(), "PROOF_VERIFIED");
    }

    #[test]
    fn test_audit_log_empty_verify() {
        let log = AuditLog::new();
        assert!(log.verify_integrity());
    }
}
