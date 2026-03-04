//! ContextSanitizer — scan text, replace keys with handle tokens,
//! and reverse-substitute when LLM output contains tokens.

use crate::core::errors::Result;
use crate::llm_guard::handle::{HandleId, KeyHandle};
use crate::llm_guard::scanner::ContextScanner;
use crate::llm_guard::vault::SecretVault;
use crate::utils::constants::HANDLE_ID_BYTES;

use alloc::{collections::BTreeMap, string::String, vec::Vec};

/// Result of sanitizing a single text.
#[derive(Debug)]
pub struct SanitizedText {
    /// The text with all detected keys replaced by `{{ZKGUARD:<hex>}}` tokens.
    pub content: String,
    /// One entry per redaction, in order.
    pub redactions: Vec<RedactionRecord>,
}

/// Describes one replacement made during sanitization.
#[derive(Debug)]
pub struct RedactionRecord {
    /// The token inserted into the sanitized text.
    pub token: String,
    /// Provider that was detected.
    pub provider: crate::llm_guard::scanner::ApiProvider,
    /// Byte range in the *original* text.
    pub original_span: (usize, usize),
}

/// Wraps `SecretVault` + `ContextScanner` for use before/after LLM calls.
pub struct ContextSanitizer {
    vault: SecretVault,
    scanner: ContextScanner,
    /// Registry of issued handles, keyed by HandleId bytes.
    handles: BTreeMap<[u8; HANDLE_ID_BYTES], KeyHandle>,
}

#[allow(clippy::missing_fields_in_debug)]
impl core::fmt::Debug for ContextSanitizer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ContextSanitizer")
            .field("vault", &self.vault)
            .field("handle_count", &self.handles.len())
            .finish()
    }
}

impl ContextSanitizer {
    pub fn new() -> Self {
        Self {
            vault: SecretVault::new(),
            scanner: ContextScanner::new(),
            handles: BTreeMap::new(),
        }
    }

    /// Create a sanitizer with an existing vault (e.g. loaded from disk).
    pub fn from_vault(vault: SecretVault) -> Self {
        Self {
            vault,
            scanner: ContextScanner::new(),
            handles: BTreeMap::new(),
        }
    }

    /// Scan `text` for API keys, store each in the vault, and return the
    /// sanitized text with `{{ZKGUARD:…}}` placeholders.
    pub fn sanitize(&mut self, text: &str) -> Result<SanitizedText> {
        let mut detected = self.scanner.scan(text);

        if detected.is_empty() {
            return Ok(SanitizedText {
                content: text.into(),
                redactions: alloc::vec![],
            });
        }

        // Sort ascending by start position for single-pass replacement.
        detected.sort_by_key(|k| k.span.0);

        let mut result = String::with_capacity(text.len());
        let mut records = Vec::with_capacity(detected.len());
        let mut cursor = 0;

        for key in &detected {
            // Append text between the previous key and this one.
            result.push_str(&text[cursor..key.span.0]);

            let handle = self.vault.store(key.value.as_bytes())?;
            let token = handle.to_token();
            result.push_str(&token);
            records.push(RedactionRecord {
                token,
                provider: key.provider,
                original_span: key.span,
            });
            // Register handle for later lookup by process_tokens().
            self.handles.insert(handle.id.0, handle);
            cursor = key.span.1;
        }

        // Append remaining text after the last key.
        result.push_str(&text[cursor..]);

        Ok(SanitizedText {
            content: result,
            redactions: records,
        })
    }

    /// Process LLM output: call `f` for every `{{ZKGUARD:<hex>}}` token
    /// found in `text`.  `f` receives the vault + handle so it can make
    /// the actual API call without ever returning the key.
    pub fn process_tokens<F>(&self, text: &str, mut f: F) -> Result<String>
    where
        F: FnMut(&SecretVault, &KeyHandle) -> Result<String>,
    {
        let mut result = String::new();
        let mut rest = text;

        while let Some(start) = rest.find("{{ZKGUARD:") {
            result.push_str(&rest[..start]);
            let after_prefix = &rest[start + "{{ZKGUARD:".len()..];
            if let Some(end) = after_prefix.find("}}") {
                let hex = &after_prefix[..end];
                rest = &after_prefix[end + 2..];
                if let Some(id) = HandleId::from_hex(hex) {
                    if let Some(handle) = self.handles.get(&id.0) {
                        let replacement = f(&self.vault, handle)?;
                        result.push_str(&replacement);
                    } else {
                        // Token present but not in our registry — pass through.
                        result.push_str("{{ZKGUARD:");
                        result.push_str(hex);
                        result.push_str("}}");
                    }
                } else {
                    // Malformed hex — pass through.
                    result.push_str("{{ZKGUARD:");
                    result.push_str(hex);
                    result.push_str("}}");
                }
            } else {
                // No closing `}}` — pass through the unclosed marker and continue.
                result.push_str("{{ZKGUARD:");
                rest = after_prefix;
            }
        }
        result.push_str(rest);
        Ok(result)
    }

    pub fn vault(&self) -> &SecretVault {
        &self.vault
    }
    pub fn vault_mut(&mut self) -> &mut SecretVault {
        &mut self.vault
    }
    pub fn handle_count(&self) -> usize {
        self.handles.len()
    }
}

impl Default for ContextSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_keys_passthrough() {
        let mut s = ContextSanitizer::new();
        let r = s.sanitize("hello world").unwrap();
        assert_eq!(r.content, "hello world");
        assert!(r.redactions.is_empty());
    }

    #[test]
    fn test_key_replaced_with_token() {
        let mut s = ContextSanitizer::new();
        let key = "sk-ant-api03-".to_owned() + &"A".repeat(93);
        let text = alloc::format!("Use key {key} for the request");
        let r = s.sanitize(&text).unwrap();
        assert!(!r.content.contains("sk-ant-"));
        assert!(r.content.contains("{{ZKGUARD:"));
        assert_eq!(r.redactions.len(), 1);
    }

    #[test]
    fn test_vault_not_empty_after_sanitize() {
        let mut s = ContextSanitizer::new();
        let key = "sk-ant-api03-".to_owned() + &"B".repeat(93);
        let _ = s.sanitize(&alloc::format!("key={key}")).unwrap();
        assert!(!s.vault().is_empty());
    }

    #[test]
    fn test_handle_registry_populated() {
        let mut s = ContextSanitizer::new();
        let key = "sk-ant-api03-".to_owned() + &"C".repeat(93);
        let _ = s.sanitize(&alloc::format!("key={key}")).unwrap();
        assert_eq!(s.handle_count(), 1);
    }

    #[test]
    fn test_round_trip_sanitize_then_process() {
        let mut s = ContextSanitizer::new();
        let key = "sk-ant-api03-".to_owned() + &"D".repeat(93);
        let original = alloc::format!("Call API with {key} now");

        // Forward: sanitize (key -> token)
        let sanitized = s.sanitize(&original).unwrap();
        assert!(!sanitized.content.contains("sk-ant-"));
        assert!(sanitized.content.contains("{{ZKGUARD:"));

        // Reverse: process_tokens (token -> use key via closure)
        let processed = s
            .process_tokens(&sanitized.content, |vault, handle| {
                vault.with_key(handle, |key_bytes| {
                    // Verify we got the original key back
                    let key_str = core::str::from_utf8(key_bytes).unwrap();
                    assert!(key_str.starts_with("sk-ant-api03-"));
                    Ok("[API_RESPONSE]".into())
                })
            })
            .unwrap();

        assert!(processed.contains("[API_RESPONSE]"));
        assert!(!processed.contains("{{ZKGUARD:"));
    }

    #[test]
    fn test_process_tokens_no_tokens() {
        let s = ContextSanitizer::new();
        let result = s
            .process_tokens("plain text", |_, _| Ok("x".into()))
            .unwrap();
        assert_eq!(result, "plain text");
    }

    #[test]
    fn test_process_tokens_malformed_hex() {
        let s = ContextSanitizer::new();
        let input = "before {{ZKGUARD:not_valid_hex}} after";
        let result = s.process_tokens(input, |_, _| Ok("x".into())).unwrap();
        assert!(result.contains("{{ZKGUARD:not_valid_hex}}"));
    }

    #[test]
    fn test_process_tokens_unclosed_marker() {
        let s = ContextSanitizer::new();
        let input = "before {{ZKGUARD:abcd no closing";
        let result = s.process_tokens(input, |_, _| Ok("x".into())).unwrap();
        assert_eq!(result, "before {{ZKGUARD:abcd no closing");
    }
}
