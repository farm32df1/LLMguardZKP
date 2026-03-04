//! LlmProxy — HTTP proxy layer for LLM API calls with automatic key protection.
//!
//! Sanitizes outgoing prompts, makes the actual HTTP call using the key from
//! the vault (never exposed as a user-accessible string), and returns the response.
//!
//! Requires feature = "llm-proxy".

use crate::core::errors::{Result, ZKGuardError};
use crate::llm_guard::handle::KeyHandle;
use crate::llm_guard::sanitizer::ContextSanitizer;

/// Supported LLM providers with their API endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmProvider {
    Anthropic,
    OpenAI,
    Custom,
}

impl LlmProvider {
    /// Default API endpoint for this provider.
    pub fn default_endpoint(&self) -> &'static str {
        match self {
            Self::Anthropic => "https://api.anthropic.com/v1/messages",
            Self::OpenAI => "https://api.openai.com/v1/chat/completions",
            Self::Custom => "",
        }
    }
}

/// Request to send to an LLM.
#[derive(Debug, Clone)]
pub struct LlmRequest {
    /// The user prompt (will be sanitized before sending).
    pub prompt: String,
    /// Model identifier (e.g. "claude-sonnet-4-20250514", "gpt-4o").
    pub model: String,
    /// Maximum tokens to generate.
    pub max_tokens: u32,
    /// Optional system prompt.
    pub system: Option<String>,
}

/// Response from an LLM API call.
#[derive(Debug, Clone)]
pub struct LlmResponse {
    /// The sanitized prompt that was actually sent (no keys).
    pub sent_prompt: String,
    /// Raw response body from the API.
    pub raw_body: String,
    /// Extracted text content from the response.
    pub content: String,
    /// Number of keys that were protected in the prompt.
    pub keys_protected: usize,
    /// HTTP status code.
    pub status: u16,
}

/// HTTP proxy that sanitizes prompts and makes LLM API calls.
///
/// The proxy accesses API keys only inside `with_key()` closures —
/// the key travels directly from vault → HTTP Authorization header,
/// never stored in a user-accessible variable.
pub struct LlmProxy {
    sanitizer: ContextSanitizer,
    client: reqwest::blocking::Client,
    provider: LlmProvider,
    endpoint: String,
    /// The handle to the registered API key in the vault.
    api_key_handle: Option<KeyHandle>,
}

impl std::fmt::Debug for LlmProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmProxy")
            .field("provider", &self.provider)
            .field("endpoint", &self.endpoint)
            .field("has_key", &self.api_key_handle.is_some())
            .finish()
    }
}

impl LlmProxy {
    /// Create a new proxy for the given provider.
    pub fn new(provider: LlmProvider) -> Self {
        let endpoint = provider.default_endpoint().to_string();
        Self {
            sanitizer: ContextSanitizer::new(),
            client: reqwest::blocking::Client::new(),
            provider,
            endpoint,
            api_key_handle: None,
        }
    }

    /// Create a proxy with a custom endpoint URL.
    pub fn with_endpoint(provider: LlmProvider, endpoint: String) -> Self {
        Self {
            sanitizer: ContextSanitizer::new(),
            client: reqwest::blocking::Client::new(),
            provider,
            endpoint,
            api_key_handle: None,
        }
    }

    /// Register an API key for use. The key is stored in the vault
    /// and never returned as a string.
    ///
    /// Returns the number of bytes stored.
    pub fn register_key(&mut self, api_key: &str) -> Result<usize> {
        let key_bytes = api_key.as_bytes();
        let len = key_bytes.len();
        let handle = self.sanitizer.vault_mut().store(key_bytes)?;
        self.api_key_handle = Some(handle);
        Ok(len)
    }

    /// Access the sanitizer for manual sanitize/process_tokens operations.
    pub fn sanitizer(&self) -> &ContextSanitizer {
        &self.sanitizer
    }

    /// Access the sanitizer mutably.
    pub fn sanitizer_mut(&mut self) -> &mut ContextSanitizer {
        &mut self.sanitizer
    }

    /// Send a request to the LLM API.
    ///
    /// 1. Sanitizes the prompt (removes any embedded API keys)
    /// 2. Builds the HTTP request with the registered key (via vault closure)
    /// 3. Sends the request and returns the response
    ///
    /// The API key travels: vault → `with_key()` closure → HTTP header.
    /// It is never stored in a user-accessible variable.
    pub fn send(&mut self, request: &LlmRequest) -> Result<LlmResponse> {
        // Step 1: Sanitize the prompt
        let sanitized = self.sanitizer.sanitize(&request.prompt)?;
        let keys_protected = sanitized.redactions.len();

        // Step 2: Get the API key handle
        let handle = self
            .api_key_handle
            .as_ref()
            .ok_or(ZKGuardError::VaultError {
                reason: "No API key registered. Call register_key() first.".into(),
            })?
            .clone();

        // Step 3: Build JSON body
        let body = self.build_request_body(&sanitized.content, request);

        // Step 4: Make the HTTP call inside with_key() — key never leaves vault
        let endpoint = self.endpoint.clone();
        let provider = self.provider;
        let client = &self.client;

        let (status, raw_body) = self.sanitizer.vault().with_key(&handle, |key_bytes| {
            let key_str = std::str::from_utf8(key_bytes).map_err(|e| ZKGuardError::VaultError {
                reason: format!("invalid UTF-8 key: {}", e),
            })?;

            let mut req = client
                .post(&endpoint)
                .header("Content-Type", "application/json");

            // Set auth header based on provider
            req = match provider {
                LlmProvider::Anthropic => req
                    .header("x-api-key", key_str)
                    .header("anthropic-version", "2023-06-01"),
                LlmProvider::OpenAI | LlmProvider::Custom => {
                    req.header("Authorization", format!("Bearer {}", key_str))
                }
            };

            let resp = req
                .body(body.clone())
                .send()
                .map_err(|e| ZKGuardError::VaultError {
                    reason: format!("HTTP request failed: {}", e),
                })?;

            let status = resp.status().as_u16();
            let text = resp.text().map_err(|e| ZKGuardError::VaultError {
                reason: format!("Failed to read response: {}", e),
            })?;

            Ok((status, text))
        })?;

        // Step 5: Extract content from response
        let content = extract_content(&raw_body, provider);

        Ok(LlmResponse {
            sent_prompt: sanitized.content,
            raw_body,
            content,
            keys_protected,
            status,
        })
    }

    /// Build the JSON request body for the provider.
    fn build_request_body(&self, prompt: &str, request: &LlmRequest) -> String {
        match self.provider {
            LlmProvider::Anthropic => {
                let system_part = request
                    .system
                    .as_ref()
                    .map(|s| format!(r#","system":"{}""#, escape_json(s)))
                    .unwrap_or_default();
                format!(
                    r#"{{"model":"{}","max_tokens":{},"messages":[{{"role":"user","content":"{}"}}]{}}}"#,
                    escape_json(&request.model),
                    request.max_tokens,
                    escape_json(prompt),
                    system_part,
                )
            }
            LlmProvider::OpenAI | LlmProvider::Custom => {
                let mut messages = String::new();
                if let Some(sys) = &request.system {
                    messages.push_str(&format!(
                        r#"{{"role":"system","content":"{}"}},"#,
                        escape_json(sys),
                    ));
                }
                messages.push_str(&format!(
                    r#"{{"role":"user","content":"{}"}}"#,
                    escape_json(prompt),
                ));
                format!(
                    r#"{{"model":"{}","max_tokens":{},"messages":[{}]}}"#,
                    escape_json(&request.model),
                    request.max_tokens,
                    messages,
                )
            }
        }
    }
}

/// Extract text content from a JSON response body.
/// Falls back to returning the raw body if parsing fails.
fn extract_content(body: &str, provider: LlmProvider) -> String {
    // Try to parse as JSON and extract the content field.
    // We do minimal parsing without pulling in a full JSON parser at runtime
    // (serde_json is only available with the "serde" feature).
    match provider {
        LlmProvider::Anthropic => {
            // Anthropic: {"content": [{"type": "text", "text": "..."}]}
            extract_json_field(body, "text").unwrap_or_else(|| body.to_string())
        }
        LlmProvider::OpenAI | LlmProvider::Custom => {
            // OpenAI: {"choices": [{"message": {"content": "..."}}]}
            extract_json_field(body, "content").unwrap_or_else(|| body.to_string())
        }
    }
}

/// Minimal JSON field extractor — finds the LAST occurrence of `"field":"value"`.
/// This handles nested JSON where `"content"` may appear as both a key name and
/// a nested value. Returns None if not found.
fn extract_json_field(json: &str, field: &str) -> Option<String> {
    let pattern = format!(r#""{}""#, field);
    // Find the last occurrence to handle nested objects
    let idx = json.rfind(&pattern)?;
    let after = &json[idx + pattern.len()..];
    // Skip whitespace, colon, whitespace
    let after = after.trim_start();
    let after = after.strip_prefix(':')?;
    let after = after.trim_start();
    // Find the quoted value
    let after = after.strip_prefix('"')?;
    // Find the closing quote (handle escaped quotes)
    let mut result = String::new();
    let mut chars = after.chars();
    loop {
        match chars.next() {
            Some('\\') => {
                if let Some(c) = chars.next() {
                    match c {
                        'n' => result.push('\n'),
                        't' => result.push('\t'),
                        '"' => result.push('"'),
                        '\\' => result.push('\\'),
                        _ => {
                            result.push('\\');
                            result.push(c);
                        }
                    }
                }
            }
            Some('"') => break,
            Some(c) => result.push(c),
            None => return None,
        }
    }
    Some(result)
}

/// Escape a string for JSON embedding.
fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_json() {
        assert_eq!(escape_json(r#"hello "world""#), r#"hello \"world\""#);
        assert_eq!(escape_json("line1\nline2"), r#"line1\nline2"#);
        assert_eq!(escape_json("tab\there"), r#"tab\there"#);
    }

    #[test]
    fn test_extract_json_field_anthropic() {
        let body = r#"{"content":[{"type":"text","text":"Hello, world!"}]}"#;
        assert_eq!(
            extract_json_field(body, "text"),
            Some("Hello, world!".into())
        );
    }

    #[test]
    fn test_extract_json_field_openai() {
        let body = r#"{"choices":[{"message":{"role":"assistant","content":"Hi there"}}]}"#;
        assert_eq!(extract_json_field(body, "content"), Some("Hi there".into()));
    }

    #[test]
    fn test_extract_json_field_escaped() {
        let body = r#"{"text":"line1\nline2"}"#;
        let result = extract_json_field(body, "text").unwrap();
        assert_eq!(result, "line1\nline2");
    }

    #[test]
    fn test_extract_json_field_not_found() {
        let body = r#"{"foo":"bar"}"#;
        assert_eq!(extract_json_field(body, "missing"), None);
    }

    #[test]
    fn test_proxy_creation() {
        let proxy = LlmProxy::new(LlmProvider::Anthropic);
        assert_eq!(proxy.provider, LlmProvider::Anthropic);
        assert!(proxy.api_key_handle.is_none());
    }

    #[test]
    fn test_proxy_register_key() {
        let mut proxy = LlmProxy::new(LlmProvider::Anthropic);
        let key = "sk-ant-api03-test-key";
        let len = proxy.register_key(key).unwrap();
        assert_eq!(len, key.len());
        assert!(proxy.api_key_handle.is_some());
    }

    #[test]
    fn test_proxy_send_without_key() {
        let mut proxy = LlmProxy::new(LlmProvider::Anthropic);
        let req = LlmRequest {
            prompt: "hello".into(),
            model: "claude-sonnet-4-20250514".into(),
            max_tokens: 100,
            system: None,
        };
        let result = proxy.send(&req);
        assert!(result.is_err()); // No key registered
    }

    #[test]
    fn test_build_request_body_anthropic() {
        let proxy = LlmProxy::new(LlmProvider::Anthropic);
        let body = proxy.build_request_body(
            "hello",
            &LlmRequest {
                prompt: String::new(), // unused, we pass prompt directly
                model: "claude-sonnet-4-20250514".into(),
                max_tokens: 100,
                system: Some("You are helpful.".into()),
            },
        );
        assert!(body.contains(r#""model":"claude-sonnet-4-20250514""#));
        assert!(body.contains(r#""max_tokens":100"#));
        assert!(body.contains(r#""content":"hello""#));
        assert!(body.contains(r#""system":"You are helpful.""#));
    }

    #[test]
    fn test_build_request_body_openai() {
        let proxy = LlmProxy::new(LlmProvider::OpenAI);
        let body = proxy.build_request_body(
            "hello",
            &LlmRequest {
                prompt: String::new(),
                model: "gpt-4o".into(),
                max_tokens: 200,
                system: None,
            },
        );
        assert!(body.contains(r#""model":"gpt-4o""#));
        assert!(body.contains(r#""role":"user""#));
        assert!(body.contains(r#""content":"hello""#));
    }

    #[test]
    fn test_build_request_body_openai_with_system() {
        let proxy = LlmProxy::new(LlmProvider::OpenAI);
        let body = proxy.build_request_body(
            "hello",
            &LlmRequest {
                prompt: String::new(),
                model: "gpt-4o".into(),
                max_tokens: 200,
                system: Some("You are a helper.".into()),
            },
        );
        // Verify valid JSON structure: no stray quotes between system and user messages
        assert!(body.contains(r#"{"role":"system","content":"You are a helper."},{"role":"user","content":"hello"}"#),
            "Invalid JSON structure in body: {}", body);
    }

    #[test]
    fn test_provider_endpoints() {
        assert_eq!(
            LlmProvider::Anthropic.default_endpoint(),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            LlmProvider::OpenAI.default_endpoint(),
            "https://api.openai.com/v1/chat/completions"
        );
        assert_eq!(LlmProvider::Custom.default_endpoint(), "");
    }
}
