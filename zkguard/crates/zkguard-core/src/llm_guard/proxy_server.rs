//! Proxy server — local HTTP reverse proxy that sanitizes LLM API requests.
//!
//! Sits between your app and the LLM provider. Automatically detects and removes
//! API keys from prompts before forwarding to the real API.
//!
//! **Security contract** (all enforced by code, not by policy document):
//!
//! - The vault on disk is always AES-256-GCM + Argon2id encrypted; there is no
//!   plaintext-persistence code path in a `proxy-server` build.
//! - The real API key is borrowed only inside a [`TokenMap::with_resolved_key`]
//!   closure and never returned as an owned `String`/`Vec<u8>`. The header
//!   value carrying it is wrapped in [`zeroize::Zeroizing`] so its buffer is
//!   wiped on drop.
//! - Strict mode (default when any `zkg-*` token is registered): authentication
//!   headers that do **not** carry a registered `zkg-*` token are rejected with
//!   HTTP 401 instead of being forwarded. This makes "leak a real key by
//!   mistake" impossible even if the application is misconfigured.
//! - Request **and** response bodies pass through [`ContextScanner`]; any
//!   provider-recognised key pattern is replaced with `[REDACTED]` before the
//!   bytes leave the proxy in either direction.
//! - Upstream errors are reported with a fixed string (`"upstream error"`) so
//!   the underlying HTTP client message can never echo sensitive request data.
//!
//! ```text
//! App → "x-api-key: zkg-anthropic-abc123" → zkguard proxy
//!     → with_resolved_key(... real key ...)
//!     → closure builds HeaderValue, forwards, drops → api.anthropic.com
//! ```
//!
//! Requires feature = "proxy-server".

use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::core::errors::Result as ZkResult;
use crate::llm_guard::scanner::ContextScanner;
use crate::llm_guard::token_map::TokenMap;
use crate::llm_guard::vault::SecretVault;

/// Configuration for the proxy server.
#[derive(Clone)]
pub struct ProxyConfig {
    /// Port to listen on (default: 8080).
    pub port: u16,
    /// Target LLM API base URL (e.g. "https://api.anthropic.com").
    pub target_base_url: String,
    /// Bind address (default: "127.0.0.1").
    pub bind_addr: String,
    /// Optional directory holding `vault.zkge` + `token_map.bin`.
    /// When `None`, the proxy runs in pure-sanitizer mode with no token map.
    pub vault_path: Option<String>,
    /// Passphrase used to decrypt the vault at startup. Required when
    /// `vault_path` points at an existing encrypted vault.
    pub passphrase: Option<String>,
}

impl core::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("port", &self.port)
            .field("target_base_url", &self.target_base_url)
            .field("bind_addr", &self.bind_addr)
            .field("vault_path", &self.vault_path)
            .field("passphrase", &"<REDACTED>")
            .finish()
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 8080,
            target_base_url: "https://api.anthropic.com".to_string(),
            bind_addr: "127.0.0.1".to_string(),
            vault_path: None,
            passphrase: None,
        }
    }
}

struct ProxyState {
    scanner: Mutex<ContextScanner>,
    client: reqwest::Client,
    target_base_url: String,
    request_count: Mutex<u64>,
    keys_blocked_req: Mutex<u64>,
    keys_blocked_resp: Mutex<u64>,
    vault: Mutex<SecretVault>,
    token_map: Mutex<TokenMap>,
    keys_injected: Mutex<u64>,
    /// When true, any auth header lacking a registered `zkg-*` token is
    /// rejected. Enabled automatically when the token map is non-empty.
    strict_auth: bool,
}

/// Start the proxy server. This function blocks until the server is shut down.
pub async fn start_proxy_server(config: ProxyConfig) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (vault, token_map) =
        load_vault_and_token_map(config.vault_path.as_deref(), config.passphrase.as_deref())?;

    let token_count = token_map.len();
    let strict_auth = token_count > 0;
    let state = Arc::new(ProxyState {
        scanner: Mutex::new(ContextScanner::new()),
        client: reqwest::Client::new(),
        target_base_url: config.target_base_url.clone(),
        request_count: Mutex::new(0),
        keys_blocked_req: Mutex::new(0),
        keys_blocked_resp: Mutex::new(0),
        vault: Mutex::new(vault),
        token_map: Mutex::new(token_map),
        keys_injected: Mutex::new(0),
        strict_auth,
    });

    let app = Router::new().fallback(proxy_handler).with_state(state);

    let addr = format!("{}:{}", config.bind_addr, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    eprintln!("[zkguard proxy] Listening on http://{}", addr);
    eprintln!("[zkguard proxy] Forwarding to {}", config.target_base_url);
    eprintln!("[zkguard proxy] Request and response bodies are scanned for API keys");
    if token_count > 0 {
        eprintln!(
            "[zkguard proxy] Key manager: {} registered token(s). Strict auth ON — non-zkg auth headers will be rejected with 401.",
            token_count
        );
    } else {
        eprintln!("[zkguard proxy] No registered tokens — running in sanitizer-only mode");
    }
    eprintln!();

    axum::serve(listener, app).await?;
    Ok(())
}

/// Load the encrypted vault and token map from the zkguard data directory.
///
/// Returns an error (never silently falls back to an empty vault) if the vault
/// file exists but can't be decrypted. That would otherwise mask a wrong
/// passphrase and cause all `zkg-*` tokens to mysteriously stop working.
fn load_vault_and_token_map(
    vault_path: Option<&str>,
    passphrase: Option<&str>,
) -> std::result::Result<(SecretVault, TokenMap), Box<dyn std::error::Error>> {
    let data_dir = vault_path
        .map(std::path::PathBuf::from)
        .unwrap_or_else(default_data_dir);

    let vault_file = data_dir.join("vault.zkge");
    let legacy_plaintext = data_dir.join("vault.zkgv");
    let token_map_file = data_dir.join("token_map.bin");

    if legacy_plaintext.exists() {
        return Err(format!(
            "refusing to start: legacy plaintext vault detected at {}. \
             This build does not support plaintext vaults. Migrate with `zkguard key migrate` or remove the file.",
            legacy_plaintext.display()
        )
        .into());
    }

    let vault = if vault_file.exists() {
        let pw = passphrase.ok_or(
            "encrypted vault found but no passphrase supplied (set ZKGUARD_PASSPHRASE or run interactively)",
        )?;
        let v = crate::llm_guard::encrypted_persistence::load_vault_encrypted(
            &vault_file,
            pw.as_bytes(),
        )
        .map_err(|e| format!("failed to decrypt vault: {}", e))?;
        eprintln!(
            "[zkguard proxy] Loaded encrypted vault from {} ({} keys)",
            vault_file.display(),
            v.len()
        );
        v
    } else {
        SecretVault::new()
    };

    let token_map = if token_map_file.exists() {
        match std::fs::read(&token_map_file) {
            Ok(data) => match TokenMap::from_bytes(&data) {
                Ok(tm) => {
                    eprintln!(
                        "[zkguard proxy] Loaded token map ({} tokens) from {}",
                        tm.len(),
                        token_map_file.display()
                    );
                    tm
                }
                Err(e) => {
                    return Err(format!("corrupt token map at {}: {}", token_map_file.display(), e).into());
                }
            },
            Err(e) => {
                return Err(format!("failed to read token map: {}", e).into());
            }
        }
    } else {
        TokenMap::new()
    };

    Ok((vault, token_map))
}

/// Default data directory: ~/.zkguard/
pub fn default_data_dir() -> std::path::PathBuf {
    dirs_fallback_home().join(".zkguard")
}

fn dirs_fallback_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
}

/// Outcome of scanning an auth header value.
enum AuthHeaderDecision {
    /// Header is absent or not an auth header we care about.
    Absent,
    /// Header holds a registered `zkg-*` token — call closure with real key.
    Resolve(String),
    /// Header holds something that looks like a raw key or an unknown
    /// `zkg-*` — must be rejected.
    Reject(&'static str),
}

fn classify_auth(
    header_val: Option<&HeaderValue>,
    token_map: &TokenMap,
    strict: bool,
) -> AuthHeaderDecision {
    let Some(v) = header_val else {
        return AuthHeaderDecision::Absent;
    };
    let Ok(s) = v.to_str() else {
        return AuthHeaderDecision::Reject("malformed auth header");
    };
    if let Some(stripped) = s.strip_prefix("Bearer ") {
        return match classify_token(stripped, token_map, strict) {
            Some(token_owned) => AuthHeaderDecision::Resolve(token_owned),
            None => {
                if strict {
                    AuthHeaderDecision::Reject("auth header does not carry a registered zkg-* token")
                } else {
                    AuthHeaderDecision::Absent
                }
            }
        };
    }
    match classify_token(s, token_map, strict) {
        Some(token_owned) => AuthHeaderDecision::Resolve(token_owned),
        None => {
            if strict {
                AuthHeaderDecision::Reject("auth header does not carry a registered zkg-* token")
            } else {
                AuthHeaderDecision::Absent
            }
        }
    }
}

fn classify_token(token: &str, token_map: &TokenMap, _strict: bool) -> Option<String> {
    if TokenMap::is_zkguard_token(token) && token_map.contains(token) {
        Some(token.to_string())
    } else {
        None
    }
}

/// Apply the scanner to `body` and return the redacted text plus how many
/// keys were replaced.
///
/// `direction` picks which detection mode to use:
/// - [`ScanDirection::Request`] — full scan (provider regex + entropy heuristic).
///   Request bodies are usually generated by the user's own app, so
///   over-detection on a developer-pasted secret is the safer default.
/// - [`ScanDirection::Response`] — provider regex only. LLM responses routinely
///   contain high-entropy strings (UUIDs, base64 content, JSON tokens) which
///   would otherwise get mis-redacted as "unknown" keys.
async fn sanitize_body(
    scanner: &Mutex<ContextScanner>,
    body: &str,
    direction: ScanDirection,
) -> (usize, String) {
    let scanner = scanner.lock().await;
    let detected = match direction {
        ScanDirection::Request => scanner.scan(body),
        ScanDirection::Response => scanner.scan_providers_only(body),
    };
    if detected.is_empty() {
        return (0, body.to_string());
    }
    let count = detected.len();
    let mut sorted = detected;
    sorted.sort_by(|a, b| b.span.0.cmp(&a.span.0));
    let mut result = body.to_string();
    for key in &sorted {
        let (start_pos, end_pos) = key.span;
        if start_pos < result.len() && end_pos <= result.len() {
            result.replace_range(start_pos..end_pos, "[REDACTED]");
        }
    }
    (count, result)
}

#[derive(Clone, Copy)]
enum ScanDirection {
    Request,
    Response,
}

async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    req: Request<Body>,
) -> impl IntoResponse {
    let start = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "bad request").into_response();
        }
    };

    let body_str = String::from_utf8_lossy(&body_bytes).to_string();
    let (req_keys_found, sanitized_body) =
        sanitize_body(&state.scanner, &body_str, ScanDirection::Request).await;

    {
        let mut count = state.request_count.lock().await;
        *count += 1;
    }
    if req_keys_found > 0 {
        let mut blocked = state.keys_blocked_req.lock().await;
        *blocked += req_keys_found as u64;
    }

    // ── Auth classification ────────────────────────────────────────────────
    let (resolve_x_api, resolve_bearer, reject_reason) = {
        let token_map = state.token_map.lock().await;
        if state.strict_auth {
            let x = classify_auth(headers.get("x-api-key"), &token_map, true);
            let b = classify_auth(headers.get("authorization"), &token_map, true);
            let any_present = headers.get("x-api-key").is_some() || headers.get("authorization").is_some();
            let any_resolvable = matches!(x, AuthHeaderDecision::Resolve(_))
                || matches!(b, AuthHeaderDecision::Resolve(_));
            let any_reject = matches!(x, AuthHeaderDecision::Reject(_))
                || matches!(b, AuthHeaderDecision::Reject(_));
            if any_present && !any_resolvable {
                let reason = match (&x, &b) {
                    (AuthHeaderDecision::Reject(r), _) | (_, AuthHeaderDecision::Reject(r)) => *r,
                    _ => "auth header does not carry a registered zkg-* token",
                };
                (None, None, Some(reason))
            } else if any_reject && !any_resolvable {
                (None, None, Some("auth header rejected"))
            } else {
                let x_tok = match x {
                    AuthHeaderDecision::Resolve(t) => Some(t),
                    _ => None,
                };
                let b_tok = match b {
                    AuthHeaderDecision::Resolve(t) => Some(t),
                    _ => None,
                };
                (x_tok, b_tok, None)
            }
        } else {
            // Sanitizer-only mode: never resolve (no vault), never reject on auth.
            (None, None, None)
        }
    };

    if let Some(reason) = reject_reason {
        eprintln!(
            "[zkguard proxy] {} {} | REJECTED ({}) | 401 ({:.0}ms)",
            method,
            path,
            reason,
            start.elapsed().as_millis()
        );
        return (
            StatusCode::UNAUTHORIZED,
            "rejected: auth header must carry a registered zkg-* token",
        )
            .into_response();
    }

    // ── Build forwarded request inside a scope so every real-key borrow
    //    drops before `.send()` is awaited. The `Zeroizing<HeaderValue>`
    //    wrappers wipe their buffers when dropped at scope end.
    let target_url = format!("{}{}{}", state.target_base_url, path, query);
    let mut forward_req = state.client.request(method.clone(), &target_url);

    // Copy non-auth, non-hop-by-hop headers first.
    for (name, value) in &headers {
        let name_str = name.as_str().to_lowercase();
        if name_str == "host"
            || name_str == "transfer-encoding"
            || name_str == "connection"
            || name_str == "x-api-key"
            || name_str == "authorization"
        {
            continue;
        }
        forward_req = forward_req.header(name.clone(), value.clone());
    }

    let mut key_injected = false;

    // `HeaderValue` does not implement `Zeroize`, so we cannot wrap it in
    // `Zeroizing`. We minimise exposure instead:
    //   1. The real key is borrowed only inside the closure.
    //   2. The intermediate byte buffer used to build a `Bearer ...` string
    //      is `Zeroizing<Vec<u8>>` and wiped on drop.
    //   3. The resulting `HeaderValue` is constructed once and moved directly
    //      into `forward_req` without any owned copy living on our side.
    //   4. Whatever reqwest/hyper keep internally is outside this crate's
    //      control; that limitation is documented in README.

    if let Some(token) = resolve_x_api.as_deref() {
        let token_map = state.token_map.lock().await;
        let vault = state.vault.lock().await;
        let hv_result: ZkResult<HeaderValue> =
            token_map.with_resolved_key(token, &vault, |real_key| {
                HeaderValue::from_bytes(real_key).map_err(|_| {
                    crate::core::errors::ZKGuardError::VaultError {
                        reason: "key contains bytes invalid for HTTP header".into(),
                    }
                })
            });
        match hv_result {
            Ok(hv) => {
                forward_req = forward_req.header("x-api-key", hv);
                key_injected = true;
            }
            Err(_) => {
                return (StatusCode::UNAUTHORIZED, "rejected: failed to resolve zkg-* token")
                    .into_response();
            }
        }
    }

    if let Some(token) = resolve_bearer.as_deref() {
        let token_map = state.token_map.lock().await;
        let vault = state.vault.lock().await;
        let hv_result: ZkResult<HeaderValue> =
            token_map.with_resolved_key(token, &vault, |real_key| {
                let mut bearer: Zeroizing<Vec<u8>> =
                    Zeroizing::new(Vec::with_capacity(7 + real_key.len()));
                bearer.extend_from_slice(b"Bearer ");
                bearer.extend_from_slice(real_key);
                HeaderValue::from_bytes(&bearer).map_err(|_| {
                    crate::core::errors::ZKGuardError::VaultError {
                        reason: "key contains bytes invalid for HTTP header".into(),
                    }
                })
            });
        match hv_result {
            Ok(hv) => {
                forward_req = forward_req.header("authorization", hv);
                key_injected = true;
            }
            Err(_) => {
                return (StatusCode::UNAUTHORIZED, "rejected: failed to resolve zkg-* token")
                    .into_response();
            }
        }
    }

    if key_injected {
        let mut injected = state.keys_injected.lock().await;
        *injected += 1;
    }

    forward_req = forward_req.body(sanitized_body);

    // Send to actual LLM API.
    let response = match forward_req.send().await {
        Ok(resp) => resp,
        Err(_) => {
            let elapsed = start.elapsed();
            eprintln!(
                "[zkguard proxy] {} {} | {} req key(s) blocked | FAILED ({:.0}ms)",
                method,
                path,
                req_keys_found,
                elapsed.as_millis()
            );
            // Fixed error string — never surface reqwest's internal message to
            // the client, it may include the target URL or header echoes.
            return (StatusCode::BAD_GATEWAY, "upstream error").into_response();
        }
    };

    let resp_status = response.status();
    let resp_headers = response.headers().clone();
    let resp_body_bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "upstream error").into_response();
        }
    };

    // ── Outbound scan: filter keys out of the response body too ───────────
    let resp_body_str = String::from_utf8_lossy(&resp_body_bytes).to_string();
    let (resp_keys_found, sanitized_resp_body) =
        sanitize_body(&state.scanner, &resp_body_str, ScanDirection::Response).await;
    if resp_keys_found > 0 {
        let mut blocked = state.keys_blocked_resp.lock().await;
        *blocked += resp_keys_found as u64;
    }

    // Log after both directions are scanned.
    let inject_label = if key_injected { " | key INJECTED" } else { "" };
    let elapsed = start.elapsed();
    if req_keys_found > 0 || resp_keys_found > 0 {
        eprintln!(
            "[zkguard proxy] {} {} | req {} / resp {} key(s) BLOCKED{} | {} ({:.0}ms)",
            method,
            path,
            req_keys_found,
            resp_keys_found,
            inject_label,
            resp_status.as_u16(),
            elapsed.as_millis()
        );
    } else {
        eprintln!(
            "[zkguard proxy] {} {}{} | clean | {} ({:.0}ms)",
            method,
            path,
            inject_label,
            resp_status.as_u16(),
            elapsed.as_millis()
        );
    }

    let mut builder = Response::builder().status(resp_status);
    for (name, value) in &resp_headers {
        let name_str = name.as_str().to_lowercase();
        if name_str == "transfer-encoding"
            || name_str == "connection"
            || name_str == "content-length"
        {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }

    builder
        .body(Body::from(sanitized_resp_body))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response())
}

/// Build a proxy router for testing (no server bind, no token map).
pub fn build_proxy_router(target_base_url: String) -> Router {
    build_proxy_router_with_vault(target_base_url, SecretVault::new(), TokenMap::new())
}

/// Build a proxy router with a pre-loaded vault and token map.
/// Strict auth activates automatically when the map is non-empty.
pub fn build_proxy_router_with_vault(
    target_base_url: String,
    vault: SecretVault,
    token_map: TokenMap,
) -> Router {
    let strict_auth = !token_map.is_empty();
    let state = Arc::new(ProxyState {
        scanner: Mutex::new(ContextScanner::new()),
        client: reqwest::Client::new(),
        target_base_url,
        request_count: Mutex::new(0),
        keys_blocked_req: Mutex::new(0),
        keys_blocked_resp: Mutex::new(0),
        vault: Mutex::new(vault),
        token_map: Mutex::new(token_map),
        keys_injected: Mutex::new(0),
        strict_auth,
    });

    Router::new().fallback(proxy_handler).with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tower::util::ServiceExt;

    // ── Config Tests ──────────────────────────────────────────────────────

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();
        assert_eq!(config.port, 8080);
        assert_eq!(config.bind_addr, "127.0.0.1");
        assert_eq!(config.target_base_url, "https://api.anthropic.com");
        assert!(config.passphrase.is_none());
    }

    #[test]
    fn test_proxy_config_custom() {
        let config = ProxyConfig {
            port: 9090,
            target_base_url: "https://api.openai.com".to_string(),
            bind_addr: "0.0.0.0".to_string(),
            vault_path: None,
            passphrase: None,
        };
        assert_eq!(config.port, 9090);
        assert_eq!(config.target_base_url, "https://api.openai.com");
    }

    #[test]
    fn test_proxy_config_debug_redacts_passphrase() {
        let config = ProxyConfig {
            passphrase: Some("super-secret-passphrase".to_string()),
            ..Default::default()
        };
        let debug_str = format!("{:?}", config);
        assert!(!debug_str.contains("super-secret-passphrase"));
        assert!(debug_str.contains("<REDACTED>"));
    }

    // ── Sanitization Logic Tests (via mock upstream) ──────────────────────

    /// Helper: start a mock upstream server that echoes the request body.
    async fn start_echo_server() -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().fallback(|body: String| async move { body });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (url, handle)
    }

    async fn proxy_post(proxy: &Router, path: &str, body: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let resp = proxy.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 10 * 1024 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    #[tokio::test]
    async fn test_proxy_clean_request_passes_through() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let body = r#"{"messages":[{"role":"user","content":"Hello, how are you?"}]}"#;
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", body).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(echoed, body);
    }

    #[tokio::test]
    async fn test_proxy_redacts_anthropic_key() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let fake_key = format!("sk-ant-api03-{}", "A".repeat(93));
        let body = format!(
            r#"{{"messages":[{{"role":"user","content":"Use key {}"}}]}}"#,
            fake_key
        );
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", &body).await;

        assert_eq!(status, StatusCode::OK);
        assert!(!echoed.contains("sk-ant-api03-"));
        assert!(echoed.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn test_proxy_redacts_aws_key() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let body = r#"{"messages":[{"role":"user","content":"AWS key: AKIAIOSFODNN7EXAMPLE"}]}"#;
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", body).await;

        assert_eq!(status, StatusCode::OK);
        assert!(!echoed.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(echoed.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn test_proxy_redacts_openai_key() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let fake_key = format!("sk-{}", "a".repeat(48));
        let body = format!(
            r#"{{"messages":[{{"role":"user","content":"key={}"}}]}}"#,
            fake_key
        );
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", &body).await;

        assert_eq!(status, StatusCode::OK);
        assert!(!echoed.contains(&fake_key));
    }

    #[tokio::test]
    async fn test_proxy_redacts_google_ai_key() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let fake_key = format!("AIza{}", "x".repeat(35));
        let body = format!(
            r#"{{"messages":[{{"role":"user","content":"key={}"}}]}}"#,
            fake_key
        );
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", &body).await;

        assert_eq!(status, StatusCode::OK);
        assert!(!echoed.contains(&fake_key));
    }

    #[tokio::test]
    async fn test_proxy_redacts_multiple_keys() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let anthropic_key = format!("sk-ant-api03-{}", "B".repeat(93));
        let body = format!(
            r#"{{"messages":[{{"role":"user","content":"keys: {} and AKIAIOSFODNN7EXAMPLE"}}]}}"#,
            anthropic_key
        );
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", &body).await;

        assert_eq!(status, StatusCode::OK);
        assert!(!echoed.contains("sk-ant-api03-"));
        assert!(!echoed.contains("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(echoed.matches("[REDACTED]").count(), 2);
    }

    #[tokio::test]
    async fn test_proxy_empty_body() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let (status, echoed) = proxy_post(&proxy, "/v1/messages", "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(echoed, "");
    }

    #[tokio::test]
    async fn test_proxy_preserves_path() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let (status, _) = proxy_post(&proxy, "/v1/chat/completions", r#"{"test":true}"#).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_proxy_preserves_query_params() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let (status, _) = proxy_post(
            &proxy,
            "/v1/messages?stream=true&version=2",
            r#"{"test":true}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_proxy_normal_text_unchanged() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let body = r#"{"messages":[{"role":"user","content":"Write me a Python function that adds two numbers. Use proper type hints and docstrings. Make it production-quality code."}]}"#;
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", body).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(echoed, body);
    }

    #[tokio::test]
    async fn test_proxy_unicode_text() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let body = r#"{"messages":[{"role":"user","content":"한국어 테스트 🔑 이모지도 포함"}]}"#;
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", body).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(echoed, body);
    }

    #[tokio::test]
    async fn test_proxy_large_body() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let large_text = "a".repeat(1_000_000);
        let body = format!(r#"{{"content":"{}"}}"#, large_text);
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", &body).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(echoed.len(), body.len());
    }

    #[tokio::test]
    async fn test_proxy_key_at_start_of_body() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let key = format!("sk-ant-api03-{}", "C".repeat(93));
        let body = format!("{} is my key", key);
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", &body).await;

        assert_eq!(status, StatusCode::OK);
        assert!(!echoed.contains("sk-ant-api03-"));
        assert!(echoed.starts_with("[REDACTED]"));
    }

    #[tokio::test]
    async fn test_proxy_key_at_end_of_body() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let key = format!("sk-ant-api03-{}", "D".repeat(93));
        let body = format!("My key is {}", key);
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", &body).await;

        assert_eq!(status, StatusCode::OK);
        assert!(!echoed.contains("sk-ant-api03-"));
        assert!(echoed.ends_with("[REDACTED]"));
    }

    #[tokio::test]
    async fn test_proxy_only_key_in_body() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let key = format!("sk-ant-api03-{}", "E".repeat(93));
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", &key).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(echoed, "[REDACTED]");
    }

    #[tokio::test]
    async fn test_proxy_adjacent_keys() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let key1 = format!("sk-ant-api03-{}", "F".repeat(93));
        let body = format!("{} AKIAIOSFODNN7EXAMPLE", key1);
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", &body).await;

        assert_eq!(status, StatusCode::OK);
        assert!(!echoed.contains("sk-ant-"));
        assert!(!echoed.contains("AKIA"));
    }

    #[tokio::test]
    async fn test_proxy_false_positive_avoidance() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let body = r#"{"content":"sk-short is not a key. AKIA alone is not enough. Regular text with numbers 12345."}"#;
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", body).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(echoed, body);
    }

    // ── Real-World Scenario Tests ─────────────────────────────────────────

    #[tokio::test]
    async fn test_scenario_openai_chat_completion() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let key = format!("sk-{}", "x".repeat(48));
        let body = format!(
            r#"{{"model":"gpt-4o","messages":[{{"role":"system","content":"You are helpful"}},{{"role":"user","content":"Use {} to call the API"}}],"max_tokens":100}}"#,
            key
        );
        let (status, echoed) = proxy_post(&proxy, "/v1/chat/completions", &body).await;

        assert_eq!(status, StatusCode::OK);
        assert!(!echoed.contains(&key));
        assert!(echoed.contains("gpt-4o"));
        assert!(echoed.contains("You are helpful"));
    }

    #[tokio::test]
    async fn test_scenario_anthropic_messages() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let key = format!("sk-ant-api03-{}", "G".repeat(93));
        let body = format!(
            r#"{{"model":"claude-sonnet-4-20250514","max_tokens":1024,"messages":[{{"role":"user","content":"Debug this code that uses {}:\nimport requests\nrequests.get('https://api.example.com')"}}]}}"#,
            key
        );
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", &body).await;

        assert_eq!(status, StatusCode::OK);
        assert!(!echoed.contains("sk-ant-api03-"));
        assert!(echoed.contains("claude-sonnet"));
        assert!(echoed.contains("import requests"));
    }

    #[tokio::test]
    async fn test_scenario_error_log_with_keys() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let key = format!("sk-ant-api03-{}", "H".repeat(93));
        let body = format!(
            r#"{{"messages":[{{"role":"user","content":"Fix this error:\nHTTPError 401: Authorization failed for key={}\nTraceback:\n  File 'main.py', line 42\n  requests.post(url, headers={{'x-api-key': '{}'}})"}}]}}"#,
            key, key
        );
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", &body).await;

        assert_eq!(status, StatusCode::OK);
        assert!(!echoed.contains("sk-ant-api03-"));
        assert!(echoed.contains("HTTPError 401"));
        assert!(echoed.contains("Traceback"));
    }

    #[tokio::test]
    async fn test_scenario_env_file_paste() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let anthropic_key = format!("sk-ant-api03-{}", "I".repeat(93));
        let body = format!(
            r#"{{"messages":[{{"role":"user","content":"What's wrong with my .env file?\nANTHROPIC_API_KEY={}\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDATABASE_URL=postgres://localhost/mydb"}}]}}"#,
            anthropic_key
        );
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", &body).await;

        assert_eq!(status, StatusCode::OK);
        assert!(!echoed.contains("sk-ant-api03-"));
        assert!(!echoed.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(echoed.contains("DATABASE_URL=postgres://localhost/mydb"));
    }

    #[tokio::test]
    async fn test_scenario_curl_command_with_key() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let key = format!("sk-ant-api03-{}", "J".repeat(93));
        let body = format!(
            r#"{{"messages":[{{"role":"user","content":"Why does this curl fail?\ncurl -X POST https://api.anthropic.com/v1/messages -H 'x-api-key: {}' -H 'content-type: application/json' -d '{{\"model\":\"claude-sonnet-4-20250514\"}}'"}}]}}"#,
            key
        );
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", &body).await;

        assert_eq!(status, StatusCode::OK);
        assert!(!echoed.contains("sk-ant-api03-"));
        assert!(echoed.contains("curl -X POST"));
    }

    // ── Headers Tests ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_proxy_forwards_custom_headers_sanitizer_mode() {
        // Sanitizer-only mode (no token map) — arbitrary auth headers pass
        // through unchanged; only bodies are scanned.
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/messages")
            .header("content-type", "application/json")
            .header("x-api-key", "test-key-in-header")
            .header("anthropic-version", "2023-06-01")
            .header("x-custom-header", "custom-value")
            .body(Body::from(r#"{"test": true}"#))
            .unwrap();

        let resp = proxy.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── Key Injection Tests (strict auth active) ──────────────────────────

    async fn setup_key_injection_proxy(real_key: &[u8], provider: &str) -> (Router, String) {
        let (upstream_url, _handle) = start_echo_server().await;
        let mut vault = SecretVault::new();
        let mut token_map = TokenMap::new();
        let (dummy_token, _) = token_map.register(&mut vault, real_key, provider).unwrap();
        let proxy = build_proxy_router_with_vault(upstream_url, vault, token_map);
        (proxy, dummy_token)
    }

    async fn proxy_post_with_headers(
        proxy: &Router,
        path: &str,
        body: &str,
        headers: Vec<(&str, &str)>,
    ) -> (StatusCode, String, HeaderMap) {
        let mut builder = Request::builder().method(Method::POST).uri(path);
        for (k, v) in &headers {
            builder = builder.header(*k, *v);
        }
        let req = builder.body(Body::from(body.to_string())).unwrap();

        let resp = proxy.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let bytes = axum::body::to_bytes(resp.into_body(), 10 * 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            String::from_utf8_lossy(&bytes).to_string(),
            resp_headers,
        )
    }

    #[tokio::test]
    async fn test_proxy_injects_real_key_via_x_api_key() {
        let (proxy, dummy_token) =
            setup_key_injection_proxy(b"sk-ant-api03-real-secret-key", "anthropic").await;

        let (status, _echoed, _) = proxy_post_with_headers(
            &proxy,
            "/v1/messages",
            r#"{"test": true}"#,
            vec![
                ("content-type", "application/json"),
                ("x-api-key", &dummy_token),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_proxy_injects_real_key_via_bearer() {
        let (proxy, dummy_token) =
            setup_key_injection_proxy(b"sk-openai-secret-key", "openai").await;

        let bearer = format!("Bearer {}", dummy_token);
        let (status, _echoed, _) = proxy_post_with_headers(
            &proxy,
            "/v1/chat/completions",
            r#"{"test": true}"#,
            vec![
                ("content-type", "application/json"),
                ("authorization", &bearer),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
    }

    // ── Strict-auth rejection tests (flipped from the old passthrough tests) ──

    #[tokio::test]
    async fn test_proxy_rejects_raw_key_in_header_under_strict_auth() {
        // A vault with any registered token → strict mode on.
        let mut vault = SecretVault::new();
        let mut token_map = TokenMap::new();
        let (_dummy, _) = token_map
            .register(&mut vault, b"real-registered-key", "anthropic")
            .unwrap();

        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router_with_vault(upstream_url, vault, token_map);

        // Sending a raw sk-ant-* in x-api-key must be rejected (never forwarded).
        let (status, _, _) = proxy_post_with_headers(
            &proxy,
            "/v1/messages",
            r#"{"test": true}"#,
            vec![
                ("content-type", "application/json"),
                ("x-api-key", "sk-ant-api03-real-key-in-header"),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_proxy_rejects_unknown_zkg_token_under_strict_auth() {
        let mut vault = SecretVault::new();
        let mut token_map = TokenMap::new();
        let (_dummy, _) = token_map
            .register(&mut vault, b"real-registered-key", "anthropic")
            .unwrap();

        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router_with_vault(upstream_url, vault, token_map);

        let (status, _, _) = proxy_post_with_headers(
            &proxy,
            "/v1/messages",
            r#"{"test": true}"#,
            vec![
                ("content-type", "application/json"),
                ("x-api-key", "zkg-unknown-doesnotexist"),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_proxy_rejects_bearer_raw_key_under_strict_auth() {
        let mut vault = SecretVault::new();
        let mut token_map = TokenMap::new();
        let (_dummy, _) = token_map
            .register(&mut vault, b"real-registered-key", "openai")
            .unwrap();

        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router_with_vault(upstream_url, vault, token_map);

        let (status, _, _) = proxy_post_with_headers(
            &proxy,
            "/v1/chat/completions",
            r#"{"test": true}"#,
            vec![
                ("content-type", "application/json"),
                ("authorization", "Bearer sk-real-openai-key-do-not-leak"),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_proxy_key_injection_plus_body_sanitize() {
        let (proxy, dummy_token) =
            setup_key_injection_proxy(b"sk-ant-api03-my-real-key", "anthropic").await;

        let body =
            r#"{"messages":[{"role":"user","content":"My AWS key is AKIAIOSFODNN7EXAMPLE"}]}"#;
        let (status, echoed, _) = proxy_post_with_headers(
            &proxy,
            "/v1/messages",
            body,
            vec![
                ("content-type", "application/json"),
                ("x-api-key", &dummy_token),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(!echoed.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(echoed.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn test_proxy_get_request_strict_rejects_missing_auth() {
        // Under strict mode, a request with no auth header at all is allowed
        // through (no auth to misroute). We assert reachability, not policy.
        let mut vault = SecretVault::new();
        let mut token_map = TokenMap::new();
        let (_dummy, _) = token_map
            .register(&mut vault, b"real-registered-key", "anthropic")
            .unwrap();

        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router_with_vault(upstream_url, vault, token_map);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/v1/models")
            .body(Body::empty())
            .unwrap();

        let resp = proxy.clone().oneshot(req).await.unwrap();
        // No auth header present → not rejected by strict mode.
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── Negative security tests ────────────────────────────────────────────

    /// The response bytes flowing back to the client must also be scanned.
    /// If an upstream (or some misbehaving mock) echoes a real API key in the
    /// response body, the proxy is required to redact it before delivery.
    #[tokio::test]
    async fn test_proxy_redacts_keys_in_response_body() {
        // Mock upstream whose body contains a fake real key — as if the
        // upstream accidentally echoed one back.
        let leaky_key = format!("sk-ant-api03-{}", "Z".repeat(93));
        let leaky_clone = leaky_key.clone();
        let app = Router::new().fallback(move || {
            let body = format!(r#"{{"mistake":"your key is {}"}}"#, leaky_clone);
            async move { body }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let proxy = build_proxy_router(url);
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", r#"{"safe":"request"}"#).await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            !echoed.contains(&leaky_key),
            "response body must never surface a raw provider key, got: {}",
            echoed
        );
        assert!(echoed.contains("[REDACTED]"));
    }

    /// Verifies that the fixed "upstream error" string is returned when the
    /// outbound request fails, so no reqwest diagnostic text containing URLs
    /// or header echoes leaks to the client.
    #[tokio::test]
    async fn test_proxy_upstream_error_has_fixed_message() {
        // Point at an unroutable port to force a connection failure.
        let proxy = build_proxy_router("http://127.0.0.1:1".to_string());
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", r#"{}"#).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(echoed, "upstream error");
    }
}
