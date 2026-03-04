//! Proxy server — local HTTP reverse proxy that sanitizes LLM API requests.
//!
//! Sits between your app and the LLM provider. Automatically detects and removes
//! API keys from prompts before forwarding to the real API.
//!
//! ```text
//! App → POST localhost:PORT/v1/messages → [sanitize] → api.anthropic.com
//! ```
//!
//! Requires feature = "proxy-server".

use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use tokio::sync::Mutex;

use crate::llm_guard::scanner::ContextScanner;

/// Configuration for the proxy server.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Port to listen on (default: 8080).
    pub port: u16,
    /// Target LLM API base URL (e.g. "https://api.anthropic.com").
    pub target_base_url: String,
    /// Bind address (default: "127.0.0.1").
    pub bind_addr: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 8080,
            target_base_url: "https://api.anthropic.com".to_string(),
            bind_addr: "127.0.0.1".to_string(),
        }
    }
}

struct ProxyState {
    scanner: Mutex<ContextScanner>,
    client: reqwest::Client,
    target_base_url: String,
    request_count: Mutex<u64>,
    keys_blocked: Mutex<u64>,
}

/// Start the proxy server. This function blocks until the server is shut down.
pub async fn start_proxy_server(config: ProxyConfig) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(ProxyState {
        scanner: Mutex::new(ContextScanner::new()),
        client: reqwest::Client::new(),
        target_base_url: config.target_base_url.clone(),
        request_count: Mutex::new(0),
        keys_blocked: Mutex::new(0),
    });

    let app = Router::new().fallback(proxy_handler).with_state(state);

    let addr = format!("{}:{}", config.bind_addr, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    eprintln!("[zkguard proxy] Listening on http://{}", addr);
    eprintln!("[zkguard proxy] Forwarding to {}", config.target_base_url);
    eprintln!("[zkguard proxy] All prompts will be scanned for API keys");
    eprintln!();

    axum::serve(listener, app).await?;
    Ok(())
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

    // Read the request body
    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("[zkguard proxy] Failed to read request body: {}", e);
            return (StatusCode::BAD_REQUEST, format!("Bad request: {}", e)).into_response();
        }
    };

    let body_str = String::from_utf8_lossy(&body_bytes);

    // Scan for API keys in the request body
    let (keys_found, sanitized_body) = {
        let scanner = state.scanner.lock().await;
        let detected = scanner.scan(&body_str);
        let count = detected.len();

        if detected.is_empty() {
            (count, body_str.to_string())
        } else {
            // Replace detected keys with [REDACTED] in the forwarded request
            let mut result = body_str.to_string();
            // Sort by position descending to avoid index shift
            let mut sorted = detected;
            sorted.sort_by(|a, b| b.span.0.cmp(&a.span.0));
            for key in &sorted {
                let (start_pos, end_pos) = key.span;
                if start_pos < result.len() && end_pos <= result.len() {
                    result.replace_range(start_pos..end_pos, "[REDACTED]");
                }
            }
            (count, result)
        }
    };

    // Update counters
    {
        let mut count = state.request_count.lock().await;
        *count += 1;
    }
    if keys_found > 0 {
        let mut blocked = state.keys_blocked.lock().await;
        *blocked += keys_found as u64;
    }

    // Build the forwarded request
    let target_url = format!("{}{}{}", state.target_base_url, path, query);

    let mut forward_req = state.client.request(method.clone(), &target_url);

    // Forward headers (except Host which should match the target)
    for (name, value) in &headers {
        let name_str = name.as_str().to_lowercase();
        // Skip hop-by-hop headers and host
        if name_str == "host" || name_str == "transfer-encoding" || name_str == "connection" {
            continue;
        }
        forward_req = forward_req.header(name.clone(), value.clone());
    }

    forward_req = forward_req.body(sanitized_body.clone());

    // Send to actual LLM API
    let response = match forward_req.send().await {
        Ok(resp) => resp,
        Err(e) => {
            let elapsed = start.elapsed();
            eprintln!(
                "[zkguard proxy] {} {} | {} keys blocked | FAILED ({:.0}ms): {}",
                method,
                path,
                keys_found,
                elapsed.as_millis(),
                e
            );
            return (StatusCode::BAD_GATEWAY, format!("Upstream error: {}", e)).into_response();
        }
    };

    let elapsed = start.elapsed();
    let status = response.status();

    // Log the request
    if keys_found > 0 {
        eprintln!(
            "[zkguard proxy] {} {} | {} key(s) BLOCKED | {} ({:.0}ms)",
            method,
            path,
            keys_found,
            status.as_u16(),
            elapsed.as_millis()
        );
    } else {
        eprintln!(
            "[zkguard proxy] {} {} | clean | {} ({:.0}ms)",
            method,
            path,
            status.as_u16(),
            elapsed.as_millis()
        );
    }

    // Forward the response back
    let resp_status = status;
    let resp_headers = response.headers().clone();
    let resp_body = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("Failed to read upstream response: {}", e),
            )
                .into_response();
        }
    };

    let mut builder = Response::builder().status(resp_status);
    for (name, value) in &resp_headers {
        let name_str = name.as_str().to_lowercase();
        if name_str == "transfer-encoding" || name_str == "connection" {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }

    builder
        .body(Body::from(resp_body))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response())
}

/// Build a proxy router for testing (no server bind).
/// Returns the router that can be used with `axum::body::to_bytes` in tests.
pub fn build_proxy_router(target_base_url: String) -> Router {
    let state = Arc::new(ProxyState {
        scanner: Mutex::new(ContextScanner::new()),
        client: reqwest::Client::new(),
        target_base_url,
        request_count: Mutex::new(0),
        keys_blocked: Mutex::new(0),
    });

    Router::new().fallback(proxy_handler).with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tower::util::ServiceExt; // for `oneshot`

    // ── Config Tests ──────────────────────────────────────────────────────

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();
        assert_eq!(config.port, 8080);
        assert_eq!(config.bind_addr, "127.0.0.1");
        assert_eq!(config.target_base_url, "https://api.anthropic.com");
    }

    #[test]
    fn test_proxy_config_custom() {
        let config = ProxyConfig {
            port: 9090,
            target_base_url: "https://api.openai.com".to_string(),
            bind_addr: "0.0.0.0".to_string(),
        };
        assert_eq!(config.port, 9090);
        assert_eq!(config.target_base_url, "https://api.openai.com");
    }

    #[test]
    fn test_proxy_config_clone() {
        let config = ProxyConfig::default();
        let cloned = config.clone();
        assert_eq!(config.port, cloned.port);
        assert_eq!(config.target_base_url, cloned.target_base_url);
    }

    // ── Sanitization Logic Tests (via mock upstream) ──────────────────────

    /// Helper: start a mock upstream server that echoes back the request body.
    async fn start_echo_server() -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().fallback(|body: String| async move { body });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        // Give the server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (url, handle)
    }

    /// Helper: send a POST request through the proxy and get the echoed body.
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

    // ── Real E2E Tests (mock upstream) ────────────────────────────────────

    #[tokio::test]
    async fn test_proxy_clean_request_passes_through() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let body = r#"{"messages":[{"role":"user","content":"Hello, how are you?"}]}"#;
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", body).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(echoed, body); // No keys → body passes unchanged
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
        assert!(!echoed.contains("sk-ant-api03-"), "Key should be redacted");
        assert!(echoed.contains("[REDACTED]"), "Should contain [REDACTED]");
    }

    #[tokio::test]
    async fn test_proxy_redacts_aws_key() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let body = r#"{"messages":[{"role":"user","content":"AWS key: AKIAIOSFODNN7EXAMPLE"}]}"#;
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", body).await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            !echoed.contains("AKIAIOSFODNN7EXAMPLE"),
            "AWS key should be redacted"
        );
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
        assert!(!echoed.contains(&fake_key), "OpenAI key should be redacted");
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
        assert!(
            !echoed.contains(&fake_key),
            "Google AI key should be redacted"
        );
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
        // Should have two [REDACTED] markers
        assert_eq!(echoed.matches("[REDACTED]").count(), 2);
    }

    // ── Edge Cases ────────────────────────────────────────────────────────

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

        // The echo server returns the body, so we can verify the request went through
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
        assert_eq!(echoed, body, "Normal text should pass through unchanged");
    }

    #[tokio::test]
    async fn test_proxy_unicode_text() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let body = r#"{"messages":[{"role":"user","content":"한국어 테스트 🔑 이모지도 포함"}]}"#;
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", body).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(echoed, body, "Unicode should pass through unchanged");
    }

    #[tokio::test]
    async fn test_proxy_large_body() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        // 1MB of safe text
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

        // These should NOT be detected as keys
        let body = r#"{"content":"sk-short is not a key. AKIA alone is not enough. Regular text with numbers 12345."}"#;
        let (status, echoed) = proxy_post(&proxy, "/v1/messages", body).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(echoed, body, "False positives should not be redacted");
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
        assert!(echoed.contains("gpt-4o")); // Model name preserved
        assert!(echoed.contains("You are helpful")); // System prompt preserved
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
        assert!(echoed.contains("claude-sonnet")); // Model preserved
        assert!(echoed.contains("import requests")); // Code preserved
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
        assert!(echoed.contains("HTTPError 401")); // Error message preserved
        assert!(echoed.contains("Traceback")); // Traceback preserved
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
        assert!(echoed.contains("DATABASE_URL=postgres://localhost/mydb")); // Non-key env var preserved
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
        assert!(echoed.contains("curl -X POST")); // Command preserved
    }

    // ── Headers Tests ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_proxy_forwards_custom_headers() {
        // Use a mock that echoes headers would need a more complex setup
        // For now, verify the proxy doesn't crash with custom headers
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

    #[tokio::test]
    async fn test_proxy_get_request() {
        let (upstream_url, _handle) = start_echo_server().await;
        let proxy = build_proxy_router(upstream_url);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/v1/models")
            .body(Body::empty())
            .unwrap();

        let resp = proxy.clone().oneshot(req).await.unwrap();
        // GET should work too (for listing models, etc.)
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
