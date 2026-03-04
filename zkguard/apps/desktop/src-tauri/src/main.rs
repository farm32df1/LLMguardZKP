//! zkguard desktop app — Tauri backend.
//!
//! Exposes zkguard functions as Tauri commands for the frontend.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::sync::Mutex;
use tauri::State;
use zkguard::llm_guard::{ContextSanitizer, ContextScanner};

struct AppState {
    scanner: Mutex<ContextScanner>,
    guard: Mutex<ContextSanitizer>,
    proxy_running: Mutex<bool>,
}

#[derive(Serialize)]
struct ScanResult {
    provider: String,
    start: usize,
    end: usize,
}

#[derive(Serialize)]
struct SanitizeResult {
    content: String,
    redaction_count: usize,
    providers: Vec<String>,
}

#[derive(Serialize)]
struct ProxyStatus {
    running: bool,
    port: u16,
    provider: String,
}

#[tauri::command]
fn scan_text(text: &str, state: State<'_, AppState>) -> Vec<ScanResult> {
    let scanner = state.scanner.lock().unwrap();
    scanner
        .scan(text)
        .into_iter()
        .map(|k| ScanResult {
            provider: format!("{:?}", k.provider),
            start: k.span.0,
            end: k.span.1,
        })
        .collect()
}

#[tauri::command]
fn sanitize_text(text: &str, state: State<'_, AppState>) -> Result<SanitizeResult, String> {
    let mut guard = state.guard.lock().unwrap();
    let result = guard.sanitize(text).map_err(|e| e.to_string())?;
    Ok(SanitizeResult {
        content: result.content,
        redaction_count: result.redactions.len(),
        providers: result
            .redactions
            .iter()
            .map(|r| format!("{:?}", r.provider))
            .collect(),
    })
}

#[tauri::command]
fn clean_text(text: &str, state: State<'_, AppState>) -> String {
    let scanner = state.scanner.lock().unwrap();
    let mut detected = scanner.scan(text);
    if detected.is_empty() {
        return text.to_string();
    }
    detected.sort_by(|a, b| b.span.0.cmp(&a.span.0));
    let mut result = text.to_string();
    for key in &detected {
        let (start, end) = key.span;
        if start < result.len() && end <= result.len() {
            result.replace_range(start..end, "[PROTECTED]");
        }
    }
    result
}

#[tauri::command]
fn get_proxy_status(state: State<'_, AppState>) -> ProxyStatus {
    let running = *state.proxy_running.lock().unwrap();
    ProxyStatus {
        running,
        port: 8080,
        provider: "anthropic".to_string(),
    }
}

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            scanner: Mutex::new(ContextScanner::new()),
            guard: Mutex::new(ContextSanitizer::new()),
            proxy_running: Mutex::new(false),
        })
        .invoke_handler(tauri::generate_handler![
            scan_text,
            sanitize_text,
            clean_text,
            get_proxy_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
