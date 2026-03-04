//! ContextScanner — detect API keys in text using regex + entropy analysis.
//!
//! Patterns are verified against actual key formats as of early 2026.
//! False negatives are worse than false positives here, so we err on the
//! side of over-detection and let the user decide.

use alloc::{string::String, vec::Vec};
use zeroize::Zeroize;

/// Which provider issued this key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiProvider {
    Anthropic,
    OpenAI,
    OpenAIProject,
    AwsAccessKey,
    GoogleAI,
    /// Key matched entropy heuristic but unknown format.
    Unknown,
}

impl ApiProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::OpenAI => "OpenAI",
            Self::OpenAIProject => "OpenAI (Project)",
            Self::AwsAccessKey => "AWS Access Key",
            Self::GoogleAI => "Google AI",
            Self::Unknown => "Unknown",
        }
    }
}

/// A detected key in a text string.
/// `value` is automatically zeroized when dropped.
pub struct DetectedKey {
    pub provider: ApiProvider,
    /// The raw key bytes (before redaction). Zeroized on drop.
    pub value: String,
    /// Byte range in the original text.
    pub span: (usize, usize),
}

impl Drop for DetectedKey {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl core::fmt::Debug for DetectedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DetectedKey")
            .field("provider", &self.provider)
            .field("value", &"<REDACTED>")
            .field("span", &self.span)
            .finish()
    }
}

/// Scan text for API keys.
///
/// With `feature = "llm-guard"`, uses compiled regexes.
/// Without it, falls back to a simple prefix scan (less accurate).
#[derive(Debug)]
pub struct ContextScanner;

/// Pre-compiled regex patterns (compiled once via OnceLock).
#[cfg(feature = "llm-guard")]
mod patterns {
    use regex::Regex;
    use std::sync::OnceLock;

    macro_rules! static_regex {
        ($name:ident, $pat:expr) => {
            pub(super) fn $name() -> &'static Regex {
                static RE: OnceLock<Regex> = OnceLock::new();
                RE.get_or_init(|| Regex::new($pat).expect(concat!("bad regex: ", $pat)))
            }
        };
    }

    // Anthropic: "sk-ant-" prefix, 93+ base64url chars
    static_regex!(anthropic, r"sk-ant-[a-zA-Z0-9\-_]{93,}");
    // OpenAI legacy: "sk-" + 48 alphanumeric chars
    // Note: overlap with anthropic/proj is removed via span deduplication
    static_regex!(openai, r"sk-[a-zA-Z0-9]{48}");
    // OpenAI project keys
    static_regex!(openai_proj, r"sk-proj-[a-zA-Z0-9\-_]{100,}");
    // AWS access key
    static_regex!(aws, r"AKIA[0-9A-Z]{16}");
    // Google AI Studio / Gemini
    static_regex!(google_ai, r"AIza[0-9A-Za-z\-_]{35}");
}

impl ContextScanner {
    pub fn new() -> Self {
        Self
    }

    #[cfg(feature = "llm-guard")]
    pub fn scan(&self, text: &str) -> Vec<DetectedKey> {
        let mut found = Vec::new();

        let providers: &[(&regex::Regex, ApiProvider)] = &[
            (patterns::anthropic(), ApiProvider::Anthropic),
            (patterns::openai(), ApiProvider::OpenAI),
            (patterns::openai_proj(), ApiProvider::OpenAIProject),
            (patterns::aws(), ApiProvider::AwsAccessKey),
            (patterns::google_ai(), ApiProvider::GoogleAI),
        ];

        for &(re, provider) in providers {
            for m in re.find_iter(text) {
                found.push(DetectedKey {
                    provider,
                    value: m.as_str().into(),
                    span: (m.start(), m.end()),
                });
            }
        }

        // Deduplicate: remove matches whose span overlaps a more-specific match.
        // Priority: Anthropic/OpenAIProject > OpenAI (since "sk-" is a prefix of "sk-ant-"/"sk-proj-").
        deduplicate_overlapping(&mut found);

        // Entropy heuristic for unknown formats
        self.scan_high_entropy(text, &mut found);

        found
    }

    #[cfg(feature = "llm-guard")]
    fn scan_high_entropy(&self, text: &str, out: &mut Vec<DetectedKey>) {
        use crate::utils::constants::{
            ENTROPY_MAX_TOKEN_LEN, ENTROPY_MIN_TOKEN_LEN, ENTROPY_THRESHOLD,
        };
        for (start, token) in tokenize(text) {
            if token.len() < ENTROPY_MIN_TOKEN_LEN || token.len() > ENTROPY_MAX_TOKEN_LEN {
                continue;
            }
            // Skip if already matched by a known pattern
            if out.iter().any(|d| d.span.0 <= start && start < d.span.1) {
                continue;
            }
            if shannon_entropy(token) > ENTROPY_THRESHOLD {
                out.push(DetectedKey {
                    provider: ApiProvider::Unknown,
                    value: token.into(),
                    span: (start, start + token.len()),
                });
            }
        }
    }

    /// Fallback scan without regex — prefix matching only.
    #[cfg(not(feature = "llm-guard"))]
    pub fn scan(&self, text: &str) -> Vec<DetectedKey> {
        let mut found = Vec::new();
        let prefixes: &[(&str, ApiProvider)] = &[
            ("sk-ant-", ApiProvider::Anthropic),
            ("sk-proj-", ApiProvider::OpenAIProject),
            ("sk-", ApiProvider::OpenAI),
            ("AKIA", ApiProvider::AwsAccessKey),
            ("AIza", ApiProvider::GoogleAI),
        ];
        for (i, _) in text.char_indices() {
            for (prefix, provider) in prefixes {
                if text[i..].starts_with(prefix) {
                    let end = text[i..]
                        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                        .map(|n| i + n)
                        .unwrap_or(text.len());
                    if end > i + prefix.len() {
                        found.push(DetectedKey {
                            provider: *provider,
                            value: text[i..end].into(),
                            span: (i, end),
                        });
                    }
                }
            }
        }
        found
    }
}

impl Default for ContextScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Remove entries whose span is a strict sub-range of a longer match.
/// Keeps the longest match for any overlapping region (Anthropic > OpenAI).
#[cfg(feature = "llm-guard")]
fn deduplicate_overlapping(keys: &mut Vec<DetectedKey>) {
    if keys.len() < 2 {
        return;
    }
    // Sort by start ascending, length descending (longest match first for same start).
    keys.sort_by(|a, b| a.span.0.cmp(&b.span.0).then(b.span.1.cmp(&a.span.1)));
    let mut keep = Vec::with_capacity(keys.len());
    let mut max_end: usize = 0;
    for key in keys.drain(..) {
        if key.span.0 < max_end && key.span.1 <= max_end {
            // This match is entirely contained within a previous longer match — skip.
            continue;
        }
        max_end = max_end.max(key.span.1);
        keep.push(key);
    }
    *keys = keep;
}

/// Yield (byte_offset, token_str) for whitespace/separator-delimited tokens.
/// Uses a lazy iterator to avoid heap allocation on the scanning hot path.
#[cfg(feature = "llm-guard")]
fn tokenize(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let separators =
        |c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']');
    text.char_indices()
        .chain(core::iter::once((text.len(), ' '))) // sentinel to flush last token
        .scan(None::<usize>, move |start, (i, c)| {
            if separators(c) {
                let token = start.take().map(|s| (s, &text[s..i]));
                Some(token)
            } else {
                if start.is_none() {
                    *start = Some(i);
                }
                Some(None)
            }
        })
        .flatten()
}

/// Shannon entropy in bits per character.
#[cfg(feature = "llm-guard")]
fn shannon_entropy(s: &str) -> f64 {
    let mut freq = [0u32; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    -freq
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_anthropic_key() {
        let scanner = ContextScanner::new();
        // 93 base64url chars after prefix
        let key = "sk-ant-api03-".to_owned() + &"A".repeat(93);
        let text = alloc::format!("My key is {key} please use it");
        let found = scanner.scan(&text);
        assert!(!found.is_empty(), "anthropic key not detected");
        assert_eq!(found[0].provider, ApiProvider::Anthropic);
    }

    #[test]
    fn test_scan_aws_key() {
        let scanner = ContextScanner::new();
        let text = "access_key = AKIAIOSFODNN7EXAMPLE";
        let found = scanner.scan(text);
        let aws: Vec<_> = found
            .iter()
            .filter(|d| d.provider == ApiProvider::AwsAccessKey)
            .collect();
        assert!(!aws.is_empty(), "AWS key not detected");
    }

    #[test]
    fn test_no_false_positive_short() {
        let scanner = ContextScanner::new();
        let found = scanner.scan("hello world foo bar");
        assert!(found.is_empty());
    }

    #[cfg(feature = "llm-guard")]
    #[test]
    fn test_entropy_calculation() {
        // "aaaa" has entropy 0
        assert!(shannon_entropy("aaaa") < 0.1);
        // random-looking string has high entropy
        assert!(shannon_entropy("aB3xQz9mKpWvRj2nYe7sUo4tL1iCfDhG") > 4.0);
    }
}
