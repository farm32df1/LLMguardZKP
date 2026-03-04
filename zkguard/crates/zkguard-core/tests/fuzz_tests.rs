//! Fuzz / property-based tests for zkguard.
//!
//! Uses proptest to generate random inputs and verify invariants:
//! - Scanner never panics on arbitrary input
//! - Sanitize → process_tokens round-trip preserves structure
//! - HandleId hex encoding is always bijective
//! - Vault store/with_key never panics on valid inputs
//! - ZK proof generation/verification never panics on valid inputs
//! - Poseidon2 hash is deterministic and domain-separated

#![cfg(feature = "llm-guard")]

use proptest::prelude::*;
use zkguard::llm_guard::{ContextSanitizer, ContextScanner};

// ─── Scanner fuzz ─────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Scanner must never panic on arbitrary UTF-8 input.
    #[test]
    fn scanner_never_panics(text in "\\PC{0,5000}") {
        let scanner = ContextScanner::new();
        let _ = scanner.scan(&text);
    }

    /// Scanner must never panic on binary-like strings.
    #[test]
    fn scanner_never_panics_binary(bytes in prop::collection::vec(any::<u8>(), 0..2000)) {
        let text = String::from_utf8_lossy(&bytes);
        let scanner = ContextScanner::new();
        let _ = scanner.scan(&text);
    }

    /// Detected key spans must be valid byte ranges in the original text.
    #[test]
    fn scanner_spans_valid(text in "\\PC{0,2000}") {
        let scanner = ContextScanner::new();
        let keys = scanner.scan(&text);
        for key in &keys {
            prop_assert!(key.span.0 <= key.span.1, "span start > end");
            prop_assert!(key.span.1 <= text.len(), "span end > text length");
            // span must be valid UTF-8 boundary
            prop_assert!(text.is_char_boundary(key.span.0), "start not char boundary");
            prop_assert!(text.is_char_boundary(key.span.1), "end not char boundary");
        }
    }

    /// Detected key spans must not overlap each other.
    #[test]
    fn scanner_no_overlapping_spans(text in "\\PC{0,2000}") {
        let scanner = ContextScanner::new();
        let mut keys = scanner.scan(&text);
        keys.sort_by_key(|k| k.span.0);
        for i in 1..keys.len() {
            prop_assert!(
                keys[i].span.0 >= keys[i-1].span.1,
                "overlapping spans: {:?} and {:?}", keys[i-1].span, keys[i].span
            );
        }
    }
}

// ─── Sanitize round-trip fuzz ─────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Sanitize must never panic on arbitrary input.
    #[test]
    fn sanitize_never_panics(text in "\\PC{0,3000}") {
        let mut guard = ContextSanitizer::new();
        let _ = guard.sanitize(&text);
    }

    /// After sanitize, the output must not contain the original key prefixes
    /// that were detected (they should all be replaced with tokens).
    #[test]
    fn sanitize_removes_detected_key_prefixes(text in "\\PC{0,2000}") {
        let mut guard = ContextSanitizer::new();
        let scanner = ContextScanner::new();
        // Scan original text for known-provider keys
        let original_keys = scanner.scan(&text);
        let known_prefixes: Vec<&str> = original_keys.iter()
            .filter(|k| k.provider != zkguard::llm_guard::scanner::ApiProvider::Unknown)
            .filter_map(|k| match k.provider {
                zkguard::llm_guard::scanner::ApiProvider::Anthropic => Some("sk-ant-"),
                zkguard::llm_guard::scanner::ApiProvider::OpenAI => Some("sk-"),
                zkguard::llm_guard::scanner::ApiProvider::OpenAIProject => Some("sk-proj-"),
                zkguard::llm_guard::scanner::ApiProvider::AwsAccessKey => Some("AKIA"),
                zkguard::llm_guard::scanner::ApiProvider::GoogleAI => Some("AIza"),
                zkguard::llm_guard::scanner::ApiProvider::Unknown => None,
            })
            .collect();

        let result = guard.sanitize(&text).unwrap();

        // Verify known key prefixes no longer appear in sanitized output
        // (ZKGUARD tokens themselves may trigger entropy heuristic, which is expected)
        for prefix in known_prefixes {
            prop_assert!(
                !result.content.contains(prefix),
                "Key prefix '{}' still present in sanitized output", prefix
            );
        }
    }

    /// Sanitize → process_tokens round-trip: every ZKGUARD token in the
    /// sanitized output must be replaceable without error.
    #[test]
    fn round_trip_no_error(text in "\\PC{0,2000}") {
        let mut guard = ContextSanitizer::new();
        let result = guard.sanitize(&text).unwrap();
        let processed = guard.process_tokens(&result.content, |_vault, _handle| {
            Ok("[REPLACED]".into())
        });
        prop_assert!(processed.is_ok(), "process_tokens error: {:?}", processed.err());
        let output = processed.unwrap();
        // Output must not contain any ZKGUARD tokens
        prop_assert!(!output.contains("{{ZKGUARD:"), "tokens remain after processing");
    }

    /// process_tokens must never panic on arbitrary input (including malformed tokens).
    #[test]
    fn process_tokens_never_panics(text in "\\PC{0,3000}") {
        let guard = ContextSanitizer::new();
        let _ = guard.process_tokens(&text, |_, _| Ok("[X]".into()));
    }
}

// ─── HandleId fuzz ────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// HandleId hex encoding must be bijective (round-trip).
    #[test]
    fn handle_id_hex_roundtrip(bytes in prop::array::uniform16(any::<u8>())) {
        let id = zkguard::llm_guard::handle::HandleId(bytes);
        let hex = id.to_hex();
        prop_assert_eq!(hex.len(), 32, "hex length must be 32");
        let restored = zkguard::llm_guard::handle::HandleId::from_hex(&hex);
        prop_assert_eq!(restored, Some(id));
    }

    /// HandleId::from_hex must reject invalid hex strings without panic.
    #[test]
    fn handle_id_from_hex_no_panic(s in "\\PC{0,100}") {
        let _ = zkguard::llm_guard::handle::HandleId::from_hex(&s);
    }
}

// ─── Vault fuzz ───────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Vault must accept any non-empty key and return it faithfully.
    #[test]
    fn vault_store_retrieve(key in prop::collection::vec(any::<u8>(), 1..500)) {
        let mut vault = zkguard::SecretVault::new();
        let handle = vault.store(&key).unwrap();
        let retrieved = vault.with_key(&handle, |k| {
            Ok(k.to_vec())
        }).unwrap();
        prop_assert_eq!(retrieved, key);
    }

    /// Vault must reject empty keys.
    #[test]
    fn vault_reject_empty_key(extra in 0u8..255) {
        let _ = extra;
        let mut vault = zkguard::SecretVault::new();
        prop_assert!(vault.store(b"").is_err());
    }
}

// ─── Poseidon2 hash fuzz ──────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Poseidon2 hash must be deterministic: same input → same output.
    #[test]
    fn poseidon_deterministic(
        data in prop::collection::vec(any::<u8>(), 0..500),
        domain in prop::collection::vec(any::<u8>(), 1..100),
    ) {
        let h1 = zkguard::utils::hash::poseidon_hash(&data, &domain);
        let h2 = zkguard::utils::hash::poseidon_hash(&data, &domain);
        prop_assert_eq!(h1, h2);
    }

    /// Different domains must produce different hashes (with overwhelming probability).
    #[test]
    fn poseidon_domain_separation(
        data in prop::collection::vec(any::<u8>(), 1..100),
        d1 in prop::collection::vec(any::<u8>(), 1..50),
        d2 in prop::collection::vec(any::<u8>(), 1..50),
    ) {
        prop_assume!(d1 != d2);
        let h1 = zkguard::utils::hash::poseidon_hash(&data, &d1);
        let h2 = zkguard::utils::hash::poseidon_hash(&data, &d2);
        prop_assert_ne!(h1, h2, "domain separation failed for domains {:?} and {:?}", d1, d2);
    }

    /// Hash output must always be 32 bytes.
    #[test]
    fn poseidon_output_size(
        data in prop::collection::vec(any::<u8>(), 0..1000),
        domain in prop::collection::vec(any::<u8>(), 1..50),
    ) {
        let h = zkguard::utils::hash::poseidon_hash(&data, &domain);
        prop_assert_eq!(h.len(), 32);
    }
}

// ─── ZK Proof fuzz ────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]  // STARK proofs are expensive

    /// KeyCommit proofs must verify for any non-empty element list.
    #[test]
    fn key_commit_proof_verifies(
        elements in prop::collection::vec(1u64..=1000000, 1..16),
    ) {
        use zkguard::stark::air::SimpleAir;
        let prover = zkguard::StarkProver::new(SimpleAir::fibonacci()).unwrap();
        let verifier = prover.get_verifier();
        let proof = prover.prove_key_commit(&elements).unwrap();
        prop_assert!(verifier.verify_key_commit(&proof).unwrap(), "proof failed to verify");
    }
}

// ─── Injected key patterns fuzz ───────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Random Anthropic-shaped keys (sk-ant-*) must always be detected.
    #[test]
    fn detect_random_anthropic_key(
        suffix in "[a-zA-Z0-9\\-_]{93,120}",
        prefix_text in "\\PC{0,100}",
        suffix_text in "\\PC{0,100}",
    ) {
        let key = format!("sk-ant-api03-{}", suffix);
        let text = format!("{} {} {}", prefix_text, key, suffix_text);
        let scanner = ContextScanner::new();
        let found = scanner.scan(&text);
        prop_assert!(
            found.iter().any(|k| k.provider == zkguard::llm_guard::scanner::ApiProvider::Anthropic),
            "Anthropic key not detected in: {:?}", &text[..text.len().min(200)]
        );
    }

    /// Random AWS-shaped keys (AKIA*) must always be detected.
    #[test]
    fn detect_random_aws_key(
        suffix in "[0-9A-Z]{16}",
        prefix_text in "\\PC{0,100}",
        suffix_text in "\\PC{0,100}",
    ) {
        let key = format!("AKIA{}", suffix);
        let text = format!("{} {} {}", prefix_text, key, suffix_text);
        let scanner = ContextScanner::new();
        let found = scanner.scan(&text);
        prop_assert!(
            found.iter().any(|k| k.provider == zkguard::llm_guard::scanner::ApiProvider::AwsAccessKey),
            "AWS key not detected in: {:?}", &text[..text.len().min(200)]
        );
    }

    /// Random Google AI-shaped keys (AIza*) must always be detected.
    #[test]
    fn detect_random_google_key(
        suffix in "[0-9A-Za-z\\-_]{35}",
        prefix_text in "\\PC{0,100}",
        suffix_text in "\\PC{0,100}",
    ) {
        let key = format!("AIza{}", suffix);
        let text = format!("{} {} {}", prefix_text, key, suffix_text);
        let scanner = ContextScanner::new();
        let found = scanner.scan(&text);
        prop_assert!(
            found.iter().any(|k| k.provider == zkguard::llm_guard::scanner::ApiProvider::GoogleAI),
            "Google key not detected in: {:?}", &text[..text.len().min(200)]
        );
    }
}

// ─── Stress: many keys in one text ────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Text with multiple embedded keys: all must be detected and sanitized.
    #[test]
    fn multi_key_sanitize(
        n in 1usize..8,
        padding in prop::collection::vec("[a-z ]{5,20}", 1..10),
    ) {
        let mut parts = Vec::new();
        for i in 0..n {
            if i < padding.len() {
                parts.push(padding[i].clone());
            }
            // Alternate between Anthropic and AWS keys
            if i % 2 == 0 {
                parts.push(format!("sk-ant-api03-{}", "A".repeat(93)));
            } else {
                parts.push(format!("AKIA{}", "X".repeat(16)));
            }
        }
        let text = parts.join(" ");

        let mut guard = ContextSanitizer::new();
        let result = guard.sanitize(&text).unwrap();

        // Must have detected at least n keys
        prop_assert!(
            result.redactions.len() >= n,
            "Expected >= {} redactions, got {}", n, result.redactions.len()
        );

        // Sanitized text must not contain key patterns
        prop_assert!(!result.content.contains("sk-ant-api03-"));
        prop_assert!(!result.content.contains("AKIA"));
    }
}
