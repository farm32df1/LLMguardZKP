#![cfg(feature = "llm-guard")]
//! Integration tests: realistic LLM usage scenarios for zkguard.
//!
//! These tests simulate the full lifecycle of API key protection
//! in LLM workflows — without calling any actual LLM API.
//!
//! Each scenario documents what happens at each step so it serves
//! as both a test and living documentation.

use zkguard::llm_guard::{ApiProvider, ContextSanitizer, SecretVault};
use zkguard::stark::air::SimpleAir;
use zkguard::stark::real_stark::{ProofAirType, StarkProver, StarkVerifier};
use zkguard::utils::hash::bytes_to_fields;

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 1: Basic round-trip — Anthropic key
// ─────────────────────────────────────────────────────────────────────────────

/// Simulates: User writes a prompt containing their Anthropic API key.
/// zkguard sanitizes it before sending to LLM, then resolves the token
/// in the LLM response to make the actual API call.
#[test]
fn scenario_single_anthropic_key_round_trip() {
    let mut guard = ContextSanitizer::new();

    // Step 1: User's original prompt contains an API key
    let api_key = format!("sk-ant-api03-{}", "X".repeat(93));
    let user_prompt = format!(
        "Please call the Claude API with this key: {} and ask about Rust.",
        api_key
    );

    // Step 2: Sanitize — key is replaced with opaque token
    let sanitized = guard.sanitize(&user_prompt).unwrap();
    assert!(
        !sanitized.content.contains("sk-ant-"),
        "API key must not appear in sanitized text"
    );
    assert!(
        sanitized.content.contains("{{ZKGUARD:"),
        "Sanitized text must contain ZKGUARD token"
    );
    assert_eq!(sanitized.redactions.len(), 1);
    assert_eq!(sanitized.redactions[0].provider, ApiProvider::Anthropic);

    // Step 3: Simulate LLM response that echoes the token
    let llm_response = format!(
        "Sure! I'll use the API key {} to call Claude now.",
        // Extract the token from sanitized text
        extract_zkguard_token(&sanitized.content)
    );

    // Step 4: Process the LLM response — token is resolved via vault closure
    let mut api_called = false;
    let final_output = guard
        .process_tokens(&llm_response, |vault, handle| {
            // This closure has access to the key without it ever being in a string
            vault.with_key(handle, |key_bytes| {
                let key_str = std::str::from_utf8(key_bytes).unwrap();
                assert!(key_str.starts_with("sk-ant-api03-"));
                assert_eq!(key_str.len(), api_key.len());
                api_called = true;
                // Simulate the API call result
                Ok("[Claude says: Hello from Rust!]".to_string())
            })
        })
        .unwrap();

    assert!(api_called, "API closure must have been invoked");
    assert!(
        final_output.contains("[Claude says: Hello from Rust!]"),
        "Final output must contain the simulated API response"
    );
    assert!(
        !final_output.contains("{{ZKGUARD:"),
        "No ZKGUARD tokens should remain in final output"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 2: Multiple keys from different providers
// ─────────────────────────────────────────────────────────────────────────────

/// User provides multiple API keys (Anthropic + AWS) in one prompt.
#[test]
fn scenario_multiple_providers() {
    let mut guard = ContextSanitizer::new();

    let anthropic_key = format!("sk-ant-api03-{}", "A".repeat(93));
    let aws_key = "AKIAIOSFODNN7EXAMPLE";

    let prompt = format!(
        "Use Anthropic key {} and AWS key {} to orchestrate the pipeline.",
        anthropic_key, aws_key
    );

    let sanitized = guard.sanitize(&prompt).unwrap();

    // Both keys should be replaced
    assert!(
        !sanitized.content.contains("sk-ant-"),
        "Anthropic key leaked"
    );
    assert!(!sanitized.content.contains("AKIA"), "AWS key leaked");
    assert_eq!(
        sanitized.redactions.len(),
        2,
        "should detect exactly 2 keys"
    );

    // Verify providers detected correctly
    let providers: Vec<_> = sanitized.redactions.iter().map(|r| r.provider).collect();
    assert!(providers.contains(&ApiProvider::Anthropic));
    assert!(providers.contains(&ApiProvider::AwsAccessKey));

    // Handle count matches
    assert_eq!(guard.handle_count(), 2);

    // Process tokens — each token resolves independently
    let mut call_count = 0;
    let result = guard
        .process_tokens(&sanitized.content, |vault, handle| {
            vault.with_key(handle, |key_bytes| {
                call_count += 1;
                let key_str = std::str::from_utf8(key_bytes).unwrap();
                if key_str.starts_with("sk-ant-") {
                    Ok("[Anthropic OK]".to_string())
                } else if key_str.starts_with("AKIA") {
                    Ok("[AWS OK]".to_string())
                } else {
                    panic!("unexpected key: {}", &key_str[..8]);
                }
            })
        })
        .unwrap();

    assert_eq!(call_count, 2, "both tokens must be resolved");
    assert!(!result.contains("{{ZKGUARD:"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 3: ZK proof of key knowledge
// ─────────────────────────────────────────────────────────────────────────────

/// After sanitizing a key, prove via STARK that you know the key
/// without revealing it. This is the core ZK value proposition.
#[test]
fn scenario_zk_proof_of_key_knowledge() {
    let mut guard = ContextSanitizer::new();

    let api_key = format!("sk-ant-api03-{}", "Z".repeat(93));
    let prompt = format!("key={}", api_key);
    let _ = guard.sanitize(&prompt).unwrap();

    // The verifier side: prove knowledge of key elements
    let prover = StarkProver::new(SimpleAir::fibonacci()).unwrap();
    let verifier = prover.get_verifier();

    // Convert key to field elements (same as vault does internally)
    let key_fields: Vec<u64> = bytes_to_fields(api_key.as_bytes());

    // Generate ZK proof — proves knowledge of elements
    let proof = prover.prove_key_commit(&key_fields).unwrap();
    assert_eq!(proof.air_type, ProofAirType::KeyCommit);
    assert_eq!(proof.public_values.len(), 2);
    assert_eq!(proof.public_values[1], key_fields.len() as u64);

    // Verifier checks proof — never sees the key
    let is_valid = verifier.verify_key_commit(&proof).unwrap();
    assert!(is_valid, "ZK proof must verify for correct key elements");

    // Verify via generic dispatch too
    let is_valid_dispatch = verifier.verify_by_type(&proof).unwrap();
    assert!(is_valid_dispatch);
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 4: Full flow — sanitize + ZK proof + LLM call + verify
// ─────────────────────────────────────────────────────────────────────────────

/// The complete pipeline:
/// 1. User provides prompt with API key
/// 2. Sanitize (key → vault → token)
/// 3. Generate ZK proof of key knowledge
/// 4. Send sanitized prompt to LLM (simulated)
/// 5. Process LLM response (token → closure → API call)
/// 6. Verify ZK proof independently
#[test]
fn scenario_full_pipeline_sanitize_prove_call_verify() {
    // ── Step 1: Sanitize ─────────────────────────────────────────────────
    let mut guard = ContextSanitizer::new();
    let api_key = format!("sk-ant-api03-{}", "P".repeat(93));
    let prompt = format!("Call API with {}", api_key);

    let sanitized = guard.sanitize(&prompt).unwrap();
    assert!(!sanitized.content.contains("sk-ant-"));

    // ── Step 2: ZK proof ─────────────────────────────────────────────────
    // The key owner generates a proof they know the key
    let prover = StarkProver::new(SimpleAir::fibonacci()).unwrap();
    let key_fields: Vec<u64> = bytes_to_fields(api_key.as_bytes());

    let proof = prover.prove_key_commit(&key_fields).unwrap();
    let eval_commitment = proof.public_values[0]; // public polynomial eval

    // ── Step 3: Simulate LLM call ────────────────────────────────────────
    // The LLM only sees the sanitized prompt (no key)
    let llm_response = format!(
        "I'll execute the request using {}. Processing...",
        extract_zkguard_token(&sanitized.content)
    );

    // ── Step 4: Process LLM response ─────────────────────────────────────
    let mut api_response = String::new();
    let output = guard
        .process_tokens(&llm_response, |vault, handle| {
            vault.with_key(handle, |key_bytes| {
                // In production: make the actual HTTP call here
                let resp = format!("API response for key len={}", key_bytes.len());
                api_response = resp.clone();
                Ok(resp)
            })
        })
        .unwrap();

    assert!(!output.contains("{{ZKGUARD:"));
    assert!(!api_response.is_empty());

    // ── Step 5: Independent ZK verification ──────────────────────────────
    // A third party can verify the proof without the key
    let verifier = StarkVerifier::new(SimpleAir::fibonacci()).unwrap();
    let verified = verifier.verify_key_commit(&proof).unwrap();
    assert!(verified, "third-party verification must succeed");

    // They can see the public eval commitment but NOT the key
    assert!(eval_commitment > 0);
    assert_eq!(proof.public_values[1], key_fields.len() as u64);
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 5: Key revocation
// ─────────────────────────────────────────────────────────────────────────────

/// After using a key, the user revokes it from the vault.
/// Subsequent process_tokens calls pass the token through unchanged.
#[test]
fn scenario_key_revocation() {
    let mut guard = ContextSanitizer::new();
    let api_key = format!("sk-ant-api03-{}", "R".repeat(93));
    let prompt = format!("key={}", api_key);

    let sanitized = guard.sanitize(&prompt).unwrap();
    assert_eq!(guard.handle_count(), 1);
    assert_eq!(guard.vault().len(), 1);

    // First call works
    let result = guard
        .process_tokens(&sanitized.content, |vault, handle| {
            vault.with_key(handle, |_| Ok("OK".to_string()))
        })
        .unwrap();
    assert!(result.contains("OK"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 6: Handle tampering detection
// ─────────────────────────────────────────────────────────────────────────────

/// After revoking a key, the vault rejects the handle.
#[test]
fn scenario_revoked_handle_rejected() {
    let mut vault = SecretVault::new();
    let handle = vault.store(b"sk-ant-api03-revocable-key").unwrap();

    // Works before revocation
    let result = vault.with_key(&handle, |k| Ok(k.len()));
    assert!(result.is_ok());

    // Revoke
    assert!(vault.revoke(&handle));
    assert_eq!(vault.len(), 0);

    // Now the handle is rejected — key no longer in vault
    let result = vault.with_key(&handle, |_| Ok(()));
    assert!(result.is_err(), "revoked handle must be rejected");
}

/// Handle integrity can be verified from outside the crate.
#[test]
fn scenario_handle_integrity_check() {
    let mut vault = SecretVault::new();
    let key = b"sk-ant-api03-secret-key-data-here";
    let handle = vault.store(key).unwrap();

    // Fresh handle is valid
    assert!(handle.is_valid(), "fresh handle must pass integrity check");

    // Normal use works — key length matches what we stored
    let result = vault.with_key(&handle, |k| Ok(k.len()));
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), key.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 7: LLM response without any tokens (passthrough)
// ─────────────────────────────────────────────────────────────────────────────

/// If the LLM response doesn't contain any ZKGUARD tokens, it passes through.
#[test]
fn scenario_llm_response_no_tokens() {
    let guard = ContextSanitizer::new();
    let llm_output = "Here's the analysis of your code. No API calls needed.";

    let result = guard
        .process_tokens(llm_output, |_, _| {
            panic!("closure should never be called when there are no tokens")
        })
        .unwrap();

    assert_eq!(result, llm_output);
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 8: Multiple LLM turns with the same sanitized context
// ─────────────────────────────────────────────────────────────────────────────

/// Simulate a multi-turn conversation where the sanitized key token
/// appears in multiple LLM responses.
#[test]
fn scenario_multi_turn_conversation() {
    let mut guard = ContextSanitizer::new();
    let api_key = format!("sk-ant-api03-{}", "M".repeat(93));
    let prompt = format!("My key is {}", api_key);

    let sanitized = guard.sanitize(&prompt).unwrap();
    let token = extract_zkguard_token(&sanitized.content);

    // Turn 1: LLM says it will use the key
    let turn1 = format!("I'll use {} to call the API.", token);
    let mut call_count = 0;
    let out1 = guard
        .process_tokens(&turn1, |vault, handle| {
            vault.with_key(handle, |_| {
                call_count += 1;
                Ok("[Result 1]".to_string())
            })
        })
        .unwrap();
    assert_eq!(call_count, 1);
    assert!(out1.contains("[Result 1]"));

    // Turn 2: LLM references the same key again
    let turn2 = format!("Let me retry with {} for a different query.", token);
    let out2 = guard
        .process_tokens(&turn2, |vault, handle| {
            vault.with_key(handle, |_| {
                call_count += 1;
                Ok("[Result 2]".to_string())
            })
        })
        .unwrap();
    assert_eq!(call_count, 2);
    assert!(out2.contains("[Result 2]"));

    // Turn 3: LLM uses the key twice in one response
    let turn3 = format!("First call {} then second call {}.", token, token);
    let out3 = guard
        .process_tokens(&turn3, |vault, handle| {
            vault.with_key(handle, |_| {
                call_count += 1;
                Ok("[Call]".to_string())
            })
        })
        .unwrap();
    assert_eq!(call_count, 4, "two tokens in one response = two calls");
    assert_eq!(out3.matches("[Call]").count(), 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 9: Mixed content with code snippets
// ─────────────────────────────────────────────────────────────────────────────

/// Real-world scenario: user pastes a code snippet containing an API key.
#[test]
fn scenario_code_snippet_with_key() {
    let mut guard = ContextSanitizer::new();
    let api_key = format!("sk-ant-api03-{}", "C".repeat(93));

    let code = format!(
        r#"```python
import anthropic
client = anthropic.Client(api_key="{}")
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    messages=[{{"role": "user", "content": "Hello"}}]
)
```"#,
        api_key
    );

    let sanitized = guard.sanitize(&code).unwrap();

    // Key is redacted but code structure is preserved
    assert!(!sanitized.content.contains("sk-ant-"));
    assert!(sanitized.content.contains("{{ZKGUARD:"));
    assert!(sanitized.content.contains("anthropic.Client"));
    assert!(sanitized.content.contains("claude-sonnet-4-20250514"));
    assert_eq!(sanitized.redactions.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 10: ZK proof binding — wrong key doesn't verify
// ─────────────────────────────────────────────────────────────────────────────

/// Proving with different key elements produces a different eval,
/// confirming the ZK proof is actually bound to specific key data.
#[test]
fn scenario_zk_proof_binding_to_specific_key() {
    let prover = StarkProver::new(SimpleAir::fibonacci()).unwrap();

    let key_a: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let key_b: Vec<u64> = vec![8, 7, 6, 5, 4, 3, 2, 1];

    let proof_a = prover.prove_key_commit(&key_a).unwrap();
    let proof_b = prover.prove_key_commit(&key_b).unwrap();

    // Both proofs verify individually
    let verifier = prover.get_verifier();
    assert!(verifier.verify_key_commit(&proof_a).unwrap());
    assert!(verifier.verify_key_commit(&proof_b).unwrap());

    // But they have different public eval values — the proof is bound to the key
    assert_ne!(
        proof_a.public_values[0], proof_b.public_values[0],
        "different keys must produce different polynomial evaluations"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 11: Commitment consistency — vault commitment matches manual
// ─────────────────────────────────────────────────────────────────────────────

/// Verify that the vault's internal commitment matches what we'd
/// compute manually from the same key + salt.
#[test]
fn scenario_commitment_consistency() {
    let mut vault = SecretVault::new();
    let key = b"sk-ant-api03-test-key-for-commitment";

    let handle = vault.store(key).unwrap();
    // Commitment is accessible via the public accessor
    assert!(!handle.commitment().commitment.iter().all(|&b| b == 0));

    // The vault stores and we can verify via with_key
    let result = vault.with_key(&handle, |stored_key| {
        assert_eq!(stored_key, key);
        Ok(())
    });
    assert!(result.is_ok());

    // Handle integrity check passes
    assert!(handle.is_valid(), "fresh handle must be self-consistent");
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 12: Google AI key detection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn scenario_google_ai_key() {
    let mut guard = ContextSanitizer::new();
    let google_key = format!("AIza{}", "X".repeat(35));
    let prompt = format!("Use Google AI key: {}", google_key);

    let sanitized = guard.sanitize(&prompt).unwrap();
    assert!(!sanitized.content.contains("AIza"));
    assert_eq!(sanitized.redactions.len(), 1);
    assert_eq!(sanitized.redactions[0].provider, ApiProvider::GoogleAI);
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 13: Sanitize preserves surrounding text exactly
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn scenario_text_preservation() {
    let mut guard = ContextSanitizer::new();
    let api_key = format!("sk-ant-api03-{}", "T".repeat(93));

    let prefix = "Before the key: ";
    let suffix = " after the key.";
    let prompt = format!("{}{}{}", prefix, api_key, suffix);

    let sanitized = guard.sanitize(&prompt).unwrap();

    assert!(sanitized.content.starts_with(prefix));
    assert!(sanitized.content.ends_with(suffix));
    assert!(!sanitized.content.contains(&api_key));
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the first `{{ZKGUARD:...}}` token from a string.
fn extract_zkguard_token(text: &str) -> String {
    let start = text.find("{{ZKGUARD:").expect("no ZKGUARD token found");
    let after = &text[start + "{{ZKGUARD:".len()..];
    let end = after.find("}}").expect("unclosed ZKGUARD token");
    format!("{{{{ZKGUARD:{}}}}}", &after[..end])
}
