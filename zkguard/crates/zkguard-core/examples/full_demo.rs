//! Full end-to-end demo: sanitize → ZK proof → LLM call → verify
//!
//! Run: cargo run --example full_demo --features llm-guard

#[cfg(feature = "llm-guard")]
fn main() {
    use zkguard::llm_guard::ContextSanitizer;
    use zkguard::stark::air::SimpleAir;
    use zkguard::stark::real_stark::{StarkProver, StarkVerifier};
    use zkguard::utils::hash::bytes_to_fields;

    println!("══════════════════════════════════════════════════════════════");
    println!("  zkguard — LLM API Key Protection Demo");
    println!("══════════════════════════════════════════════════════════════\n");

    // ── Step 1: User writes a prompt with real API keys ──────────────────
    let anthropic_key = format!("sk-ant-api03-{}", "X".repeat(93));
    let aws_key = "AKIAIOSFODNN7EXAMPLE";

    let user_prompt = format!(
        "Use my Anthropic key {} and AWS key {} to run the pipeline.",
        anthropic_key, aws_key,
    );

    println!("[1] Original prompt ({} chars):", user_prompt.len());
    println!("    \"{}...\"", &user_prompt[..80]);
    println!(
        "    Keys visible: Anthropic={}, AWS={}\n",
        user_prompt.contains("sk-ant-"),
        user_prompt.contains("AKIA"),
    );

    // ── Step 2: Sanitize — keys replaced with opaque tokens ─────────────
    let mut guard = ContextSanitizer::new();
    let sanitized = guard.sanitize(&user_prompt).expect("sanitize failed");

    println!("[2] Sanitized prompt ({} chars):", sanitized.content.len());
    println!(
        "    \"{}...\"",
        &sanitized.content[..80.min(sanitized.content.len())]
    );
    println!(
        "    Keys visible: Anthropic={}, AWS={}",
        sanitized.content.contains("sk-ant-"),
        sanitized.content.contains("AKIA"),
    );
    println!("    ZKGUARD tokens: {}", sanitized.redactions.len());
    for r in &sanitized.redactions {
        println!(
            "      - {:?} → {}",
            r.provider,
            &r.token[..30.min(r.token.len())]
        );
    }
    println!("    Vault entries: {}", guard.vault().len());
    println!("    Handle registry: {}\n", guard.handle_count());

    // ── Step 3: Generate ZK proof of key knowledge ──────────────────────
    println!("[3] Generating ZK proof (STARK) of Anthropic key knowledge...");
    let prover = StarkProver::new(SimpleAir::fibonacci()).expect("prover init");

    let key_fields: Vec<u64> = bytes_to_fields(anthropic_key.as_bytes());
    println!("    Key → {} field elements", key_fields.len());

    let start = std::time::Instant::now();
    let proof = prover.prove_key_commit(&key_fields).expect("prove failed");
    let prove_time = start.elapsed();

    println!("    Proof generated in {:?}", prove_time);
    println!("    Trace rows: {}", proof.num_rows);
    println!(
        "    Public values: eval={}, num_elements={}",
        proof.public_values[0], proof.public_values[1]
    );
    println!("    Key hidden: YES (only eval + count are public)\n");

    // ── Step 4: Simulate LLM interaction ────────────────────────────────
    println!("[4] Simulating LLM interaction...");
    println!("    → Sending sanitized prompt to LLM (no real keys!)");

    // LLM "responds" using the token it saw
    let token = extract_token(&sanitized.content);
    let llm_response = format!(
        "I'll execute the API call using {} and return the results.",
        token,
    );
    println!(
        "    ← LLM response: \"{}...\"",
        &llm_response[..60.min(llm_response.len())]
    );

    // ── Step 5: Process LLM output — resolve tokens via vault closure ───
    println!("\n[5] Processing LLM output (token → vault → API call)...");
    let mut calls = Vec::new();

    let final_output = guard
        .process_tokens(&llm_response, |vault, handle| {
            vault.with_key(handle, |key_bytes| {
                let key_str = std::str::from_utf8(key_bytes).unwrap_or("<binary>");
                let provider = if key_str.starts_with("sk-ant-") {
                    "Anthropic"
                } else if key_str.starts_with("AKIA") {
                    "AWS"
                } else {
                    "Unknown"
                };
                println!(
                    "    Closure called: provider={}, key_len={}",
                    provider,
                    key_bytes.len()
                );
                println!(
                    "    Key preview: {}...{} (never in LLM context!)",
                    &key_str[..12.min(key_str.len())],
                    &key_str[key_str.len().saturating_sub(4)..]
                );

                // In production: make the actual HTTP API call here
                let result = format!("[{} API: 200 OK, model=claude-sonnet-4-20250514]", provider);
                calls.push(provider.to_string());
                Ok(result)
            })
        })
        .expect("process_tokens failed");

    println!("    API calls made: {}", calls.len());
    println!("    Final output: \"{}\"\n", final_output);

    // ── Step 6: Independent ZK verification ─────────────────────────────
    println!("[6] Third-party ZK verification (no key access needed)...");
    let verifier = StarkVerifier::new(SimpleAir::fibonacci()).expect("verifier init");

    let start = std::time::Instant::now();
    let verified = verifier.verify_key_commit(&proof).expect("verify failed");
    let verify_time = start.elapsed();

    println!("    Proof valid: {}", verified);
    println!("    Verified in {:?}", verify_time);
    println!(
        "    Verifier saw: eval={}, num_elements={}",
        proof.public_values[0], proof.public_values[1]
    );
    println!("    Verifier knows the key: NO (ZK property)\n");

    // ── Step 7: Demonstrate proof binding ───────────────────────────────
    println!("[7] Proof binding verification...");
    let wrong_key_fields: Vec<u64> = bytes_to_fields(b"sk-ant-api03-WRONG-KEY");
    let wrong_proof = prover
        .prove_key_commit(&wrong_key_fields)
        .expect("prove wrong");

    println!("    Correct key eval:  {}", proof.public_values[0]);
    println!("    Wrong key eval:    {}", wrong_proof.public_values[0]);
    println!(
        "    Evals match: {} (different keys → different proofs)\n",
        proof.public_values[0] == wrong_proof.public_values[0]
    );

    // ── Summary ─────────────────────────────────────────────────────────
    println!("══════════════════════════════════════════════════════════════");
    println!("  SUMMARY");
    println!("══════════════════════════════════════════════════════════════");
    println!("  Keys detected:        {}", sanitized.redactions.len());
    println!("  Keys sent to LLM:     0 (all replaced with tokens)");
    println!(
        "  API calls made:       {} (via vault closure)",
        calls.len()
    );
    println!("  ZK proof generated:   YES ({:?})", prove_time);
    println!("  ZK proof verified:    {} ({:?})", verified, verify_time);
    println!("  Key leaked to LLM:    NO");
    println!("  Key leaked to verifier: NO");
    println!("══════════════════════════════════════════════════════════════");

    // Assertions
    assert!(!sanitized.content.contains("sk-ant-"));
    assert!(!sanitized.content.contains("AKIA"));
    assert!(verified);
    assert!(!final_output.contains("{{ZKGUARD:"));
}

#[cfg(feature = "llm-guard")]
fn extract_token(text: &str) -> &str {
    let start = text.find("{{ZKGUARD:").expect("no token");
    let end = text[start..].find("}}").expect("unclosed") + start + 2;
    &text[start..end]
}

#[cfg(not(feature = "llm-guard"))]
fn main() {
    println!("Run with: cargo run --example full_demo --features llm-guard");
}
