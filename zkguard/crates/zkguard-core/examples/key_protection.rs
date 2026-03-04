//! LLM API key protection demo

#[cfg(feature = "llm-guard")]
fn main() {
    use zkguard::llm_guard::ContextSanitizer;

    let mut guard = ContextSanitizer::new();

    // Simulate user accidentally including an API key in a prompt
    let user_prompt = concat!(
        "Please use my Anthropic key sk-ant-api03-",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        " to call Claude."
    );

    let safe = guard.sanitize(user_prompt).expect("sanitize failed");

    println!("Original: {}", user_prompt);
    println!("Sanitized: {}", safe.content);
    println!("Redactions: {}", safe.redactions.len());

    assert!(!safe.content.contains("sk-ant-"));
    assert!(safe.content.contains("{{ZKGUARD:"));
    println!("Key successfully protected!");
}

#[cfg(not(feature = "llm-guard"))]
fn main() {
    println!("Run with: cargo run --example key_protection --features llm-guard");
}
