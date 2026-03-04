# Why zkguard?

## The Problem: API Keys Leak Through LLMs

Every day, developers accidentally paste API keys into LLM prompts:

```
"Debug this code: requests.get(url, headers={'Authorization': 'Bearer sk-ant-api03-AAAA...'})"
```

Once that prompt reaches the LLM provider's server, your key is:

- Stored in the provider's logs (potentially for months)
- Visible to the provider's employees and systems
- Exposed if the provider suffers a data breach
- Possibly used to train future models (depending on the provider's data policy)

**The damage is already done the moment you press Enter.**

### Real-World Impact

| Scenario | Risk |
|----------|------|
| Pasting code with hardcoded keys into ChatGPT | Key stored in OpenAI's logs |
| Asking Claude to debug an API integration | Key visible in Anthropic's systems |
| Using an LLM-powered IDE assistant | Key sent to the provider with every code completion |
| Sharing prompts in team Slack/docs | Keys spread across multiple services |
| LLM echoing the key back in its response | Key appears in your terminal/chat logs |

### Existing "Solutions" and Why They Fall Short

| Approach | Problem |
|----------|---------|
| "Just don't paste keys" | Human error is inevitable. One mistake is enough. |
| `.env` files + `.gitignore` | Only protects git. Doesn't protect LLM prompts. |
| Secret managers (Vault, AWS SM) | Designed for server-side. No LLM prompt integration. |
| Regex linters (detect-secrets, gitleaks) | Pre-commit only. Don't intercept live LLM sessions. |
| Provider-side scanning | Too late — the key already left your machine. |

## zkguard's Approach: Protect Before It Leaves

zkguard operates on a simple principle: **the key should never leave your machine in the first place.**

```
Your prompt: "Use sk-ant-api03-AAAA... to call the API"
                    │
                    ▼  ← YOUR MACHINE (Rust/Python, < 1ms)
            [zkguard.sanitize()]
                    │
                    ▼
Safe prompt: "Use {{ZKGUARD:a3f2b1c9...}} to call the API"
                    │
                    ▼  ← NETWORK
            LLM (Claude, GPT, etc.)
                    │
           Never sees the real key
```

### What Makes This Different

1. **Local-first**: Scanning and replacement happen entirely on your machine. The LLM never receives the key.

2. **Automatic**: No need to manually redact keys. `sanitize()` detects them by pattern and entropy analysis.

3. **Round-trip capable**: When the LLM responds with `{{ZKGUARD:...}}` tokens, `process_tokens()` can use the real key (from vault) to make API calls — without ever exposing the key as a string.

4. **Cryptographic proof**: zkguard can generate a zero-knowledge STARK proof that you *possess* a key, without revealing it. This enables scenarios like:
   - Proving to an auditor that you have valid API credentials
   - Verifying key ownership in automated pipelines
   - Attestation without exposure

5. **Memory-safe**: Keys in the vault are zeroized on drop. The only way to access a key is through a closure (`with_key()`), and the borrow ends before the function returns.

## Use Cases

### 1. LLM-Assisted Development

You're debugging an API integration and need Claude/GPT to help:

```python
guard = zkguard.ZkGuard()

# Your prompt accidentally contains an API key
prompt = f"This request returns 403: curl -H 'x-api-key: {api_key}' https://api.example.com"

# zkguard catches it before it reaches the LLM
safe = guard.sanitize(prompt)
response = llm.invoke(safe.content)  # LLM sees {{ZKGUARD:...}}, not the real key
```

### 2. LangChain / Agent Pipelines

LLM agents often handle API keys as part of tool-calling workflows:

```python
from zkguard_langchain import ZkGuardCallbackHandler

# Callback monitors every prompt and response for accidental key leakage
llm = ChatAnthropic(
    model="claude-sonnet-4-20250514",
    callbacks=[ZkGuardCallbackHandler(raise_on_leak=True)]
)
# If a key appears in any prompt or response, ValueError is raised immediately
```

### 3. Shared Prompt Libraries

Teams share prompt templates that sometimes contain keys by accident:

```python
guard = zkguard.ZkGuard()

# Scan a prompt library for exposed keys
for prompt in prompt_library:
    result = guard.sanitize(prompt)
    if result.redaction_count > 0:
        print(f"WARNING: {result.redaction_count} key(s) found in prompt")
        # Save the sanitized version instead
        save_sanitized(result.content)
```

### 4. Compliance and Audit

Prove that API keys are handled securely without exposing them:

```python
prover = zkguard.StarkProver()

# Generate a ZK proof that you possess a valid API key
key_bytes = [ord(c) for c in api_key[:6]]
proof = prover.prove_key_commit(key_bytes)

# Auditor can verify without ever seeing the key
verifier = zkguard.StarkVerifier()
assert verifier.verify(proof)  # True — key ownership proven
```

### 5. CI/CD Pipeline Protection

Prevent accidental key exposure in build logs and test outputs:

```bash
# Scan text for keys in a CI pipeline
echo "$LOG_OUTPUT" | cargo run --features cli -p zkguard -- scan

# Sanitize before logging
echo "$PROMPT_TEXT" | cargo run --features cli -p zkguard -- sanitize
```

## What zkguard Does NOT Do

Being honest about limitations is important:

| Limitation | Explanation |
|------------|-------------|
| Vault encryption requires explicit opt-in | Use the `vault-encrypt` feature for AES-256-GCM + Argon2id on-disk encryption. Without it, vault files are plaintext. |
| Cannot protect keys in HTTP headers | Use the `llm-proxy` feature for HTTP-level protection. |
| Cannot protect against malicious code | If code intentionally extracts keys from memory, zkguard cannot prevent it. |
| Python zeroize not guaranteed | When key bytes cross from Rust to Python (via callbacks), Python's GC manages them. Deterministic zeroing is not possible in Python. |
| Not a replacement for secret managers | zkguard protects LLM prompts specifically. Use Vault/AWS SM for general secret management. |

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| `sanitize()` (1 key) | < 0.1 ms | Regex + vault store |
| `sanitize()` (10 keys) | < 0.5 ms | O(n) single-pass replacement |
| `process_tokens()` | < 0.1 ms | String scanning + closure call |
| STARK proof generation | ~50-200 ms | Depends on key length |
| STARK proof verification | ~10-50 ms | Faster than generation |
| Poseidon2 hash | < 0.01 ms | OnceLock singleton, zero allocation after first call |

## Language Support

| Language | Status | Install |
|----------|--------|---------|
| Rust | Stable | `zkguard = { features = ["llm-guard"] }` |
| Python | Stable | `pip install zkguard` (via maturin) |
| LangChain | Stable | `from zkguard_langchain import ZkGuardCallbackHandler` |
| Node.js | Planned (v0.4) | via napi-rs or C FFI |

## Summary

zkguard exists because **the best time to protect an API key is before it leaves your machine**. Every other solution — provider-side scanning, post-hoc detection, manual redaction — is too late. zkguard makes protection automatic, transparent, and cryptographically verifiable.
