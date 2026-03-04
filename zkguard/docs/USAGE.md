# zkguard Usage Guide

## How It Works (Important)

zkguard runs **locally on your machine**, not on the LLM server. The scanning and key replacement happen **before** any text leaves your computer.

```
User input: "Call API with sk-ant-api03-AAAA..."
      │
      ▼  ← LOCAL (your machine, Rust/Python code)
 [zkguard.sanitize()]
      │
      ▼
 Safe text: "Call API with {{ZKGUARD:a3f2...}}"
      │
      ▼  ← NETWORK (sent to LLM provider)
 LLM (Claude, GPT, etc.)  ← never sees the real key
```

The LLM does not scan your keys. zkguard scans them locally and replaces them before the LLM ever receives the text.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start — Easy API (For Everyone)](#quick-start--easy-api-for-everyone)
3. [Quick Start — Full API (For Developers)](#quick-start--full-api-for-developers)
4. [Quick Start (Rust)](#quick-start-rust)
5. [API Key Scanning](#api-key-scanning)
6. [Sanitizing LLM Prompts](#sanitizing-llm-prompts)
7. [Processing LLM Output](#processing-llm-output)
8. [Encrypted Vault](#encrypted-vault)
9. [ZK Proofs](#zk-proofs)
10. [LangChain Integration](#langchain-integration)
11. [Rust CLI](#rust-cli)
12. [Security Notes](#security-notes)

---

## Installation

### Python (Recommended for LLM users)

```bash
# Build from source (requires Rust toolchain)
cd bindings/python
pip install maturin
maturin develop --features stark

# Or install the wheel directly
pip install zkguard-0.2.0-cp38-abi3-*.whl
```

### Rust

```toml
# Cargo.toml
[dependencies]
zkguard = { path = "crates/zkguard-core", features = ["llm-guard"] }
```

### LangChain Integration

```bash
pip install zkguard langchain-core
```

---

## Quick Start — Easy API (For Everyone)

No setup, no config. One line.

```python
import zkguard

# Remove all API keys from text
safe = zkguard.clean("Debug this: curl -H 'x-api-key: sk-ant-api03-AAAA...' https://api.anthropic.com")
# → "Debug this: curl -H 'x-api-key: [PROTECTED]' https://api.anthropic.com"

# Check if text has keys
zkguard.has_keys("AKIAIOSFODNN7EXAMPLE")   # True
zkguard.has_keys("normal text")             # False

# Scan for details
keys = zkguard.scan("Use AKIAIOSFODNN7EXAMPLE here")
# → [{"provider": "AWS Access Key", "position": (4, 24)}]

# Get detailed report
report = zkguard.safe_prompt("Use sk-ant-api03-... and AKIAIOSFODNN7EXAMPLE")
# → {"text": "Use [PROTECTED] and [PROTECTED]", "found": 2, "providers": ["Anthropic", "AWS Access Key"]}

# Auto-protect any LLM function call
safe_llm = zkguard.wrap_fn(your_openai_call)
safe_llm(messages=[{"role": "user", "content": "key=sk-ant-api03-..."}])
# → LLM never sees the real key
```

### Easy API Reference

| Function | Description |
|----------|-------------|
| `clean(text, placeholder="[PROTECTED]")` | Remove all API keys, return clean text |
| `has_keys(text)` | Check if text contains any API keys (True/False) |
| `scan(text)` | Find all API keys, return list of dicts with provider and position |
| `safe_prompt(text)` | Sanitize text and return dict with text, found count, and providers |
| `wrap_fn(fn, placeholder="[PROTECTED]")` | Wrap any function to auto-clean its string arguments |

---

## Quick Start — Full API (For Developers)

```python
import zkguard

# Create a guard instance
guard = zkguard.ZkGuard()

# Your text that accidentally contains an API key
text = "Call the API with key sk-ant-api03-AAAA...AAAA and get results"

# Step 1: Sanitize — keys are replaced with safe tokens
result = guard.sanitize(text)
print(result.content)
# → "Call the API with key {{ZKGUARD:a3f2b1c9...}} and get results"
print(f"Removed {result.redaction_count} key(s): {result.providers}")

# Step 2: Send sanitized text to LLM (safe — no keys exposed)
llm_response = call_your_llm(result.content)  # your LLM call here

# Step 3: If LLM output contains tokens, replace them
final = guard.process_tokens(llm_response, lambda token: "[KEY_USED]")
```

### What Just Happened?

1. `sanitize()` scanned your text for API keys (Anthropic, OpenAI, AWS, Google)
2. Each key was stored in a secure in-memory vault
3. Keys were replaced with `{{ZKGUARD:<id>}}` tokens
4. The LLM only sees tokens, never real keys
5. `process_tokens()` lets you handle tokens in the LLM output

---

## Quick Start (Rust)

```rust
use zkguard::llm_guard::ContextSanitizer;

let mut guard = ContextSanitizer::new();

// Sanitize
let result = guard.sanitize("Use key sk-ant-api03-AAAA...AAAA here").unwrap();
assert!(!result.content.contains("sk-ant-"));

// Process tokens in LLM output
let output = guard.process_tokens(&result.content, |vault, handle| {
    vault.with_key(handle, |key_bytes| {
        // Use key_bytes to make the actual API call
        Ok("[API_RESPONSE]".to_string())
    })
}).unwrap();
```

---

## API Key Scanning

### Supported Providers

| Provider | Pattern | Example Prefix |
|----------|---------|----------------|
| Anthropic | `sk-ant-*` (93+ chars) | `sk-ant-api03-...` |
| OpenAI | `sk-` (48 chars) | `sk-abc123...` |
| OpenAI Project | `sk-proj-*` (100+ chars) | `sk-proj-...` |
| AWS Access Key | `AKIA` (20 chars) | `AKIAIOSFODNN7...` |
| Google AI | `AIza` (39 chars) | `AIzaSyB...` |
| Unknown | High entropy strings | (auto-detected) |

### Scan Only (No Modification)

```python
scanner = zkguard.ContextScanner()
keys = scanner.scan("My key is AKIAIOSFODNN7EXAMPLE")

for key in keys:
    print(f"Provider: {key.provider}")
    print(f"Position: {key.span}")  # (start, end) byte offsets
```

Note: `DetectedKey.value` is intentionally NOT exposed in Python. The raw key bytes stay in Rust memory with zeroize protection. You can extract the key from the original text using the span if needed.

---

## Sanitizing LLM Prompts

### Basic Usage

```python
guard = zkguard.ZkGuard()

# Sanitize text — detects and replaces all API keys
result = guard.sanitize("Connect with sk-ant-api03-... and AKIAIOSFODNN7EXAMPLE")

print(result.content)         # Text with {{ZKGUARD:...}} tokens
print(result.redaction_count) # Number of keys found
print(result.providers)       # ["Anthropic", "AWS Access Key"]
```

### Manual Key Storage

```python
guard = zkguard.ZkGuard()

# Store a key manually (not from text scanning)
token = guard.store_key(b"my-secret-api-key")
print(token)  # "{{ZKGUARD:a1b2c3...}}"

# Use the token in your prompt
prompt = f"Use {token} to authenticate"
```

### Finding Tokens in Text

```python
tokens = guard.find_tokens("Use {{ZKGUARD:abc123...}} here")
print(tokens)  # ["{{ZKGUARD:abc123...}}"]
```

---

## Processing LLM Output

When the LLM returns text containing `{{ZKGUARD:...}}` tokens, use `process_tokens()` to handle them.

### Replace Tokens with a Label

```python
output = guard.process_tokens(
    llm_response,
    lambda token: "[REDACTED]"
)
```

### Replace Tokens with Custom Logic

```python
def handle_token(token):
    # token is the full "{{ZKGUARD:hex}}" string
    # Return whatever string should replace it
    return f"<key:{token[:20]}...>"

output = guard.process_tokens(llm_response, handle_token)
```

### Typical Round-Trip Flow

```python
guard = zkguard.ZkGuard()

# 1. User input with accidental key
user_input = f"Please use {api_key} to call the weather API"

# 2. Sanitize before sending to LLM
safe = guard.sanitize(user_input)

# 3. Send to LLM (key is protected)
llm_output = your_llm.invoke(safe.content)

# 4. Process LLM output
final = guard.process_tokens(llm_output, lambda t: "[API_CALLED]")
```

---

## Encrypted Vault

zkguard can encrypt your vault to disk using AES-256-GCM with Argon2id key derivation. This protects stored API keys at rest.

### Python

```python
guard = zkguard.ZkGuard()

# Store some keys
guard.sanitize("key=sk-ant-api03-AAAA...AAAA")

# Save encrypted (AES-256-GCM + Argon2id, 64 MiB memory-hard)
guard.save_encrypted("vault.enc", b"my-strong-password")

# Load with password
loaded = zkguard.ZkGuard.load_encrypted("vault.enc", b"my-strong-password")
assert loaded.vault_size == 1

# Custom Argon2id parameters (for faster tests or higher security)
guard.save_encrypted("vault.enc", b"password", m_cost=1024, t_cost=1, p_cost=1)
```

### Rust

```rust
use zkguard::{SecretVault, save_vault_encrypted, load_vault_encrypted, VaultEncryptionParams};

let mut vault = SecretVault::new();
vault.store(b"sk-ant-api03-secret-key").unwrap();

// Save encrypted
let params = VaultEncryptionParams::default(); // 64 MiB, 3 iterations
save_vault_encrypted(&vault, "vault.enc".as_ref(), b"my-password", &params).unwrap();

// Load with password
let loaded = load_vault_encrypted("vault.enc".as_ref(), b"my-password").unwrap();

// Migrate plaintext vault to encrypted
use zkguard::migrate_vault_to_encrypted;
migrate_vault_to_encrypted("vault.bin".as_ref(), "vault.enc".as_ref(), b"password", &params).unwrap();
```

### Security Notes

- Default Argon2id parameters: 64 MiB memory, 3 iterations, 1 parallelism (GPU/ASIC resistant)
- File format v2 with magic bytes "ZKGE", self-contained KDF params
- Vault files written with 0600 permissions on Unix
- All plaintext buffers zeroized after encryption
- Wrong password returns an error (decryption fails with AEAD tag mismatch)

---

## ZK Proofs

zkguard can generate zero-knowledge STARK proofs to prove you possess certain data without revealing it.

### Prove Key Ownership

```python
prover = zkguard.StarkProver()

# Prove knowledge of field elements (e.g., key bytes as integers)
key_bytes = [ord(c) for c in "sk-ant"]  # [115, 107, 45, 97, 110, 116]
proof = prover.prove_key_commit(key_bytes)

print(proof.air_type)       # "KeyCommit"
print(proof.num_rows)       # trace size
print(proof.public_values)  # [eval_final, num_elements]
```

### Verify a Proof

```python
verifier = zkguard.StarkVerifier()
is_valid = verifier.verify(proof)
print(f"Valid: {is_valid}")  # True
```

### Serialize / Deserialize

```python
# Binary (compact)
data = proof.to_bytes()              # bytes
restored = zkguard.StarkProof.from_bytes(data)

# JSON (human-readable)
json_str = proof.to_json()           # str
restored = zkguard.StarkProof.from_json(json_str)
```

### Fibonacci Proof (Example)

```python
prover = zkguard.StarkProver()
proof = prover.prove_fibonacci(8)  # 8 rows (must be power of 2, >= 4)

verifier = zkguard.StarkVerifier()
assert verifier.verify(proof)
```

---

## LangChain Integration

### Callback Handler (Monitoring)

Detects API keys in LLM prompts and outputs. Works with all LangChain versions.

```python
from zkguard_langchain import ZkGuardCallbackHandler

# Warning mode (default) — logs warnings when keys are detected
handler = ZkGuardCallbackHandler()

# Strict mode — raises ValueError when keys are detected
handler = ZkGuardCallbackHandler(raise_on_leak=True)

# Custom logging
handler = ZkGuardCallbackHandler(log_fn=my_logger.warning)

# Use with any LangChain LLM
from langchain_anthropic import ChatAnthropic
llm = ChatAnthropic(
    model="claude-sonnet-4-20250514",
    callbacks=[handler]
)

# After calls, inspect detected keys
print(f"Leaks found: {handler.leak_count}")
print(f"Details: {handler.detected_keys}")

# Reset counters
handler.reset()
```

### What the Callback Scans

| Event | What's Scanned |
|-------|---------------|
| `on_llm_start` | Prompts before sending to LLM |
| `on_chat_model_start` | Chat messages before sending |
| `on_llm_end` | LLM response text |

---

## Rust CLI

```bash
# Build the CLI
cargo build --features cli -p zkguard

# Scan text for keys
echo "key=sk-ant-api03-AAAA..." | cargo run --features cli -p zkguard -- scan

# Sanitize text
echo "key=AKIAIOSFODNN7EXAMPLE" | cargo run --features cli -p zkguard -- sanitize

# Generate a ZK proof
cargo run --features cli -p zkguard -- prove --elements 115,107,45 --output proof.bin

# Verify a proof
cargo run --features cli -p zkguard -- verify --input proof.bin

# Full demo
cargo run --features cli -p zkguard -- demo
```

---

## Security Notes

### What zkguard Protects Against

- Accidental API key inclusion in LLM prompts
- Key leakage through LLM context windows
- Key echoing in LLM responses
- Undetected key exposure in shared prompts/logs

### What zkguard Does NOT Protect Against

- Keys stored in environment variables (`.env` files)
- Keys in HTTP headers (use `llm-proxy` feature for that)
- Keys in database connections
- Intentional key extraction by malicious code

### Python Security Limitations

**Important**: When key bytes cross from Rust to Python (via `process_tokens` callback), they enter Python's garbage-collected memory. Rust's `zeroize` guarantee does not apply to Python memory. The key bytes will persist until Python's GC collects them.

For maximum security, use the Rust library directly or keep key handling inside the `process_tokens` callback without storing the bytes.

### Poseidon2 Hash

```python
# Domain-separated Poseidon2 hash
h = zkguard.poseidon_hash(b"data", b"my_domain")
# Returns 32 bytes (256-bit digest)
```

All internal hashing uses Poseidon2 with unique domain tags to prevent cross-context collisions.

---

## API Reference

### Python Classes

| Class | Description |
|-------|-------------|
| `ContextScanner` | Scan text for API keys |
| `DetectedKey` | Detected key info (provider, span) |
| `ZkGuard` | Main orchestrator (scan + vault + tokens) |
| `SanitizedResult` | Result of sanitize() |
| `StarkProver` | Generate STARK proofs |
| `StarkVerifier` | Verify STARK proofs |
| `StarkProof` | Serializable proof object |

### Easy API Functions

| Function | Description |
|----------|-------------|
| `clean(text, placeholder)` | Remove all API keys from text |
| `has_keys(text)` | Check if text contains API keys |
| `scan(text)` | Find all API keys, return dicts |
| `safe_prompt(text)` | Sanitize and return detailed info |
| `wrap_fn(fn, placeholder)` | Wrap any function for auto-protection |

### Python Functions

| Function | Description |
|----------|-------------|
| `poseidon_hash(data, domain)` | Poseidon2 hash with domain separation |

### Constants

| Constant | Description |
|----------|-------------|
| `VERSION` | Library version string |
