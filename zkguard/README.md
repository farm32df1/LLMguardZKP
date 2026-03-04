<p align="center">
  <h1 align="center">zkguard</h1>
  <p align="center">
    <strong>Zero-knowledge credential protection for LLM workflows</strong>
  </p>
  <p align="center">
    <a href="#quick-start">Quick Start</a> &middot;
    <a href="docs/USAGE.md">Usage Guide</a> &middot;
    <a href="docs/ARCHITECTURE.md">Architecture</a> &middot;
    <a href="docs/WHY_ZKGUARD.md">Why zkguard?</a>
  </p>
</p>

---

API keys leak into LLM prompts every day. zkguard stops them **before they leave your machine**.

```python
import zkguard

# One line. Your API key is gone. Safe to send to any LLM.
safe = zkguard.clean("Debug this: curl -H 'x-api-key: sk-ant-api03-AAAA...' https://api.anthropic.com")
# → "Debug this: curl -H 'x-api-key: [PROTECTED]' https://api.anthropic.com"
```

It scans text for credentials, replaces them with safe placeholders, stores the real keys in a zeroize-on-drop vault, and optionally generates STARK proofs of key ownership — all locally, in under 1ms.

```
                         YOUR MACHINE                              NETWORK
┌──────────────────────────────────────────────────────┐    ┌─────────────────┐
│                                                      │    │                 │
│  "Call API with sk-ant-api03-AAAA..."                │    │                 │
│         │                                            │    │                 │
│         ▼                                            │    │                 │
│  ┌─────────────────┐    ┌───────────────┐            │    │                 │
│  │ Context Scanner │───▶│ Secret Vault  │            │    │                 │
│  │  (regex +       │    │  (zeroize +   │            │    │                 │
│  │   entropy)      │    │   AES-256)    │            │    │                 │
│  └────────┬────────┘    └───────────────┘            │    │                 │
│           │                                          │    │                 │
│           ▼                                          │    │                 │
│  "Call API with {{ZKGUARD:a3f2...}}" ────────────────┼───▶│  LLM (Claude,  │
│                                                      │    │   GPT, etc.)   │
│                                                      │    │                 │
│  LLM response with {{ZKGUARD:a3f2...}} ◀─────────────┼────│  Never sees    │
│         │                                            │    │  the real key  │
│         ▼                                            │    │                 │
│  ┌─────────────────┐                                 │    │                 │
│  │ process_tokens() │──▶ vault.with_key() closure    │    │                 │
│  │  (token → key   │    (key never returned as val)  │    │                 │
│  │   resolution)   │                                 │    │                 │
│  └─────────────────┘                                 │    │                 │
│                                                      │    │                 │
└──────────────────────────────────────────────────────┘    └─────────────────┘
```

## Features

| Feature | Description |
|---------|-------------|
| **API Key Detection** | Regex + Shannon entropy scanning for Anthropic, OpenAI, AWS, Google AI keys |
| **Context Sanitization** | O(n) single-pass key replacement with opaque `{{ZKGUARD:...}}` tokens |
| **Secret Vault** | In-memory key store with `Zeroize + ZeroizeOnDrop`, closure-based access only |
| **Encrypted Vault** | AES-256-GCM encrypted on-disk storage with Argon2id key derivation (64 MiB memory-hard) |
| **ZK Proof of Ownership** | Plonky3 STARK proofs — prove you have a key without revealing it |
| **Handle Registry** | Round-trip token resolution: `sanitize()` → LLM → `process_tokens()` → `with_key()` |
| **Python Bindings** | PyO3 + maturin — `pip install zkguard` (Python 3.8+) |
| **LangChain Integration** | Callback handler for automatic prompt/response monitoring |
| **Poseidon2 Hashing** | Domain-separated hashing with 16 unique `ZKGUARD::` tags |
| **Merkle Batching** | Aggregate multiple proofs into a single Merkle root |
| **CLI** | `scan`, `sanitize`, `prove`, `verify` from the command line |
| **`#![forbid(unsafe_code)]`** | No unsafe Rust in the core crate |

## Quick Start

### Easy API (For Everyone)

```bash
cd bindings/python && pip install maturin && maturin develop --features stark,vault-encrypt
```

```python
import zkguard

# Clean text — one line, done
safe = zkguard.clean("Use key sk-ant-api03-AAAA...AAAA here")
# → "Use key [PROTECTED] here"

# Check if text has keys
zkguard.has_keys("AKIAIOSFODNN7EXAMPLE")  # True
zkguard.has_keys("normal text")            # False

# Get details
zkguard.scan("my key is AKIAIOSFODNN7EXAMPLE")
# → [{"provider": "AWS Access Key", "position": (14, 34)}]

# Auto-protect any LLM call
safe_llm = zkguard.wrap_fn(your_llm_function)
safe_llm(messages=[{"role": "user", "content": "key=sk-ant-api03-..."}])
# → LLM never sees the real key
```

### Full API (For Developers)

```python
import zkguard

guard = zkguard.ZkGuard()

# Step 1: Sanitize — keys are replaced with safe tokens
result = guard.sanitize("Use key sk-ant-api03-AAAA...AAAA for the request")
print(result.content)          # "Use key {{ZKGUARD:a3f2...}} for the request"
print(result.redaction_count)  # 1

# Step 2: Send to LLM safely
llm_response = your_llm(result.content)

# Step 3: Process tokens in LLM output
final = guard.process_tokens(llm_response, lambda token: "[REDACTED]")
```

### Rust

```toml
# Cargo.toml
[dependencies]
zkguard = { path = "crates/zkguard-core", features = ["llm-guard"] }
```

```rust
use zkguard::llm_guard::ContextSanitizer;

let mut guard = ContextSanitizer::new();

// Sanitize
let safe = guard.sanitize("Use key sk-ant-api03-AAAA...AAAA here").unwrap();
assert!(!safe.content.contains("sk-ant-"));

// Process tokens in LLM output
let result = guard.process_tokens(&safe.content, |vault, handle| {
    vault.with_key(handle, |key_bytes| {
        Ok("[API_RESPONSE]".to_string())
    })
}).unwrap();
```

### LangChain

```python
from zkguard_langchain import ZkGuardCallbackHandler

handler = ZkGuardCallbackHandler(raise_on_leak=True)
llm = ChatAnthropic(model="claude-sonnet-4-20250514", callbacks=[handler])
# If a key appears in any prompt or response → ValueError
```

### Encrypted Vault

```python
guard = zkguard.ZkGuard()
guard.sanitize("key=sk-ant-api03-AAAA...AAAA")

# Save encrypted (AES-256-GCM + Argon2id)
guard.save_encrypted("vault.enc", b"my-password")

# Load with password
loaded = zkguard.ZkGuard.load_encrypted("vault.enc", b"my-password")
```

```rust
use zkguard::{SecretVault, save_vault_encrypted, load_vault_encrypted, VaultEncryptionParams};

let mut vault = SecretVault::new();
vault.store(b"sk-ant-api03-secret-key").unwrap();

// Save encrypted (64 MiB memory-hard Argon2id)
let params = VaultEncryptionParams::default();
save_vault_encrypted(&vault, "vault.enc".as_ref(), b"my-password", &params).unwrap();

// Load with password
let loaded = load_vault_encrypted("vault.enc".as_ref(), b"my-password").unwrap();
```

### ZK Proof of Key Knowledge

```python
prover = zkguard.StarkProver()
proof = prover.prove_key_commit([115, 107, 45, 97, 110, 116])  # "sk-ant" as integers

verifier = zkguard.StarkVerifier()
assert verifier.verify(proof)  # True — key ownership proven, key NOT revealed
```

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                          zkguard-core (Rust)                          │
├───────────┬───────────┬────────────┬────────────┬─────────────────────┤
│  core/    │  stark/   │  utils/    │  batching/ │    llm_guard/       │
│           │           │            │            │                     │
│ errors    │ air       │ hash       │ merkle     │ scanner   vault     │
│ types     │ range_air │ constants  │ batch      │ handle    sanitizer │
│ traits    │ key_commit│ compress   │            │ audit     persist   │
│           │ real_stark│            │            │ proxy     encrypt   │
│           │ config    │            │            │                     │
├───────────┴───────────┴────────────┴────────────┴─────────────────────┤
│                                                                       │
│  ┌──────────────────┐    ┌─────────────────────┐                      │
│  │ Python (PyO3)    │    │ LangChain (pure Py)  │                     │
│  │ pip install      │    │ callback + middleware │                     │
│  │ zkguard          │    │ zkguard_langchain     │                     │
│  └──────────────────┘    └─────────────────────┘                      │
└────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
Forward Path (Sanitization):

  User Input ──→ ContextScanner ──→ SecretVault ──→ Safe Output
  "sk-ant-..."    regex + entropy    store(key)     "{{ZKGUARD:a3f2...}}"
                  → DetectedKey      → KeyHandle    (key never leaves vault)


Reverse Path (Token Resolution):

  LLM Output ──→ Handle Registry ──→ SecretVault ──→ Action
  "{{ZKGUARD:..}}"  parse hex id     with_key(h,    closure receives key,
                    → KeyHandle      |bytes| {...})  makes API call


ZK Proof Path (Optional):

  Key Bytes ──→ StarkProver ──→ StarkVerifier
  bytes_to_fields()  prove_key_commit()  verify(proof)
  → Vec<u64>         → STARK trace       → True/False
                     → FRI commit        (key NOT revealed)
                     → StarkProof
```

## Supported Providers

| Provider | Pattern | Example Prefix |
|----------|---------|----------------|
| Anthropic | `sk-ant-[a-zA-Z0-9\-_]{93,}` | `sk-ant-api03-...` |
| OpenAI | `sk-[a-zA-Z0-9]{48}` | `sk-...` |
| OpenAI Project | `sk-proj-[a-zA-Z0-9\-_]{100,}` | `sk-proj-...` |
| AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7...` |
| Google AI | `AIza[0-9A-Za-z\-_]{35}` | `AIzaSy...` |
| Unknown (entropy) | Shannon entropy > 4.5 bits/char | High-entropy tokens (40-200 chars) |

## Build & Test

```bash
# Rust core
cargo test -p zkguard                          # 46 tests (default)
cargo test -p zkguard --features serde         # 50 tests
cargo test -p zkguard --features llm-guard     # 111 tests (77 unit + 20 fuzz + 14 integration)
cargo test -p zkguard --features llm-proxy     # 123 tests (89 unit + 20 fuzz + 14 integration)
cargo test -p zkguard --features vault-encrypt # 121 tests (87 unit + 20 fuzz + 14 integration)

# Code quality
cargo fmt --all -- --check
cargo clippy -p zkguard --all-targets --features vault-encrypt -- -D warnings

# Python bindings (39 tests)
cd bindings/python
maturin develop --features stark,vault-encrypt
pytest tests/ -v

# LangChain integration (8 tests)
cd integrations/langchain
PYTHONPATH=. pytest tests/ -v
```

## Project Structure

```
zkguard/
├── Cargo.toml                        # Workspace root
├── .github/workflows/
│   ├── ci.yml                        # CI (Rust + Python + LangChain, cross-platform)
│   └── release.yml                   # PyPI release (tag-triggered)
├── LICENSE-MIT
├── LICENSE-APACHE
├── crates/
│   └── zkguard-core/                 # Rust engine (crate name: "zkguard")
│       ├── src/
│       │   ├── core/       errors.rs, types.rs, traits.rs
│       │   ├── stark/      air.rs, range_air.rs, key_commit_air.rs, real_stark.rs, config.rs
│       │   ├── utils/      hash.rs, constants.rs, compression.rs
│       │   ├── batching/   merkle.rs, mod.rs
│       │   ├── llm_guard/  vault.rs, scanner.rs, handle.rs, sanitizer.rs,
│       │   │               audit.rs, persistence.rs, encrypted_persistence.rs, proxy.rs
│       │   └── bin/        main.rs (CLI)
│       ├── tests/          llm_scenarios.rs, fuzz_tests.rs
│       └── examples/       basic_proof.rs, key_protection.rs, full_demo.rs
├── bindings/
│   └── python/                       # PyO3 + maturin (pip install zkguard)
│       ├── src/lib.rs
│       ├── python/zkguard/
│       │   ├── __init__.py
│       │   ├── easy.py               # One-liner easy API (clean, has_keys, scan, wrap_fn)
│       │   └── _lowlevel.pyi
│       └── tests/test_zkguard.py     # 39 tests
├── integrations/
│   └── langchain/                    # LangChain callback + middleware
│       ├── zkguard_langchain/
│       │   ├── callback.py
│       │   └── middleware.py
│       └── tests/test_callback.py    # 8 tests
├── examples/python/
│   ├── basic_usage.py
│   ├── easy_example.py               # Easy API usage examples for beginners
│   └── langchain_demo.py
└── docs/
    ├── WHY_ZKGUARD.md                # Motivation and use cases
    ├── WHY_ZKGUARD_KR.md
    ├── USAGE.md                      # Full usage guide
    ├── USAGE_KR.md
    ├── ARCHITECTURE.md               # Internal architecture
    └── ARCHITECTURE_KR.md
```

## Technical Details

| Parameter | Value |
|-----------|-------|
| **Field** | Goldilocks (p = 2^64 - 2^32 + 1) |
| **Hash** | Poseidon2 (width=16, rate=8, S-box=x^7, seed=`0x5A4B_4755_4152_4432`) |
| **STARK** | Plonky3-based transparent proofs (no trusted setup, post-quantum) |
| **FRI** | log_blowup=2, 60 queries, 8 PoW bits (~128-bit soundness) |
| **Vault Encryption** | AES-256-GCM + Argon2id (64 MiB, 3 iterations) |
| **Memory Safety** | `#![forbid(unsafe_code)]` (core), zeroize all secrets, constant-time comparisons |
| **Bindings** | PyO3 0.22 + maturin, abi3-py38 (single wheel for Python 3.8+) |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `alloc` | Yes | Heap allocation support |
| `full-p3` | Yes | Plonky3 STARK prover/verifier |
| `std` | Yes | OS CSPRNG + standard library |
| `llm-guard` | No | API key detection and protection |
| `llm-proxy` | No | HTTP proxy for LLM API calls (reqwest) |
| `serde` | No | JSON/bincode serialization for StarkProof |
| `vault-encrypt` | No | AES-256-GCM encrypted vault (Argon2id KDF) |
| `cli` | No | CLI binary (scan, sanitize, prove, verify) |

## Security Properties

| # | Property | Detail |
|---|----------|--------|
| 1 | **Zero Knowledge** | STARK proofs reveal nothing about the key beyond the public evaluation point |
| 2 | **Memory Safety** | All secret material uses `Zeroize + ZeroizeOnDrop` across 5 modules |
| 3 | **No Unsafe Code** | `#![forbid(unsafe_code)]` enforced in the core crate |
| 4 | **Domain Separation** | 16 unique Poseidon2 domain tags prevent cross-context hash collisions |
| 5 | **Constant-Time** | All key/hash comparisons use `constant_time_eq_fixed` across 8 modules |
| 6 | **Closure-Based Access** | Keys never leave the vault — accessed only via `with_key()` closures |
| 7 | **Encrypted At-Rest** | AES-256-GCM vault encryption with Argon2id (64 MiB memory-hard) |
| 8 | **File Permissions** | Vault files written with 0600 permissions (Unix) |
| 9 | **Fuzz Tested** | 20 proptest-based property tests covering scanner, sanitizer, vault, ZK proofs |

## Honest Limitations

| Limitation | Explanation |
|------------|-------------|
| **Python zeroize** | Python GC does not support deterministic zeroing. Key bytes in Python memory are not zeroized by Rust. |
| **KeyCommitAir** | Uses polynomial evaluation, not a full Poseidon2 hash circuit. Full hash-in-circuit is a future goal. |
| **Windows untested** | macOS + Linux confirmed. Windows wheel builds in CI but not tested end-to-end. |
| **PyO3 bindings** | `#![forbid(unsafe_code)]` does not apply to the Python bindings crate (PyO3 requires unsafe internally). |
| **Not a secret manager** | zkguard protects LLM prompts specifically. Use HashiCorp Vault / AWS SM for general secret management. |

## Documentation

| Document | Language | Description |
|----------|----------|-------------|
| [docs/WHY_ZKGUARD.md](docs/WHY_ZKGUARD.md) | English | Why use zkguard — problem, approach, use cases |
| [docs/WHY_ZKGUARD_KR.md](docs/WHY_ZKGUARD_KR.md) | Korean | Motivation and use cases (Korean) |
| [docs/USAGE.md](docs/USAGE.md) | English | Full usage guide with examples |
| [docs/USAGE_KR.md](docs/USAGE_KR.md) | Korean | Full usage guide (Korean) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | English | Internal architecture and design |
| [docs/ARCHITECTURE_KR.md](docs/ARCHITECTURE_KR.md) | Korean | Architecture document (Korean) |

## Roadmap

- [x] LLM API Proxy (v0.2 — `llm-proxy` feature)
- [x] StarkProof serialization (v0.2 — JSON + bincode)
- [x] Audit logging (v0.2 — hash-chain integrity)
- [x] Persistent vault storage (v0.2 — MAC-verified file format)
- [x] Python bindings (v0.2 — PyO3 + maturin, 39 tests)
- [x] LangChain integration (v0.2 — callback handler, 8 tests)
- [x] Vault disk encryption (v0.3 — AES-256-GCM + Argon2id)
- [x] GitHub Actions CI (v0.3 — Rust + Python + LangChain, cross-platform)
- [ ] Poseidon2-in-AIR: full hash circuit inside STARK (v0.4)
- [ ] Node.js bindings via napi-rs or C FFI (v0.4)
- [ ] Async Python support (v0.4)
- [ ] PyPI published package (v0.4)

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
