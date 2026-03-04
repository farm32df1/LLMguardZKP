# zkguard Architecture

## Overview

zkguard is a Rust library that protects API keys and secrets from leaking into LLM context windows. It combines **context sanitization** (detect and replace keys with opaque tokens) with **zero-knowledge proofs** (prove key ownership without revealing the key).

```
┌─────────────────────────────────────────────────────────────┐
│                     User Application                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   User Prompt ──→ ContextSanitizer.sanitize()               │
│                        │                                    │
│                        ├── ContextScanner (detect keys)     │
│                        ├── SecretVault (store keys)         │
│                        └── HandleId (opaque token)          │
│                                                             │
│   Sanitized Prompt ──→ LLM API Call (no secrets!)           │
│                                                             │
│   LLM Response ──→ ContextSanitizer.process_tokens()        │
│                        │                                    │
│                        └── vault.with_key() closure         │
│                             └── Make real API call           │
│                                                             │
│   [Optional] StarkProver.prove_key_commit()                 │
│                  └── ZK proof of key ownership              │
│                                                             │
│   [Optional] StarkVerifier.verify_key_commit()              │
│                  └── Third-party verification               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

### Forward Path (Sanitization)

```
User Input          ContextScanner           SecretVault          Output
─────────────       ──────────────           ───────────          ──────
"Use key             regex scan              store(key_bytes)     "Use key
 sk-ant-api03-..."   entropy scan  ──────→   → KeyHandle          {{ZKGUARD:a3f2...}}
                     → DetectedKey           → HandleId           ..."
                                             → zeroize-on-drop
```

1. `ContextScanner.scan()` detects API keys using compiled regex patterns (OnceLock) and Shannon entropy heuristics
2. For each detected key, `SecretVault.store()` encrypts and stores the key material, returning a `KeyHandle`
3. The key in the original text is replaced with `{{ZKGUARD:<hex-id>}}`
4. The `KeyHandle` is registered in the `ContextSanitizer`'s handle registry (`BTreeMap<HandleId, KeyHandle>`)

### Reverse Path (Token Resolution)

```
LLM Output          Handle Registry          SecretVault          Action
──────────          ───────────────          ───────────          ──────
"Call API with       find "{{ZKGUARD:..."    with_key(handle,     Closure receives
 {{ZKGUARD:a3f2..}}  → parse hex id          |key_bytes| {       raw key bytes,
 and return"         → lookup KeyHandle       // API call        makes HTTP call,
                                             })                  returns result
```

1. `process_tokens()` scans LLM output for `{{ZKGUARD:<hex>}}` patterns
2. Each token is resolved via the handle registry to find the corresponding `KeyHandle`
3. The caller's closure receives `(&SecretVault, &KeyHandle)` — it calls `vault.with_key()` to access the raw key
4. The key **never** appears in the returned string — only the closure's return value

### ZK Proof Path (Optional)

```
Key Material         StarkProver              StarkVerifier
────────────         ───────────              ─────────────
bytes_to_fields()    prove_key_commit()       verify_key_commit()
→ Vec<u64>           → polynomial eval        → check proof
                     → STARK trace            → public values only
                     → FRI commit             → key NOT revealed
                     → StarkProof
```

1. Key bytes are converted to Goldilocks field elements via `bytes_to_fields()`
2. `KeyCommitAir` computes a polynomial evaluation: `eval = Σ(key[i] * ALPHA^i)` where `ALPHA = 0x7A4B_4755_4152_4431`
3. The STARK proof commits to the trace without revealing key values
4. The verifier sees only `(eval, num_elements)` — enough to confirm key knowledge, not enough to recover the key

## Module Architecture

### core/ — Foundation Types

```
errors.rs ──→ ZKGuardError enum (11 variants)
              Result<T> type alias

types.rs  ──→ CommittedPublicInputs (Poseidon2 commitment)
              Proof, Witness, PublicInputs

traits.rs ──→ Prover<Input, Output> trait
              Verifier<Proof, Output> trait
```

### stark/ — Plonky3 STARK Integration

```
air.rs ──────────→ SimpleAir { Fibonacci, Sum, Multiplication }
                   Implements p3_air::Air<AB>

range_air.rs ────→ RangeCheckAir (value within [0, max])

key_commit_air.rs → KeyCommitAir (polynomial evaluation circuit)
                   WIDTH = 3 columns: [value, eval, alpha_power]
                   MAX_KEY_ELEMENTS = 512

real_stark.rs ───→ StarkProver  (wraps p3-uni-stark prove())
                   StarkVerifier (wraps p3-uni-stark verify())
                   StarkProof { trace data, public values, num_rows }

                   Methods:
                   - prove_fibonacci / verify_fibonacci
                   - prove_sum / verify_sum
                   - prove_multiplication / verify_multiplication
                   - prove_range / verify_range
                   - prove_key_commit / verify_key_commit

config.rs ───────→ StarkConfig { security_bits, fri_queries, ... }
                   validate() with bounds from constants.rs
```

### utils/ — Cryptographic Utilities

```
hash.rs ─────────→ get_poseidon2() — OnceLock singleton
                   poseidon2_hash(domain, data) → [u8; 32]
                   bytes_to_fields(bytes) → Vec<u64>
                   combine_hashes() — stack-based combination
                   constant_time_eq_fixed() — side-channel resistant

constants.rs ────→ Single source of truth for ALL numeric constants
                   Poseidon2: WIDTH, RATE, OUTPUT_SIZE, SEED
                   FRI: LOG_BLOWUP, NUM_QUERIES, POW_BITS
                   Config: SECURITY_BITS_MIN/MAX, FRI_QUERIES_MIN/MAX
                   Handle: ID_BYTES, BINDING_SIZE
                   Scanner: ENTROPY_THRESHOLD, MIN/MAX_TOKEN_LEN
                   16 domain separation tags (ZKGUARD::*)

compression.rs ──→ RLE compression with integrity checksums
                   Decompression bomb guard (MAX_RLE_DECOMPRESSED_SIZE)
```

### batching/ — Proof Aggregation

```
merkle.rs ───────→ MerkleTree (Poseidon2-based)
                   Domain-separated node hashing

mod.rs ──────────→ ProofBatch { proofs, merkle_root }
                   Batch verification
```

### llm_guard/ — LLM API Key Protection

```
scanner.rs ──────→ ContextScanner
                   - 5 regex patterns (OnceLock, compiled once)
                   - Shannon entropy heuristic for unknown formats
                   - Span deduplication (Anthropic > OpenAI)

                   DetectedKey { provider, value (Zeroize), span }
                   ApiProvider enum (6 variants)

vault.rs ────────→ SecretVault
                   - BTreeMap<HandleId, VaultEntry>
                   - store(key_bytes) → KeyHandle
                   - with_key(handle, closure) → Result
                   - revoke(handle_id) — remove from vault
                   - Zeroize on drop for all entries

handle.rs ───────→ HandleId([u8; 16]) — opaque identifier
                   KeyHandle { id, commitment, binding }
                   - to_token() → "{{ZKGUARD:<hex>}}"
                   - is_valid() → verify binding integrity
                   - from_hex() → parse hex string

                   Poseidon2 commitment binds handle to key

sanitizer.rs ────→ ContextSanitizer (main API surface)
                   - sanitize(text) → SanitizedText
                   - process_tokens(text, closure) → String
                   - from_vault(vault) — construct from loaded vault
                   - vault() / vault_mut() — vault access
                   - handle_count() — registry size

                   Internally owns:
                   - SecretVault
                   - ContextScanner
                   - BTreeMap<HandleId, KeyHandle> (registry)

audit.rs ────────→ AuditLog
                   - Hash-chain integrity (DOMAIN_AUDIT_ENTRY)
                   - Append-only event log

persistence.rs ──→ save_vault / load_vault
                   - MAC-verified plaintext file format

encrypted_persistence.rs → Encrypted vault (vault-encrypt feature)
                   - AES-256-GCM + Argon2id key derivation
                   - File format v2: magic "ZKGE" + KDF params + ciphertext
                   - save_vault_encrypted / load_vault_encrypted
                   - migrate_vault_to_encrypted

proxy.rs ────────→ LlmProxy (llm-proxy feature)
                   - reqwest-based HTTP proxy for LLM API calls
```

## Cryptographic Design

### Poseidon2 Hash

- **Width**: 16 field elements (rate=8, capacity=8)
- **S-box**: x^7 (algebraic degree 7)
- **Seed**: `0x5A4B_4755_4152_4432` (ASCII "ZKGUARD2")
- **Initialization**: `OnceLock` singleton — computed once, reused
- **Domain separation**: Every call includes a unique `ZKGUARD::*` tag to prevent cross-context collisions

### STARK Proof System

- **Framework**: Plonky3 (transparent, post-quantum)
- **Field**: Goldilocks (p = 2^64 - 2^32 + 1)
- **FRI parameters**:
  - `log_blowup = 2` (4x blowup)
  - `num_queries = 60`
  - `proof_of_work_bits = 8`
  - Soundness: 2 × 60 + 8 = 128 bits

### KeyCommitAir Circuit

The key commitment circuit proves knowledge of a key via polynomial evaluation:

```
Trace columns: [value, eval, alpha_power]

Row 0:   value=key[0]  eval=key[0]              alpha_power=ALPHA
Row i:   value=key[i]  eval=eval+key[i]*alpha^i  alpha_power=alpha^(i+1)

Public outputs: (final_eval, num_elements)
```

- `ALPHA = 0x7A4B_4755_4152_4431` (domain-specific evaluation point)
- Different keys produce different `(eval, num_elements)` pairs
- The verifier learns only the evaluation point — not the key coefficients

### Secret Vault Security Model

```
   store(key_bytes)
        │
        ▼
   ┌─────────────┐
   │  VaultEntry  │
   │  ┌─────────┐ │
   │  │key_data │ │ ← Zeroize + ZeroizeOnDrop
   │  │(Vec<u8>)│ │
   │  └─────────┘ │
   │  commitment   │ ← Poseidon2(DOMAIN_KEY_COMMIT, key_data)
   │  handle_id    │ ← random 16 bytes (getrandom)
   └──────┬────────┘
          │
          ▼
   with_key(handle, |bytes| { ... })
        │
        └── Closure receives &[u8] — key never returned as value
```

Key principles:
1. Keys enter via `store()`, exit only via `with_key()` closures
2. All key material implements `Zeroize + ZeroizeOnDrop`
3. `Debug` implementations redact secret fields
4. Handle bindings use Poseidon2 with `DOMAIN_KEY_HANDLE` tag
5. Binding verification uses `constant_time_eq_fixed`

## Constants Management

All numeric constants are centralized in `src/utils/constants.rs`:

| Category | Constants | Purpose |
|----------|-----------|---------|
| Poseidon2 | WIDTH, RATE, OUTPUT_SIZE, SEED | Hash function parameters |
| FRI | LOG_BLOWUP, NUM_QUERIES, POW_BITS | Proof system soundness |
| Config | SECURITY_BITS_MIN/MAX, FRI_QUERIES_MIN/MAX | Validation bounds |
| Handle | ID_BYTES, BINDING_SIZE | Opaque reference sizing |
| Scanner | ENTROPY_THRESHOLD, MIN/MAX_TOKEN_LEN | Key detection tuning |
| KeyCommit | WIDTH, MAX_KEY_ELEMENTS | AIR circuit dimensions |
| Compression | RLE_SIZE_THRESHOLD | Compression trigger |
| Domains | 16 unique ZKGUARD:: tags | Hash domain separation |

No magic numbers in application code — all numeric literals come from `constants.rs`.

## Error Handling

```rust
enum ZKGuardError {
    InvalidProof { reason: String },
    VerificationFailed { reason: String },
    InvalidInput { reason: String },
    SerializationError { reason: String },
    ProverError { reason: String },
    ConfigError { reason: String },
    KeyNotFound,
    VaultError { reason: String },
    HandleError { reason: String },
    CompressionError { reason: String },
    DecompressionError { reason: String },
}
```

- Verify methods use `stark_verify_result()` — errors are propagated, never swallowed
- `Ok(true)` = valid proof, `Err(VerificationFailed)` = invalid proof with reason

## Testing Strategy

### Unit Tests (77 tests with llm-guard, 87 with vault-encrypt)

Each module has co-located `#[cfg(test)] mod tests` covering:
- Happy path operations
- Edge cases (empty input, malformed data, boundary values)
- Error conditions (invalid handles, revoked keys)
- Constant consistency checks

### Fuzz Tests (20 proptest-based)

`tests/fuzz_tests.rs` — property-based testing with proptest:
- Random input fuzzing for scanner, sanitizer, vault
- Arbitrary key patterns and edge cases
- Round-trip consistency verification

### Integration Tests (14 scenarios)

`tests/llm_scenarios.rs` — end-to-end scenarios:

| # | Scenario | What it verifies |
|---|----------|-----------------|
| 1 | Anthropic key round-trip | sanitize → LLM → process_tokens → with_key |
| 2 | Multi-provider (Anthropic+AWS) | 2 keys detected + individually processed |
| 3 | ZK key ownership proof | STARK prove + verify (KeyCommitAir) |
| 4 | Full pipeline | sanitize + ZK proof + LLM call + independent verify |
| 5 | Key revocation | sanitize, then vault state check |
| 6 | Revoked handle rejection | revoke, then with_key fails |
| 7 | Handle integrity | is_valid() + with_key() |
| 8 | No tokens in response | passthrough, closure not called |
| 9 | Multi-turn conversation | same token reused across turns |
| 10 | Code snippet keys | code structure preserved + key replaced |
| 11 | ZK proof binding | different key → different eval value |
| 12 | Commitment consistency | vault storage + handle accessor methods |
| 13 | Google AI key detection | AIza prefix detected |
| 14 | Text preservation | surrounding text exactly maintained |

### Examples (3 runnable demos)

- `basic_proof.rs` — STARK Fibonacci proof generation and verification
- `key_protection.rs` — API key sanitization
- `full_demo.rs` — complete 7-step pipeline with timing output
