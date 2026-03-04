"""zkguard basic usage example.

Install: pip install zkguard
"""

import zkguard

print(f"zkguard v{zkguard.VERSION}")
print()

# ── 1. Scan for API keys ────────────────────────────────────────────────────

scanner = zkguard.ContextScanner()
text = "Call Anthropic with sk-ant-api03-" + "A" * 93 + " and AWS AKIAIOSFODNN7EXAMPLE"
keys = scanner.scan(text)
print(f"[Scan] Found {len(keys)} key(s):")
for k in keys:
    print(f"  - {k.provider} at position {k.span}")

# ── 2. Sanitize (auto-detect + vault + token replacement) ───────────────────

guard = zkguard.ZkGuard()
result = guard.sanitize(text)
print(f"\n[Sanitize] {result.redaction_count} key(s) redacted")
print(f"  Safe text: {result.content[:60]}...")
print(f"  Providers: {result.providers}")
print(f"  Vault size: {guard.vault_size}")

# ── 3. Process tokens (reverse substitution) ────────────────────────────────

output = guard.process_tokens(result.content, lambda token: "[KEY_USED]")
print(f"\n[Process] {output[:60]}...")

# ── 4. ZK Proof (STARK) ────────────────────────────────────────────────────

prover = zkguard.StarkProver()
proof = prover.prove_key_commit([115, 107, 45, 97, 110, 116])  # "sk-ant"
print(f"\n[Prove] {proof}")

verifier = zkguard.StarkVerifier()
valid = verifier.verify(proof)
print(f"[Verify] Valid: {valid}")

# ── 5. Serialization ────────────────────────────────────────────────────────

data = proof.to_bytes()
print(f"\n[Serialize] {len(data)} bytes (bincode)")
restored = zkguard.StarkProof.from_bytes(data)
print(f"[Deserialize] Verified: {verifier.verify(restored)}")

# ── 6. Poseidon2 Hash ───────────────────────────────────────────────────────

h = zkguard.poseidon_hash(b"hello zkguard", b"example_domain")
print(f"\n[Hash] Poseidon2: {h.hex()[:32]}...")
