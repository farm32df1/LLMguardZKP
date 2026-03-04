"""Tests for zkguard Python bindings."""

import zkguard
import pytest


# ── Scanner ──────────────────────────────────────────────────────────────────

class TestContextScanner:
    def test_scan_anthropic_key(self):
        scanner = zkguard.ContextScanner()
        key = "sk-ant-api03-" + "A" * 93
        keys = scanner.scan(f"Use key {key} here")
        assert len(keys) == 1
        assert keys[0].provider == "Anthropic"
        assert keys[0].span == (8, 114)

    def test_scan_aws_key(self):
        scanner = zkguard.ContextScanner()
        keys = scanner.scan("access_key = AKIAIOSFODNN7EXAMPLE")
        aws = [k for k in keys if k.provider == "AWS Access Key"]
        assert len(aws) == 1

    def test_scan_no_keys(self):
        scanner = zkguard.ContextScanner()
        keys = scanner.scan("hello world, no secrets here")
        assert len(keys) == 0

    def test_scan_multiple_keys(self):
        scanner = zkguard.ContextScanner()
        text = f"Key1: sk-ant-api03-{'X' * 93} Key2: AKIAIOSFODNN7EXAMPLE"
        keys = scanner.scan(text)
        assert len(keys) == 2
        providers = {k.provider for k in keys}
        assert "Anthropic" in providers
        assert "AWS Access Key" in providers

    def test_detected_key_repr(self):
        scanner = zkguard.ContextScanner()
        keys = scanner.scan("key=AKIAIOSFODNN7EXAMPLE")
        assert "AWS Access Key" in repr(keys[0])


# ── ZkGuard ──────────────────────────────────────────────────────────────────

class TestZkGuard:
    def test_sanitize_replaces_key(self):
        guard = zkguard.ZkGuard()
        key = "sk-ant-api03-" + "A" * 93
        result = guard.sanitize(f"Use {key} please")
        assert "sk-ant-" not in result.content
        assert "{{ZKGUARD:" in result.content
        assert result.redaction_count == 1
        assert "Anthropic" in result.providers

    def test_sanitize_no_keys(self):
        guard = zkguard.ZkGuard()
        result = guard.sanitize("plain text")
        assert result.content == "plain text"
        assert result.redaction_count == 0

    def test_process_tokens_round_trip(self):
        guard = zkguard.ZkGuard()
        key = "sk-ant-api03-" + "B" * 93
        sanitized = guard.sanitize(f"Call with {key}")
        output = guard.process_tokens(
            sanitized.content,
            lambda token: "[RESOLVED]"
        )
        assert "[RESOLVED]" in output
        assert "{{ZKGUARD:" not in output

    def test_store_key_returns_token(self):
        guard = zkguard.ZkGuard()
        token = guard.store_key(b"my-secret-key")
        assert token.startswith("{{ZKGUARD:")
        assert token.endswith("}}")
        assert guard.vault_size == 1

    def test_find_tokens(self):
        guard = zkguard.ZkGuard()
        token = guard.store_key(b"test-key")
        text = f"Use {token} in your request"
        found = guard.find_tokens(text)
        assert len(found) == 1
        assert found[0] == token

    def test_vault_size_and_handle_count(self):
        guard = zkguard.ZkGuard()
        assert guard.vault_size == 0
        assert guard.handle_count == 0
        key = "sk-ant-api03-" + "C" * 93
        guard.sanitize(f"key={key}")
        assert guard.vault_size == 1
        assert guard.handle_count == 1

    def test_store_empty_key_error(self):
        guard = zkguard.ZkGuard()
        with pytest.raises(ValueError):
            guard.store_key(b"")

    def test_repr(self):
        guard = zkguard.ZkGuard()
        assert "ZkGuard" in repr(guard)


# ── Encrypted Vault ─────────────────────────────────────────────────────────

class TestEncryptedVault:
    def test_save_and_load_encrypted(self, tmp_path):
        guard = zkguard.ZkGuard()
        key = "sk-ant-api03-" + "E" * 93
        result = guard.sanitize(f"key={key}")
        assert result.redaction_count == 1
        assert guard.vault_size == 1

        vault_path = str(tmp_path / "vault.enc")
        password = b"test-password-2024"

        # Save encrypted (fast params for tests)
        saved = guard.save_encrypted(vault_path, password, m_cost=1024, t_cost=1, p_cost=1)
        assert saved == 1

        # Verify file is not readable as plaintext
        with open(vault_path, "rb") as f:
            raw = f.read()
        assert b"sk-ant-api03" not in raw

        # Load and verify vault size
        loaded = zkguard.ZkGuard.load_encrypted(vault_path, password)
        assert loaded.vault_size == 1

    def test_wrong_password_fails(self, tmp_path):
        guard = zkguard.ZkGuard()
        guard.store_key(b"secret-key")

        vault_path = str(tmp_path / "vault.enc")
        guard.save_encrypted(vault_path, b"correct", m_cost=1024, t_cost=1, p_cost=1)

        with pytest.raises(RuntimeError, match="wrong password|decryption"):
            zkguard.ZkGuard.load_encrypted(vault_path, b"wrong")

    def test_empty_password_rejected(self, tmp_path):
        guard = zkguard.ZkGuard()
        vault_path = str(tmp_path / "vault.enc")
        with pytest.raises(RuntimeError):
            guard.save_encrypted(vault_path, b"", m_cost=1024, t_cost=1, p_cost=1)

    def test_encrypted_empty_vault(self, tmp_path):
        guard = zkguard.ZkGuard()
        vault_path = str(tmp_path / "empty.enc")
        saved = guard.save_encrypted(vault_path, b"pw", m_cost=1024, t_cost=1, p_cost=1)
        assert saved == 0

        loaded = zkguard.ZkGuard.load_encrypted(vault_path, b"pw")
        assert loaded.vault_size == 0


# ── STARK ────────────────────────────────────────────────────────────────────

class TestStark:
    def test_prove_verify_key_commit(self):
        prover = zkguard.StarkProver()
        proof = prover.prove_key_commit([115, 107, 45, 97, 110, 116])
        assert proof.air_type == "KeyCommit"
        assert proof.num_rows >= 4

        verifier = zkguard.StarkVerifier()
        assert verifier.verify(proof) is True

    def test_prove_verify_fibonacci(self):
        prover = zkguard.StarkProver()
        proof = prover.prove_fibonacci(8)
        assert proof.air_type == "Fibonacci"

        verifier = zkguard.StarkVerifier()
        assert verifier.verify(proof) is True

    def test_proof_serialization_bincode(self):
        prover = zkguard.StarkProver()
        proof = prover.prove_key_commit([1, 2, 3])
        data = proof.to_bytes()
        assert isinstance(data, bytes)
        assert len(data) > 0

        restored = zkguard.StarkProof.from_bytes(data)
        verifier = zkguard.StarkVerifier()
        assert verifier.verify(restored) is True

    def test_proof_serialization_json(self):
        prover = zkguard.StarkProver()
        proof = prover.prove_fibonacci(8)
        json_str = proof.to_json()
        assert isinstance(json_str, str)

        restored = zkguard.StarkProof.from_json(json_str)
        verifier = zkguard.StarkVerifier()
        assert verifier.verify(restored) is True

    def test_proof_properties(self):
        prover = zkguard.StarkProver()
        proof = prover.prove_key_commit([10, 20, 30])
        assert isinstance(proof.public_values, list)
        assert len(proof.public_values) == 2  # [eval_final, num_elements]
        assert proof.public_values[1] == 3   # num_elements

    def test_invalid_bincode_error(self):
        with pytest.raises(RuntimeError):
            zkguard.StarkProof.from_bytes(b"invalid data")


# ── Hash ─────────────────────────────────────────────────────────────────────

class TestHash:
    def test_poseidon_hash_deterministic(self):
        h1 = zkguard.poseidon_hash(b"hello", b"domain")
        h2 = zkguard.poseidon_hash(b"hello", b"domain")
        assert h1 == h2
        assert isinstance(h1, bytes)
        assert len(h1) == 32

    def test_poseidon_hash_domain_separation(self):
        h1 = zkguard.poseidon_hash(b"data", b"domain1")
        h2 = zkguard.poseidon_hash(b"data", b"domain2")
        assert h1 != h2

    def test_poseidon_hash_different_data(self):
        h1 = zkguard.poseidon_hash(b"data1", b"domain")
        h2 = zkguard.poseidon_hash(b"data2", b"domain")
        assert h1 != h2


# ── Easy API ────────────────────────────────────────────────────────────────

class TestEasyAPI:
    """Tests for the one-liner easy API (for non-technical users)."""

    def test_clean_removes_key(self):
        key = "sk-ant-api03-" + "A" * 93
        result = zkguard.clean(f"Use {key} here")
        assert "sk-ant-" not in result
        assert "[PROTECTED]" in result
        assert "Use " in result and " here" in result

    def test_clean_custom_placeholder(self):
        key = "sk-ant-api03-" + "A" * 93
        result = zkguard.clean(f"key={key}", placeholder="***")
        assert "***" in result
        assert "sk-ant-" not in result

    def test_clean_no_keys(self):
        text = "just normal text, nothing secret"
        assert zkguard.clean(text) == text

    def test_clean_multiple_keys(self):
        key1 = "sk-ant-api03-" + "X" * 93
        text = f"{key1} and AKIAIOSFODNN7EXAMPLE"
        result = zkguard.clean(text)
        assert "sk-ant-" not in result
        assert "AKIA" not in result
        assert result.count("[PROTECTED]") == 2

    def test_has_keys_true(self):
        key = "sk-ant-api03-" + "A" * 93
        assert zkguard.has_keys(f"key={key}") is True

    def test_has_keys_false(self):
        assert zkguard.has_keys("no secrets here") is False

    def test_scan_returns_dicts(self):
        keys = zkguard.scan("key=AKIAIOSFODNN7EXAMPLE")
        assert len(keys) == 1
        assert keys[0]["provider"] == "AWS Access Key"
        assert isinstance(keys[0]["position"], tuple)

    def test_scan_empty(self):
        assert zkguard.scan("safe text") == []

    def test_safe_prompt(self):
        key = "sk-ant-api03-" + "A" * 93
        result = zkguard.safe_prompt(f"Use {key} here")
        assert "sk-ant-" not in result["text"]
        assert "[PROTECTED]" in result["text"]
        assert result["found"] == 1
        assert "Anthropic" in result["providers"]

    def test_safe_prompt_no_keys(self):
        result = zkguard.safe_prompt("safe text")
        assert result["text"] == "safe text"
        assert result["found"] == 0
        assert result["providers"] == []

    def test_wrap_fn(self):
        captured = []
        def fake_llm(prompt):
            captured.append(prompt)
            return "response"

        key = "sk-ant-api03-" + "A" * 93
        safe_llm = zkguard.wrap_fn(fake_llm)
        safe_llm(f"Use {key}")
        assert "sk-ant-" not in captured[0]
        assert "[PROTECTED]" in captured[0]

    def test_wrap_fn_messages(self):
        captured = []
        def fake_llm(messages=None):
            captured.append(messages)
            return "response"

        key = "sk-ant-api03-" + "A" * 93
        safe_llm = zkguard.wrap_fn(fake_llm)
        safe_llm(messages=[
            {"role": "user", "content": f"Use {key}"},
            {"role": "system", "content": "Be helpful"},
        ])
        assert "sk-ant-" not in captured[0][0]["content"]
        assert captured[0][1]["content"] == "Be helpful"  # no keys, unchanged


# ── Version ──────────────────────────────────────────────────────────────────

def test_version():
    assert isinstance(zkguard.VERSION, str)
    assert len(zkguard.VERSION) > 0
