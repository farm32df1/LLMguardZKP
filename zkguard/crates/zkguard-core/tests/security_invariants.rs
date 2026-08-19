#![cfg(all(feature = "vault-encrypt", feature = "llm-guard"))]
//! End-to-end security invariants — the kind of tests a third-party auditor
//! or a security-conscious user can run to confirm that "install it and your
//! API keys don't leak" is backed by code, not just documentation.
//!
//! Every test here is a negative claim: "this thing that would be a leak MUST
//! NOT happen". If any of these regress, the leak-prevention contract is
//! broken and CI fails.

use std::path::PathBuf;
use zkguard::llm_guard::encrypted_persistence::{
    load_vault_encrypted, save_vault_encrypted, VaultEncryptionParams,
};
use zkguard::llm_guard::token_map::TokenMap;
use zkguard::llm_guard::vault::SecretVault;

fn fast_params() -> VaultEncryptionParams {
    // Real deployments use the default (64 MiB / t=3). Tests want speed.
    VaultEncryptionParams {
        m_cost: 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("zkguard_sec_{}_{}.bin", name, std::process::id()))
}

/// Invariant 1: The on-disk vault file contains no raw API-key bytes.
///
/// We search the full encrypted file for sentinel substrings that would be
/// present if the persistence layer accidentally leaked plaintext. AES-256-GCM
/// makes such a match statistically impossible for a correctly encrypted file.
#[test]
fn vault_file_contains_no_plaintext_keys() {
    let mut vault = SecretVault::new();
    // Canary keys with very distinctive byte patterns.
    vault
        .store(b"sk-ant-api03-CANARY-ANTHROPIC-KEY-MUST-NOT-APPEAR-ON-DISK")
        .unwrap();
    vault
        .store(b"sk-proj-CANARY-OPENAI-PROJ-MUST-NOT-APPEAR-ON-DISK")
        .unwrap();
    vault.store(b"AKIAIOSFODNN7CANARY").unwrap();
    vault
        .store(b"AIzaCANARYxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        .unwrap();

    let path = tmp("no_plaintext");
    save_vault_encrypted(&vault, &path, b"test-passphrase-2026", &fast_params()).unwrap();

    let raw = std::fs::read(&path).expect("vault file must exist");

    // Each of these substrings must be absent from the encrypted file.
    let sentinels: &[&[u8]] = &[
        b"sk-ant-api03-CANARY",
        b"sk-proj-CANARY",
        b"AKIAIOSFODNN7CANARY",
        b"AIzaCANARY",
        b"CANARY-ANTHROPIC-KEY",
        b"CANARY-OPENAI-PROJ",
        b"MUST-NOT-APPEAR-ON-DISK",
    ];
    for needle in sentinels {
        assert!(
            !raw.windows(needle.len()).any(|w| w == *needle),
            "vault file leaked sentinel {:?} — persistence is not encrypting!",
            core::str::from_utf8(needle).unwrap_or("<bin>")
        );
    }

    // Extra guard: the file must start with the encrypted-vault magic, not
    // the legacy plaintext magic.
    assert_eq!(&raw[..4], b"ZKGE");

    std::fs::remove_file(&path).ok();
}

/// Invariant 2: Wrong passphrase cannot decrypt, and the error message does
/// not leak any distinguishing information about the real passphrase.
#[test]
fn wrong_passphrase_is_rejected_with_generic_error() {
    let mut vault = SecretVault::new();
    vault.store(b"secret-data").unwrap();

    let path = tmp("wrong_pw");
    save_vault_encrypted(&vault, &path, b"real-passphrase", &fast_params()).unwrap();

    let result = load_vault_encrypted(&path, b"guessed-passphrase");
    assert!(result.is_err(), "wrong passphrase must fail");

    let msg = format!("{}", result.unwrap_err());
    assert!(
        !msg.contains("real-passphrase") && !msg.contains("guessed-passphrase"),
        "error message must not leak either passphrase: {}",
        msg
    );

    std::fs::remove_file(&path).ok();
}

/// Invariant 3: Tampering with any byte of the encrypted vault is detected.
/// GCM auth tag + Argon2id salt mean any bit-flip is caught on load.
#[test]
fn tampered_vault_is_rejected() {
    let mut vault = SecretVault::new();
    vault.store(b"integrity-matters").unwrap();

    let path = tmp("tamper");
    save_vault_encrypted(&vault, &path, b"pass", &fast_params()).unwrap();

    let mut data = std::fs::read(&path).unwrap();
    // Flip a byte in the middle (ciphertext region).
    let mid = data.len() / 2;
    data[mid] ^= 0x01;
    std::fs::write(&path, &data).unwrap();

    let result = load_vault_encrypted(&path, b"pass");
    assert!(result.is_err(), "tampered file must be rejected");

    std::fs::remove_file(&path).ok();
}

/// Invariant 4: `TokenMap::to_bytes()` serialization never contains raw key
/// bytes. The token map is stored next to the vault and MUST be free of
/// secret material so that even if someone reads only that file they learn
/// nothing about the keys themselves.
#[test]
fn token_map_serialization_has_no_secrets() {
    let mut vault = SecretVault::new();
    let mut map = TokenMap::new();

    let canary = b"sk-ant-api03-CANARY-IN-TOKEN-MAP-MUST-NOT-LEAK";
    map.register(&mut vault, canary, "anthropic").unwrap();
    map.register(&mut vault, b"AKIACANARY-TOKEN-MAP", "aws")
        .unwrap();

    let bytes = map.to_bytes();

    let sentinels: &[&[u8]] = &[
        b"sk-ant-api03-CANARY",
        b"CANARY-IN-TOKEN-MAP",
        b"AKIACANARY-TOKEN-MAP",
        b"MUST-NOT-LEAK",
    ];
    for needle in sentinels {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == *needle),
            "token map leaked sentinel {:?}",
            core::str::from_utf8(needle).unwrap_or("<bin>")
        );
    }

    // Round-trip still works.
    let restored = TokenMap::from_bytes(&bytes).unwrap();
    assert_eq!(restored.len(), 2);
}

/// Invariant 5: `TokenMap::with_resolved_key` does not return the key — the
/// closure must be the only avenue to touch it. We confirm this by checking
/// that the caller only ever receives a caller-chosen return type.
///
/// This is effectively a type-system assertion: if `resolve()` were still
/// present and returning `String`, this test's signature would not compile.
#[test]
fn token_map_exposes_keys_only_through_closure() {
    let mut vault = SecretVault::new();
    let mut map = TokenMap::new();
    let (token, _) = map
        .register(&mut vault, b"a-very-real-key", "anthropic")
        .unwrap();

    // The closure receives the key as a short-lived borrow; we return only
    // an integer (the length) to prove that no owned copy escapes.
    let len = map
        .with_resolved_key(&token, &vault, |borrowed| Ok(borrowed.len()))
        .unwrap();
    assert_eq!(len, "a-very-real-key".len());

    // Removing the token also wipes the entry from the vault.
    assert!(map.remove_by_provider(&mut vault, "anthropic"));
    assert_eq!(vault.len(), 0);
    assert!(map.with_resolved_key(&token, &vault, |_| Ok(())).is_err());
}

/// Invariant 6: Saving to disk and loading back produces a vault from which
/// every registered key is still addressable through the closure API —
/// but the on-disk bytes never contained the key.
#[test]
fn encrypted_round_trip_keeps_keys_usable_without_leaking() {
    let mut vault = SecretVault::new();
    let handle = vault.store(b"round-trip-secret").unwrap();

    let path = tmp("roundtrip");
    save_vault_encrypted(&vault, &path, b"pw-roundtrip", &fast_params()).unwrap();

    // File should NOT contain the plaintext.
    let raw = std::fs::read(&path).unwrap();
    assert!(!raw.windows(17).any(|w| w == b"round-trip-secret"));

    // Loaded vault still serves the key through with_key.
    let loaded = load_vault_encrypted(&path, b"pw-roundtrip").unwrap();
    let got = loaded
        .with_key(&handle, |k| Ok(k.to_vec()))
        .expect("handle must still work after round-trip");
    assert_eq!(got, b"round-trip-secret");

    std::fs::remove_file(&path).ok();
}

/// Invariant 7: The legacy plaintext persistence format is still parseable
/// for migration, but its MAGIC differs from the encrypted one — so a caller
/// cannot accidentally treat an encrypted file as plaintext or vice versa.
#[test]
fn plaintext_and_encrypted_magic_bytes_differ() {
    let mut vault = SecretVault::new();
    vault.store(b"magic-probe").unwrap();

    let enc_path = tmp("magic_enc");
    save_vault_encrypted(&vault, &enc_path, b"pw", &fast_params()).unwrap();
    let enc = std::fs::read(&enc_path).unwrap();
    assert_eq!(&enc[..4], b"ZKGE", "encrypted magic must be ZKGE");

    let pt_path = tmp("magic_pt");
    zkguard::llm_guard::persistence::save_vault(&vault, &pt_path).unwrap();
    let pt = std::fs::read(&pt_path).unwrap();
    assert_eq!(&pt[..4], b"ZKGV", "plaintext magic must be ZKGV");

    // Loading wrong format fails.
    assert!(load_vault_encrypted(&pt_path, b"pw").is_err());
    assert!(zkguard::llm_guard::persistence::load_vault(&enc_path).is_err());

    std::fs::remove_file(&enc_path).ok();
    std::fs::remove_file(&pt_path).ok();
}
