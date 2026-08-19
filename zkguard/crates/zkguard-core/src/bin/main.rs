//! zkguard CLI — command-line tool for API key protection and ZK proofs.
//!
//! Build: `cargo build --features cli`
//! Usage: `zkguard <COMMAND>`

use clap::{Parser, Subcommand};
use std::io::{self, Read};
use std::path::PathBuf;
use std::time::Instant;

use zkguard::llm_guard::ContextSanitizer;
use zkguard::stark::air::SimpleAir;
use zkguard::stark::real_stark::{StarkProof, StarkProver, StarkVerifier};
use zkguard::utils::hash::bytes_to_fields;

#[derive(Parser)]
#[command(name = "zkguard")]
#[command(about = "ZK-based credential protection for LLM workflows")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan text for API keys and report findings
    Scan {
        /// Text to scan (reads from stdin if not provided)
        #[arg(short, long)]
        text: Option<String>,
    },

    /// Sanitize text: replace API keys with {{ZKGUARD:...}} tokens
    Sanitize {
        /// Text to sanitize (reads from stdin if not provided)
        #[arg(short, long)]
        text: Option<String>,
    },

    /// Generate a ZK proof of key knowledge
    Prove {
        /// The API key to prove knowledge of (read from stdin if not provided)
        #[arg(short, long)]
        key: Option<String>,

        /// Output file for the proof (bincode format)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify a ZK proof from a file
    Verify {
        /// Proof file to verify (bincode format)
        #[arg(short, long)]
        proof: PathBuf,
    },

    /// Start a local proxy server that sanitizes LLM API requests
    #[cfg(feature = "proxy-server")]
    Proxy {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// LLM provider: anthropic, openai, or a custom URL
        #[arg(long, default_value = "anthropic")]
        provider: String,

        /// Bind address
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
    },

    /// Manage API keys in the encrypted vault (key manager mode)
    #[cfg(feature = "proxy-server")]
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },

    /// Run a full demo: sanitize + prove + verify
    Demo,
}

#[cfg(feature = "proxy-server")]
#[derive(Subcommand)]
enum KeyAction {
    /// Register an API key and get a dummy proxy token
    Add {
        /// Provider name: anthropic, openai, google, aws, or custom
        #[arg(long)]
        provider: String,
    },

    /// List all registered proxy tokens (real keys are never shown)
    List,

    /// Remove a registered key by provider name
    Remove {
        /// Provider name to remove
        #[arg(long)]
        provider: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { text } => cmd_scan(text),
        Commands::Sanitize { text } => cmd_sanitize(text),
        Commands::Prove { key, output } => cmd_prove(key, output),
        Commands::Verify { proof } => cmd_verify(proof),
        #[cfg(feature = "proxy-server")]
        Commands::Proxy {
            port,
            provider,
            bind,
        } => cmd_proxy(port, provider, bind),
        #[cfg(feature = "proxy-server")]
        Commands::Key { action } => cmd_key(action),
        Commands::Demo => cmd_demo(),
    }
}

fn read_stdin() -> String {
    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .expect("Failed to read stdin");
    buf
}

fn cmd_scan(text: Option<String>) {
    let text = text.unwrap_or_else(read_stdin);
    let mut guard = ContextSanitizer::new();
    let result = guard.sanitize(&text).expect("Scan failed");

    if result.redactions.is_empty() {
        println!("No API keys detected.");
    } else {
        println!("Detected {} API key(s):", result.redactions.len());
        for (i, r) in result.redactions.iter().enumerate() {
            println!(
                "  [{}] Provider: {:?}, Span: {:?}",
                i + 1,
                r.provider,
                r.original_span
            );
        }
    }
}

fn cmd_sanitize(text: Option<String>) {
    let text = text.unwrap_or_else(read_stdin);
    let mut guard = ContextSanitizer::new();
    let result = guard.sanitize(&text).expect("Sanitize failed");

    println!("{}", result.content);

    if !result.redactions.is_empty() {
        eprintln!("--- {} key(s) redacted ---", result.redactions.len());
    }
}

fn cmd_prove(key: Option<String>, output: Option<PathBuf>) {
    let key = key.unwrap_or_else(|| {
        eprint!("Enter API key (will not echo): ");
        read_stdin().trim().to_string()
    });

    if key.is_empty() {
        eprintln!("Error: key must not be empty");
        std::process::exit(1);
    }

    let start = Instant::now();
    let prover = StarkProver::new(SimpleAir::fibonacci()).expect("Prover init failed");
    let fields = bytes_to_fields(key.as_bytes());
    let proof = prover
        .prove_key_commit(&fields)
        .expect("Proof generation failed");
    let prove_time = start.elapsed();

    println!(
        "Proof generated in {:.1}ms",
        prove_time.as_secs_f64() * 1000.0
    );
    println!("  Air type:    {:?}", proof.air_type);
    println!("  Trace rows:  {}", proof.num_rows);
    println!("  Public vals: {:?}", proof.public_values);

    if let Some(path) = output {
        proof.save_to_file(&path).expect("Failed to save proof");
        println!("  Saved to:    {}", path.display());
    } else {
        let bin = proof.to_bincode().expect("Serialization failed");
        println!("  Proof size:  {} bytes", bin.len());
        eprintln!("(Use --output <file> to save the proof)");
    }
}

fn cmd_verify(proof_path: PathBuf) {
    let start = Instant::now();
    let proof = StarkProof::load_from_file(&proof_path).expect("Failed to load proof");
    let load_time = start.elapsed();

    println!("Proof loaded in {:.1}ms", load_time.as_secs_f64() * 1000.0);
    println!("  Air type:    {:?}", proof.air_type);
    println!("  Trace rows:  {}", proof.num_rows);
    println!("  Public vals: {:?}", proof.public_values);

    let start = Instant::now();
    let verifier = StarkVerifier::new(SimpleAir::fibonacci()).expect("Verifier init failed");
    match verifier.verify_by_type(&proof) {
        Ok(true) => {
            let verify_time = start.elapsed();
            println!(
                "VALID - proof verified in {:.1}ms",
                verify_time.as_secs_f64() * 1000.0
            );
        }
        Ok(false) => {
            println!("INVALID - proof verification returned false");
            std::process::exit(1);
        }
        Err(e) => {
            println!("INVALID - verification error: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "proxy-server")]
fn cmd_proxy(port: u16, provider: String, bind: String) {
    let target_base_url = match provider.to_lowercase().as_str() {
        "anthropic" => "https://api.anthropic.com".to_string(),
        "openai" => "https://api.openai.com".to_string(),
        url if url.starts_with("http") => url.to_string(),
        other => {
            eprintln!(
                "Error: unknown provider '{}'. Use: anthropic, openai, or a full URL",
                other
            );
            std::process::exit(1);
        }
    };

    let data_dir = zkguard::llm_guard::proxy_server::default_data_dir();
    let vault_file = data_dir.join("vault.zkge");

    // If a vault is present on disk, we need the passphrase to unlock it.
    // The passphrase can come from the ZKGUARD_PASSPHRASE env var (for service
    // deployments) or an interactive TTY prompt.
    let passphrase = if vault_file.exists() {
        Some(prompt_passphrase("vault passphrase").unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }))
    } else {
        None
    };

    let vault_dir = if vault_file.exists() {
        Some(data_dir.to_string_lossy().to_string())
    } else {
        None
    };

    let config = zkguard::llm_guard::proxy_server::ProxyConfig {
        port,
        target_base_url,
        bind_addr: bind,
        vault_path: vault_dir,
        passphrase,
    };

    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    if let Err(e) = rt.block_on(zkguard::llm_guard::proxy_server::start_proxy_server(config)) {
        eprintln!("Proxy server error: {}", e);
        std::process::exit(1);
    }
}

/// Read a passphrase from `ZKGUARD_PASSPHRASE` env var if set, otherwise
/// prompt the user on the TTY without echoing. Empty input is rejected so a
/// missing passphrase never silently falls through to an unencrypted path.
#[cfg(feature = "proxy-server")]
fn prompt_passphrase(label: &str) -> std::result::Result<String, String> {
    if let Ok(env_pw) = std::env::var("ZKGUARD_PASSPHRASE") {
        if env_pw.is_empty() {
            return Err("ZKGUARD_PASSPHRASE is set but empty".into());
        }
        return Ok(env_pw);
    }
    let pw = rpassword::prompt_password(format!("{}: ", label))
        .map_err(|e| format!("failed to read passphrase: {}", e))?;
    if pw.is_empty() {
        return Err("passphrase must not be empty".into());
    }
    Ok(pw)
}

/// Prompt twice and verify the two entries match — used on first vault
/// creation so a typo doesn't lock the user out of their own keys.
#[cfg(feature = "proxy-server")]
fn prompt_new_passphrase() -> std::result::Result<String, String> {
    if let Ok(env_pw) = std::env::var("ZKGUARD_PASSPHRASE") {
        if env_pw.is_empty() {
            return Err("ZKGUARD_PASSPHRASE is set but empty".into());
        }
        return Ok(env_pw);
    }
    let pw = rpassword::prompt_password("new vault passphrase: ")
        .map_err(|e| format!("failed to read passphrase: {}", e))?;
    if pw.len() < 8 {
        return Err("passphrase must be at least 8 characters".into());
    }
    let confirm = rpassword::prompt_password("confirm passphrase: ")
        .map_err(|e| format!("failed to read passphrase: {}", e))?;
    if pw != confirm {
        return Err("passphrases do not match".into());
    }
    Ok(pw)
}

#[cfg(feature = "proxy-server")]
fn cmd_key(action: KeyAction) {
    use zeroize::Zeroizing;
    use zkguard::llm_guard::encrypted_persistence::{
        load_vault_encrypted, save_vault_encrypted, VaultEncryptionParams,
    };
    use zkguard::llm_guard::token_map::TokenMap;
    use zkguard::llm_guard::vault::SecretVault;

    let data_dir = zkguard::llm_guard::proxy_server::default_data_dir();
    std::fs::create_dir_all(&data_dir).expect("Failed to create data directory");

    let vault_file = data_dir.join("vault.zkge");
    let token_map_file = data_dir.join("token_map.bin");
    let legacy_plaintext = data_dir.join("vault.zkgv");

    if legacy_plaintext.exists() {
        eprintln!(
            "Refusing to operate: a legacy plaintext vault exists at {}.",
            legacy_plaintext.display()
        );
        eprintln!("This zkguard build writes only encrypted vaults (AES-256-GCM).");
        eprintln!("Migrate it with:");
        eprintln!(
            "  zkguard key migrate --input {} --output {}",
            legacy_plaintext.display(),
            vault_file.display()
        );
        eprintln!(
            "or delete the file after extracting its keys, then re-run `zkguard key add`."
        );
        std::process::exit(1);
    }

    // Obtain passphrase — new-vault flow confirms; subsequent opens do not.
    let vault_exists = vault_file.exists();
    let passphrase = Zeroizing::new(
        if vault_exists {
            prompt_passphrase("vault passphrase")
        } else {
            prompt_new_passphrase()
        }
        .unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }),
    );

    let mut vault = if vault_exists {
        load_vault_encrypted(&vault_file, passphrase.as_bytes()).unwrap_or_else(|e| {
            eprintln!("Failed to open vault: {}", e);
            eprintln!("(wrong passphrase or corrupted file)");
            std::process::exit(1);
        })
    } else {
        SecretVault::new()
    };

    let mut token_map = if token_map_file.exists() {
        std::fs::read(&token_map_file)
            .ok()
            .and_then(|data| TokenMap::from_bytes(&data).ok())
            .unwrap_or_else(TokenMap::new)
    } else {
        TokenMap::new()
    };

    let params = VaultEncryptionParams::default();

    match action {
        KeyAction::Add { provider } => {
            let key_str = Zeroizing::new(
                rpassword::prompt_password("Enter API key (will not echo): ")
                    .unwrap_or_else(|e| {
                        eprintln!("Failed to read key: {}", e);
                        std::process::exit(1);
                    })
                    .trim()
                    .to_string(),
            );
            if key_str.is_empty() {
                eprintln!("Error: API key must not be empty");
                std::process::exit(1);
            }

            match token_map.register(&mut vault, key_str.as_bytes(), &provider) {
                Ok((dummy_token, _handle)) => {
                    save_vault_encrypted(&vault, &vault_file, passphrase.as_bytes(), &params)
                        .expect("Failed to save encrypted vault");
                    std::fs::write(&token_map_file, token_map.to_bytes())
                        .expect("Failed to save token map");

                    println!();
                    println!("Key registered and encrypted.");
                    println!("  Provider:    {}", provider);
                    println!("  Proxy token: {}", dummy_token);
                    println!();
                    println!("Use this token as your API key in apps:");
                    println!("  x-api-key: {}", dummy_token);
                    println!();
                    println!("Encrypted vault: {}", vault_file.display());
                    println!(
                        "Start proxy with: zkguard proxy --port 8080 --provider {}",
                        provider
                    );
                }
                Err(e) => {
                    eprintln!("Error registering key: {}", e);
                    std::process::exit(1);
                }
            }
        }

        KeyAction::List => {
            let tokens = token_map.list();
            if tokens.is_empty() {
                println!("No keys registered. Use `zkguard key add --provider <name>` to add one.");
            } else {
                println!("Registered proxy tokens ({}):", tokens.len());
                println!();
                for (token, provider) in &tokens {
                    println!("  {} ({})", token, provider);
                }
                println!();
                println!("Encrypted vault: {}", vault_file.display());
                println!("Real keys are NEVER displayed and are stored only inside the AES-256-GCM vault.");
            }
        }

        KeyAction::Remove { provider } => {
            if token_map.remove_by_provider(&mut vault, &provider) {
                save_vault_encrypted(&vault, &vault_file, passphrase.as_bytes(), &params)
                    .expect("Failed to save encrypted vault");
                std::fs::write(&token_map_file, token_map.to_bytes())
                    .expect("Failed to save token map");
                println!("Key for '{}' removed and securely erased.", provider);
            } else {
                eprintln!("No key found for provider '{}'.", provider);
                std::process::exit(1);
            }
        }
    }
}

fn cmd_demo() {
    println!("=== zkguard Demo ===\n");

    // Step 1: Sanitize
    let prompt = format!(
        "Use my Anthropic key {} and AWS key AKIAIOSFODNN7EXAMPLE to call Claude.",
        "sk-ant-api03-".to_owned() + &"A".repeat(93),
    );
    println!("[1] Original prompt ({} chars):", prompt.len());
    println!("    {}...\n", &prompt[..80]);

    let mut guard = ContextSanitizer::new();
    let sanitized = guard.sanitize(&prompt).expect("Sanitize failed");
    println!(
        "[2] Sanitized ({} keys redacted):",
        sanitized.redactions.len()
    );
    println!(
        "    {}...\n",
        &sanitized.content[..80.min(sanitized.content.len())]
    );

    // Step 2: ZK Proof
    let key_bytes = format!("sk-ant-api03-{}", "A".repeat(93));
    let fields = bytes_to_fields(key_bytes.as_bytes());

    let start = Instant::now();
    let prover = StarkProver::new(SimpleAir::fibonacci()).expect("Prover init failed");
    let proof = prover.prove_key_commit(&fields).expect("Proof failed");
    let prove_time = start.elapsed();
    println!(
        "[3] STARK proof generated in {:.1}ms",
        prove_time.as_secs_f64() * 1000.0
    );
    println!(
        "    eval={}, elements={}\n",
        proof.public_values[0], proof.public_values[1]
    );

    // Step 3: Verify
    let start = Instant::now();
    let verifier = prover.get_verifier();
    let valid = verifier.verify_key_commit(&proof).expect("Verify failed");
    let verify_time = start.elapsed();
    println!(
        "[4] Proof verified: {} ({:.1}ms)\n",
        valid,
        verify_time.as_secs_f64() * 1000.0
    );

    // Step 4: Serialization round-trip
    let bin = proof.to_bincode().expect("Serialize failed");
    let restored = StarkProof::from_bincode(&bin).expect("Deserialize failed");
    let still_valid = verifier
        .verify_key_commit(&restored)
        .expect("Verify restored failed");
    println!(
        "[5] Serialization round-trip: {} bytes, still valid: {}\n",
        bin.len(),
        still_valid
    );

    // Step 5: Process tokens
    let llm_output = sanitized.content.clone();
    let processed = guard
        .process_tokens(&llm_output, |vault, handle| {
            vault.with_key(handle, |_key_bytes| Ok("[API_CALL_RESULT]".to_string()))
        })
        .expect("Process failed");
    println!("[6] Token processing:");
    println!(
        "    Keys in output: {}",
        if processed.contains("sk-ant-") {
            "LEAKED!"
        } else {
            "0 (safe)"
        }
    );

    println!("\n=== Demo complete ===");
}
