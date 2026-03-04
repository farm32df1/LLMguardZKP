use pyo3::prelude::*;
use pyo3::types::PyBytes;

// ── ContextScanner ──────────────────────────────────────────────────────────

#[pyclass(name = "ContextScanner")]
struct PyContextScanner {
    inner: zkguard::ContextScanner,
}

#[pymethods]
impl PyContextScanner {
    #[new]
    fn new() -> Self {
        Self {
            inner: zkguard::ContextScanner::new(),
        }
    }

    /// Scan text for API keys. Returns list of DetectedKey.
    fn scan(&self, text: &str) -> Vec<PyDetectedKey> {
        self.inner
            .scan(text)
            .into_iter()
            .map(|dk| PyDetectedKey {
                provider: dk.provider.as_str().to_string(),
                span_start: dk.span.0,
                span_end: dk.span.1,
            })
            .collect()
    }
}

// ── DetectedKey ─────────────────────────────────────────────────────────────

/// Detected API key info. Value is NOT exposed (zeroize safety).
#[pyclass(name = "DetectedKey", frozen)]
struct PyDetectedKey {
    #[pyo3(get)]
    provider: String,
    #[pyo3(get)]
    span_start: usize,
    #[pyo3(get)]
    span_end: usize,
}

#[pymethods]
impl PyDetectedKey {
    #[getter]
    fn span(&self) -> (usize, usize) {
        (self.span_start, self.span_end)
    }

    fn __repr__(&self) -> String {
        format!(
            "DetectedKey(provider='{}', span=({}, {}))",
            self.provider, self.span_start, self.span_end
        )
    }
}

// ── SanitizedResult ─────────────────────────────────────────────────────────

#[pyclass(name = "SanitizedResult", frozen)]
struct PySanitizedResult {
    #[pyo3(get)]
    content: String,
    #[pyo3(get)]
    redaction_count: usize,
    #[pyo3(get)]
    providers: Vec<String>,
}

#[pymethods]
impl PySanitizedResult {
    fn __repr__(&self) -> String {
        format!(
            "SanitizedResult(redactions={}, providers={:?})",
            self.redaction_count, self.providers
        )
    }
}

// ── ZkGuard (main orchestrator) ─────────────────────────────────────────────

#[pyclass(name = "ZkGuard")]
struct PyZkGuard {
    inner: zkguard::ContextSanitizer,
}

#[pymethods]
impl PyZkGuard {
    #[new]
    fn new() -> Self {
        Self {
            inner: zkguard::ContextSanitizer::new(),
        }
    }

    /// Scan and redact all API keys in text.
    fn sanitize(&mut self, text: &str) -> PyResult<PySanitizedResult> {
        let result = self
            .inner
            .sanitize(text)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;

        let providers: Vec<String> = result
            .redactions
            .iter()
            .map(|r| r.provider.as_str().to_string())
            .collect();

        Ok(PySanitizedResult {
            content: result.content,
            redaction_count: result.redactions.len(),
            providers,
        })
    }

    /// Store a key manually and return its token string.
    fn store_key(&mut self, key: &[u8]) -> PyResult<String> {
        let handle = self
            .inner
            .vault_mut()
            .store(key)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        Ok(handle.to_token())
    }

    /// Find all {{ZKGUARD:...}} tokens in text.
    fn find_tokens(&self, text: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find("{{ZKGUARD:") {
            let after = &rest[start + "{{ZKGUARD:".len()..];
            if let Some(end) = after.find("}}") {
                let hex = &after[..end];
                tokens.push(format!("{{{{ZKGUARD:{}}}}}", hex));
                rest = &after[end + 2..];
            } else {
                break;
            }
        }
        tokens
    }

    /// Replace all tokens using a Python callable: callable(token) -> str
    fn process_tokens(&self, text: &str, callable: &Bound<'_, PyAny>) -> PyResult<String> {
        let result = self
            .inner
            .process_tokens(text, |_vault, handle| {
                let token = handle.to_token();
                let py_result = callable.call1((token.as_str(),)).map_err(|e| {
                    zkguard::ZKGuardError::VaultError {
                        reason: format!("Python callback error: {}", e),
                    }
                })?;
                py_result
                    .extract::<String>()
                    .map_err(|e| zkguard::ZKGuardError::VaultError {
                        reason: format!("callback must return str: {}", e),
                    })
            })
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;

        Ok(result)
    }

    /// Retrieve raw key bytes for a token. WARNING: key enters Python memory
    /// and is NOT zeroized by Rust after this call. Delete the reference ASAP.
    fn get_key_for_token(&self, _token: &str) -> PyResult<Vec<u8>> {
        // Intentionally not implemented: exposing raw key bytes to Python
        // bypasses zeroize guarantees. Use process_tokens() instead.
        Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "get_key_for_token is disabled for security — use process_tokens() instead",
        ))
    }

    /// Number of keys in vault.
    #[getter]
    fn vault_size(&self) -> usize {
        self.inner.vault().len()
    }

    /// Number of issued handles.
    #[getter]
    fn handle_count(&self) -> usize {
        self.inner.handle_count()
    }

    /// Save vault to an AES-256-GCM encrypted file.
    /// password: bytes, m_cost/t_cost/p_cost: Argon2id params.
    #[cfg(feature = "vault-encrypt")]
    #[pyo3(signature = (path, password, m_cost=65536, t_cost=3, p_cost=1))]
    fn save_encrypted(
        &self,
        path: &str,
        password: &[u8],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> PyResult<usize> {
        let params = zkguard::VaultEncryptionParams {
            m_cost,
            t_cost,
            p_cost,
        };
        zkguard::save_vault_encrypted(self.inner.vault(), path.as_ref(), password, &params)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))
    }

    /// Load vault from an AES-256-GCM encrypted file.
    /// Returns a new ZkGuard with the loaded keys.
    #[cfg(feature = "vault-encrypt")]
    #[staticmethod]
    fn load_encrypted(path: &str, password: &[u8]) -> PyResult<Self> {
        let vault = zkguard::load_vault_encrypted(path.as_ref(), password)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        Ok(Self {
            inner: zkguard::ContextSanitizer::from_vault(vault),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "ZkGuard(vault_size={}, handles={})",
            self.inner.vault().len(),
            self.inner.handle_count()
        )
    }
}

// ── StarkProof ──────────────────────────────────────────────────────────────

#[cfg(feature = "stark")]
#[pyclass(name = "StarkProof")]
struct PyStarkProof {
    inner: zkguard::StarkProof,
}

#[cfg(feature = "stark")]
#[pymethods]
impl PyStarkProof {
    /// Serialize to bincode bytes.
    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let data = self
            .inner
            .to_bincode()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        Ok(PyBytes::new_bound(py, &data))
    }

    /// Deserialize from bincode bytes.
    #[staticmethod]
    fn from_bytes(data: Vec<u8>) -> PyResult<Self> {
        let inner = zkguard::StarkProof::from_bincode(&data)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        Ok(Self { inner })
    }

    /// Serialize to JSON string.
    fn to_json(&self) -> PyResult<String> {
        let bytes = self
            .inner
            .to_json()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        String::from_utf8(bytes)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("UTF-8 error: {}", e)))
    }

    /// Deserialize from JSON string.
    #[staticmethod]
    fn from_json(data: &str) -> PyResult<Self> {
        let inner = zkguard::StarkProof::from_json(data.as_bytes())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        Ok(Self { inner })
    }

    #[getter]
    fn air_type(&self) -> String {
        format!("{:?}", self.inner.air_type)
    }

    #[getter]
    fn num_rows(&self) -> usize {
        self.inner.num_rows
    }

    #[getter]
    fn public_values(&self) -> Vec<u64> {
        self.inner.public_values.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "StarkProof(air_type={:?}, num_rows={}, public_values={:?})",
            self.inner.air_type, self.inner.num_rows, self.inner.public_values
        )
    }
}

// ── StarkProver ─────────────────────────────────────────────────────────────

#[cfg(feature = "stark")]
#[pyclass(name = "StarkProver")]
struct PyStarkProver {
    inner: zkguard::StarkProver,
}

#[cfg(feature = "stark")]
#[pymethods]
impl PyStarkProver {
    #[new]
    fn new() -> PyResult<Self> {
        let air = zkguard::stark::air::SimpleAir::fibonacci();
        let inner = zkguard::StarkProver::new(air)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        Ok(Self { inner })
    }

    /// Prove knowledge of field elements (key commitment).
    fn prove_key_commit(&self, elements: Vec<u64>) -> PyResult<PyStarkProof> {
        let proof = self
            .inner
            .prove_key_commit(&elements)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        Ok(PyStarkProof { inner: proof })
    }

    /// Prove a Fibonacci computation of given size (must be power of 2, >= 4).
    fn prove_fibonacci(&self, num_rows: usize) -> PyResult<PyStarkProof> {
        let proof = self
            .inner
            .prove_fibonacci(num_rows)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        Ok(PyStarkProof { inner: proof })
    }

    fn __repr__(&self) -> String {
        "StarkProver()".to_string()
    }
}

// ── StarkVerifier ───────────────────────────────────────────────────────────

#[cfg(feature = "stark")]
#[pyclass(name = "StarkVerifier")]
struct PyStarkVerifier {
    inner: zkguard::StarkVerifier,
}

#[cfg(feature = "stark")]
#[pymethods]
impl PyStarkVerifier {
    #[new]
    fn new() -> PyResult<Self> {
        let air = zkguard::stark::air::SimpleAir::fibonacci();
        let inner = zkguard::StarkVerifier::new(air)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        Ok(Self { inner })
    }

    /// Verify a STARK proof. Returns True if valid.
    fn verify(&self, proof: &PyStarkProof) -> PyResult<bool> {
        let result = self
            .inner
            .verify_by_type(&proof.inner)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        Ok(result)
    }

    fn __repr__(&self) -> String {
        "StarkVerifier()".to_string()
    }
}

// ── poseidon_hash ───────────────────────────────────────────────────────────

#[pyfunction]
fn poseidon_hash<'py>(py: Python<'py>, data: &[u8], domain: &[u8]) -> Bound<'py, PyBytes> {
    let hash = zkguard::utils::hash::poseidon_hash(data, domain);
    PyBytes::new_bound(py, &hash)
}

// ── Module ──────────────────────────────────────────────────────────────────

#[pymodule]
fn _zkguard(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("VERSION", zkguard::VERSION)?;

    m.add_class::<PyContextScanner>()?;
    m.add_class::<PyDetectedKey>()?;
    m.add_class::<PySanitizedResult>()?;
    m.add_class::<PyZkGuard>()?;
    m.add_function(wrap_pyfunction!(poseidon_hash, m)?)?;

    #[cfg(feature = "stark")]
    {
        m.add_class::<PyStarkProver>()?;
        m.add_class::<PyStarkVerifier>()?;
        m.add_class::<PyStarkProof>()?;
    }

    Ok(())
}
