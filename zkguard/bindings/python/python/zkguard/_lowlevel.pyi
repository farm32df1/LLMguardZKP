"""Type stubs for zkguard native module."""

from typing import List, Tuple, Callable, Optional

VERSION: str

class DetectedKey:
    """Detected API key (value NOT exposed for security)."""
    provider: str
    span_start: int
    span_end: int
    @property
    def span(self) -> Tuple[int, int]: ...

class ContextScanner:
    """Scan text for API keys using regex + entropy analysis."""
    def __init__(self) -> None: ...
    def scan(self, text: str) -> List[DetectedKey]: ...

class SanitizedResult:
    """Result of sanitizing text."""
    content: str
    redaction_count: int
    providers: List[str]

class ZkGuard:
    """Main orchestrator: scan, sanitize, and protect API keys.

    Example:
        >>> guard = ZkGuard()
        >>> result = guard.sanitize("Use key sk-ant-api03-...")
        >>> print(result.content)  # "Use key {{ZKGUARD:...}}"
        >>> output = guard.process_tokens(result.content, lambda t: "[REDACTED]")
    """
    def __init__(self) -> None: ...
    def sanitize(self, text: str) -> SanitizedResult:
        """Scan and redact all API keys in text. Returns SanitizedResult."""
        ...
    def store_key(self, key: bytes) -> str:
        """Store a key manually and return its {{ZKGUARD:...}} token.

        Raises:
            ValueError: If key is empty.
        """
        ...
    def find_tokens(self, text: str) -> List[str]:
        """Find all {{ZKGUARD:...}} tokens in text."""
        ...
    def process_tokens(self, text: str, callable: Callable[[str], str]) -> str:
        """Replace all {{ZKGUARD:...}} tokens using a callable.

        The callable receives the token string (e.g., "{{ZKGUARD:hex}}")
        and should return the replacement string.

        Note: The callable receives the token, NOT the raw key bytes.
        This is intentional — key bytes stay in Rust memory with zeroize protection.
        """
        ...
    def save_encrypted(
        self,
        path: str,
        password: bytes,
        m_cost: int = 65536,
        t_cost: int = 3,
        p_cost: int = 1,
    ) -> int:
        """Save vault to an AES-256-GCM encrypted file.

        Args:
            path: File path to save to.
            password: Encryption password (bytes).
            m_cost: Argon2id memory cost in KiB (default: 65536 = 64 MiB).
            t_cost: Argon2id time cost / iterations (default: 3).
            p_cost: Argon2id parallelism (default: 1).

        Returns:
            Number of keys saved.

        Raises:
            RuntimeError: If password is empty or write fails.
        """
        ...
    @staticmethod
    def load_encrypted(path: str, password: bytes) -> "ZkGuard":
        """Load vault from an AES-256-GCM encrypted file.

        Args:
            path: File path to load from.
            password: Decryption password (bytes).

        Returns:
            New ZkGuard instance with the loaded keys.

        Raises:
            RuntimeError: If password is wrong or file is corrupted.
        """
        ...
    @property
    def vault_size(self) -> int:
        """Number of keys currently in the vault."""
        ...
    @property
    def handle_count(self) -> int:
        """Number of issued token handles."""
        ...

class StarkProof:
    """STARK proof (serializable via bincode or JSON)."""
    def to_bytes(self) -> bytes:
        """Serialize to bincode bytes."""
        ...
    @staticmethod
    def from_bytes(data: bytes) -> "StarkProof":
        """Deserialize from bincode bytes.

        Raises:
            RuntimeError: If data is invalid.
        """
        ...
    def to_json(self) -> str:
        """Serialize to JSON string."""
        ...
    @staticmethod
    def from_json(data: str) -> "StarkProof":
        """Deserialize from JSON string.

        Raises:
            RuntimeError: If data is invalid.
        """
        ...
    @property
    def air_type(self) -> str:
        """Type of AIR circuit (e.g., "KeyCommit", "Fibonacci")."""
        ...
    @property
    def num_rows(self) -> int:
        """Number of rows in the STARK trace."""
        ...
    @property
    def public_values(self) -> List[int]:
        """Public values of the proof (e.g., [eval_final, num_elements])."""
        ...

class StarkProver:
    """Plonky3 STARK prover."""
    def __init__(self) -> None: ...
    def prove_key_commit(self, elements: List[int]) -> StarkProof:
        """Prove knowledge of field elements (key commitment).

        Args:
            elements: List of u64 values representing key bytes.

        Returns:
            StarkProof with air_type="KeyCommit".
        """
        ...
    def prove_fibonacci(self, num_rows: int) -> StarkProof:
        """Prove a Fibonacci computation.

        Args:
            num_rows: Trace size (must be power of 2, >= 4).

        Returns:
            StarkProof with air_type="Fibonacci".
        """
        ...

class StarkVerifier:
    """Plonky3 STARK verifier."""
    def __init__(self) -> None: ...
    def verify(self, proof: StarkProof) -> bool:
        """Verify a STARK proof. Returns True if valid.

        Raises:
            RuntimeError: If proof structure is invalid.
        """
        ...

def poseidon_hash(data: bytes, domain: bytes) -> bytes:
    """Compute Poseidon2 hash with domain separation.

    Args:
        data: Input data bytes.
        domain: Domain separation tag bytes.

    Returns:
        32-byte (256-bit) hash digest.
    """
    ...
