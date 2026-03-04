"""zkguard - ZK-based credential protection for LLM workflows.

Quick start (one line):
    >>> import zkguard
    >>> safe = zkguard.clean("my prompt with sk-ant-api03-...")
    >>> # Done. API key removed. Safe to send to any LLM.

Full API:
    >>> guard = zkguard.ZkGuard()
    >>> result = guard.sanitize("text with API keys")
    >>> output = guard.process_tokens(result.content, lambda t: "[REDACTED]")
"""

from zkguard._zkguard import (
    ContextScanner,
    DetectedKey,
    SanitizedResult,
    ZkGuard,
    poseidon_hash,
    VERSION,
)

# Easy API — one-liners for everyone
from zkguard.easy import clean, has_keys, scan, safe_prompt, wrap_fn

__all__ = [
    # Easy API (use these first)
    "clean",
    "has_keys",
    "scan",
    "safe_prompt",
    "wrap_fn",
    # Full API (for advanced usage)
    "ContextScanner",
    "DetectedKey",
    "SanitizedResult",
    "ZkGuard",
    "poseidon_hash",
    "VERSION",
]

# STARK classes (only available if built with stark feature)
try:
    from zkguard._zkguard import StarkProver, StarkVerifier, StarkProof
    __all__ += ["StarkProver", "StarkVerifier", "StarkProof"]
except ImportError:
    pass
