"""LangChain callback handler for API key leak detection.

Works with all LangChain versions that support BaseCallbackHandler.
This is a monitoring-only handler: it detects and warns/raises when
API keys appear in LLM prompts or outputs.

Usage:
    from zkguard_langchain import ZkGuardCallbackHandler

    llm = ChatAnthropic(
        model="claude-sonnet-4-20250514",
        callbacks=[ZkGuardCallbackHandler(raise_on_leak=True)]
    )
"""

from typing import Any, Dict, List, Optional, Union
from uuid import UUID

import zkguard

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
except ImportError:
    raise ImportError(
        "langchain-core is required. Install with: pip install langchain-core"
    )


class ZkGuardCallbackHandler(BaseCallbackHandler):
    """Scans LLM inputs/outputs for leaked API keys.

    This handler monitors prompts sent to LLMs and responses received,
    warning or raising an error when API keys are detected.

    Args:
        raise_on_leak: If True, raises ValueError when a key is detected.
            If False (default), prints a warning.
        log_fn: Optional custom logging function. Called with warning message.

    Attributes:
        detected_keys: List of all detected keys (provider + span info).
        leak_count: Total number of key leaks detected.
    """

    def __init__(
        self,
        raise_on_leak: bool = False,
        log_fn: Optional[Any] = None,
    ):
        super().__init__()
        self._scanner = zkguard.ContextScanner()
        self._raise_on_leak = raise_on_leak
        self._log_fn = log_fn or print
        self.detected_keys: List[Dict[str, Any]] = []
        self.leak_count: int = 0

    def _check_text(self, text: str, source: str) -> None:
        """Scan text for API keys and handle detection."""
        keys = self._scanner.scan(text)
        if not keys:
            return

        self.leak_count += len(keys)
        for key in keys:
            self.detected_keys.append({
                "provider": key.provider,
                "span": key.span,
                "source": source,
            })

        providers = ", ".join(k.provider for k in keys)
        msg = f"[zkguard] WARNING: {len(keys)} API key(s) detected in {source} ({providers})"

        if self._raise_on_leak:
            raise ValueError(msg)
        self._log_fn(msg)

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """Scan prompts before they are sent to the LLM."""
        for i, prompt in enumerate(prompts):
            self._check_text(prompt, f"LLM input (prompt {i})")

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[Any]],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """Scan chat messages before they are sent to the LLM."""
        for i, msg_list in enumerate(messages):
            for j, msg in enumerate(msg_list):
                content = getattr(msg, "content", "")
                if isinstance(content, str):
                    self._check_text(content, f"chat message [{i}][{j}]")

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """Scan LLM output for echoed API keys."""
        for i, gen_list in enumerate(response.generations):
            for j, gen in enumerate(gen_list):
                self._check_text(gen.text, f"LLM output [{i}][{j}]")

    def reset(self) -> None:
        """Clear detected keys and leak count."""
        self.detected_keys.clear()
        self.leak_count = 0
