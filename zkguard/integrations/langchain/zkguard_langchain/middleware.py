"""LangChain agent middleware for automatic API key protection.

Requires LangChain >= 0.3 with agent middleware support.
Automatically scans and redacts API keys in prompts before
they reach the LLM.

Usage:
    from zkguard_langchain import ZkGuardMiddleware

    agent = create_react_agent(
        model=model,
        tools=tools,
        middleware=[ZkGuardMiddleware()],
    )
"""

from typing import Any, Optional

import zkguard

try:
    from langchain.agents.middleware import AgentMiddleware
except ImportError:
    raise ImportError(
        "LangChain agent middleware requires langchain >= 0.3. "
        "Install with: pip install langchain>=0.3"
    )


class ZkGuardMiddleware(AgentMiddleware):
    """Scans and redacts API keys in prompts before they reach the LLM.

    Unlike the callback handler (monitoring-only), this middleware
    actively modifies prompts to remove detected API keys.

    Args:
        log_redactions: If True, prints redaction details.
        log_fn: Optional custom logging function.

    Example:
        >>> from zkguard_langchain import ZkGuardMiddleware
        >>> middleware = ZkGuardMiddleware(log_redactions=True)
        >>> # Use with LangChain agent:
        >>> agent = create_react_agent(model=llm, tools=[], middleware=[middleware])
    """

    def __init__(
        self,
        log_redactions: bool = False,
        log_fn: Optional[Any] = None,
    ):
        super().__init__()
        self._guard = zkguard.ZkGuard()
        self._log_redactions = log_redactions
        self._log_fn = log_fn or print
        self._total_redactions = 0

    def before_model(self, state: dict, runtime: Any = None) -> Optional[dict]:
        """Scan and redact API keys in messages before sending to model."""
        messages = state.get("messages", [])
        if not messages:
            return None

        modified = False
        new_messages = list(messages)

        for i, msg in enumerate(new_messages):
            content = getattr(msg, "content", None)
            if not isinstance(content, str):
                continue

            result = self._guard.sanitize(content)
            if result.redaction_count == 0:
                continue

            modified = True
            self._total_redactions += result.redaction_count

            if self._log_redactions:
                providers = ", ".join(result.providers)
                self._log_fn(
                    f"[zkguard] Redacted {result.redaction_count} key(s) "
                    f"in message {i}: {providers}"
                )

            # Create a new message with sanitized content
            try:
                from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
                if type(msg).__name__ == "HumanMessage":
                    new_messages[i] = HumanMessage(content=result.content)
                elif type(msg).__name__ == "SystemMessage":
                    new_messages[i] = SystemMessage(content=result.content)
                elif type(msg).__name__ == "AIMessage":
                    new_messages[i] = AIMessage(content=result.content)
                else:
                    # Unknown message type — replace content directly if possible
                    if hasattr(msg, "content"):
                        msg.content = result.content
            except ImportError:
                if hasattr(msg, "content"):
                    msg.content = result.content

        if modified:
            return {"messages": new_messages}
        return None

    @property
    def guard(self) -> zkguard.ZkGuard:
        """Access the underlying ZkGuard instance."""
        return self._guard

    @property
    def total_redactions(self) -> int:
        """Total number of keys redacted across all calls."""
        return self._total_redactions
