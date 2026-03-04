"""zkguard-langchain: LangChain integration for ZK-based API key protection."""

from zkguard_langchain.callback import ZkGuardCallbackHandler

__all__ = ["ZkGuardCallbackHandler"]

# Middleware requires LangChain >= 0.3 with agent middleware support
try:
    from zkguard_langchain.middleware import ZkGuardMiddleware
    __all__.append("ZkGuardMiddleware")
except ImportError:
    ZkGuardMiddleware = None  # type: ignore
