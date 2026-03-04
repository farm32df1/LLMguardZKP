"""zkguard easy API — one-liner protection for everyone.

No setup, no config, no Rust knowledge required.

    import zkguard
    safe = zkguard.clean("my prompt with sk-ant-api03-...")
    print(safe)  # "my prompt with [PROTECTED]"

That's it. Your API key never reaches the LLM.
"""

from typing import List, Optional, Callable, Any
from zkguard._zkguard import ContextScanner, ZkGuard

# Module-level singleton — created once, reused
_scanner: Optional[ContextScanner] = None
_guard: Optional[ZkGuard] = None


def _get_scanner() -> ContextScanner:
    global _scanner
    if _scanner is None:
        _scanner = ContextScanner()
    return _scanner


def _get_guard() -> ZkGuard:
    global _guard
    if _guard is None:
        _guard = ZkGuard()
    return _guard


def clean(text: str, placeholder: str = "[PROTECTED]") -> str:
    """Remove all API keys from text. Returns clean text.

    This is the simplest way to use zkguard. One line, done.

    Args:
        text: Any text that might contain API keys.
        placeholder: What to replace keys with (default: "[PROTECTED]").

    Returns:
        Text with all API keys replaced by the placeholder.

    Example:
        >>> import zkguard
        >>> safe = zkguard.clean("Use key sk-ant-api03-AAAA...AAAA here")
        >>> print(safe)
        "Use key [PROTECTED] here"
        >>> # Now safe to send to any LLM
    """
    scanner = _get_scanner()
    keys = scanner.scan(text)
    if not keys:
        return text

    # Sort by position (reverse) so replacements don't shift indices
    sorted_keys = sorted(keys, key=lambda k: k.span[0], reverse=True)
    result = text
    for key in sorted_keys:
        start, end = key.span
        result = result[:start] + placeholder + result[end:]
    return result


def has_keys(text: str) -> bool:
    """Check if text contains any API keys.

    Args:
        text: Text to check.

    Returns:
        True if API keys were found.

    Example:
        >>> import zkguard
        >>> zkguard.has_keys("safe text")
        False
        >>> zkguard.has_keys("key=sk-ant-api03-AAAA...")
        True
    """
    scanner = _get_scanner()
    return len(scanner.scan(text)) > 0


def scan(text: str) -> List[dict]:
    """Scan text for API keys. Returns simple dicts.

    Args:
        text: Text to scan.

    Returns:
        List of dicts with 'provider' and 'position' keys.

    Example:
        >>> import zkguard
        >>> keys = zkguard.scan("Use AKIAIOSFODNN7EXAMPLE here")
        >>> print(keys)
        [{'provider': 'AWS Access Key', 'position': (4, 24)}]
    """
    scanner = _get_scanner()
    return [
        {"provider": k.provider, "position": k.span}
        for k in scanner.scan(text)
    ]


def safe_prompt(text: str) -> dict:
    """Sanitize text and return detailed info.

    Like clean(), but gives you more information about what was found.

    Args:
        text: Text that might contain API keys.

    Returns:
        Dict with 'text' (cleaned), 'found' (count), 'providers' (list).

    Example:
        >>> import zkguard
        >>> result = zkguard.safe_prompt("Use sk-ant-api03-... and AKIAIOSFODNN7EXAMPLE")
        >>> print(result['text'])     # cleaned text
        >>> print(result['found'])    # 2
        >>> print(result['providers'])  # ['Anthropic', 'AWS Access Key']
    """
    guard = _get_guard()
    result = guard.sanitize(text)

    # Also clean the tokens for simple usage
    output = guard.process_tokens(result.content, lambda _: "[PROTECTED]")

    return {
        "text": output,
        "found": result.redaction_count,
        "providers": list(result.providers),
    }


def wrap_fn(fn: Callable, placeholder: str = "[PROTECTED]") -> Callable:
    """Wrap any function to auto-clean its first string argument.

    Use this to protect any LLM call function.

    Args:
        fn: Function whose first string argument should be cleaned.
        placeholder: What to replace keys with.

    Returns:
        Wrapped function that auto-cleans input.

    Example:
        >>> import zkguard
        >>> import openai
        >>>
        >>> # Wrap your LLM call
        >>> safe_complete = zkguard.wrap_fn(openai.chat.completions.create)
        >>>
        >>> # Or wrap any function
        >>> def my_llm(prompt):
        ...     return call_api(prompt)
        >>> safe_llm = zkguard.wrap_fn(my_llm)
        >>> safe_llm("Use key sk-ant-api03-...")  # key auto-removed
    """
    def wrapper(*args, **kwargs):
        new_args = list(args)
        # Clean first string positional arg
        for i, arg in enumerate(new_args):
            if isinstance(arg, str):
                new_args[i] = clean(arg, placeholder)
                break

        # Clean string values in kwargs
        new_kwargs = {}
        for k, v in kwargs.items():
            if isinstance(v, str):
                new_kwargs[k] = clean(v, placeholder)
            elif isinstance(v, list):
                # Handle messages=[{...}] pattern (OpenAI/Anthropic style)
                new_kwargs[k] = _clean_messages(v, placeholder)
            else:
                new_kwargs[k] = v

        return fn(*new_args, **new_kwargs)
    wrapper.__name__ = getattr(fn, "__name__", "wrapped")
    wrapper.__doc__ = f"[zkguard-protected] {getattr(fn, '__doc__', '')}"
    return wrapper


def _clean_messages(messages: list, placeholder: str) -> list:
    """Clean API keys from a list of message dicts (OpenAI/Anthropic format)."""
    cleaned = []
    for msg in messages:
        if isinstance(msg, dict) and "content" in msg:
            content = msg["content"]
            if isinstance(content, str):
                cleaned.append({**msg, "content": clean(content, placeholder)})
            else:
                cleaned.append(msg)
        else:
            cleaned.append(msg)
    return cleaned
