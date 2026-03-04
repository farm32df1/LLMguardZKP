"""zkguard + LangChain integration demo.

Install:
    pip install zkguard langchain-core

This demo shows how ZkGuardCallbackHandler detects API keys
in LLM prompts and outputs.
"""

from uuid import uuid4
from zkguard_langchain import ZkGuardCallbackHandler
from langchain_core.outputs import LLMResult, Generation


ANTHROPIC_KEY = "sk-ant-api03-" + "X" * 93

# ── Setup ────────────────────────────────────────────────────────────────────

print("=== zkguard + LangChain Demo ===\n")

# 1. Monitoring mode (warn only)
print("[1] Monitoring mode (warn only):")
handler = ZkGuardCallbackHandler(log_fn=lambda msg: print(f"    {msg}"))

handler.on_llm_start(
    serialized={},
    prompts=[f"Please use API key {ANTHROPIC_KEY} for authentication"],
    run_id=uuid4(),
)
print(f"    Leaks detected: {handler.leak_count}")
print()

# 2. Strict mode (raise on leak)
print("[2] Strict mode (raise on leak):")
strict_handler = ZkGuardCallbackHandler(raise_on_leak=True)
try:
    strict_handler.on_llm_start(
        serialized={},
        prompts=[f"Key: {ANTHROPIC_KEY}"],
        run_id=uuid4(),
    )
except ValueError as e:
    print(f"    Caught: {e}")
print()

# 3. LLM output scanning
print("[3] Scanning LLM output for echoed keys:")
output_handler = ZkGuardCallbackHandler(log_fn=lambda msg: print(f"    {msg}"))
result = LLMResult(
    generations=[[Generation(text=f"Sure! Your key is {ANTHROPIC_KEY}")]]
)
output_handler.on_llm_end(response=result, run_id=uuid4())
print(f"    Output leaks: {output_handler.leak_count}")
print()

# 4. Clean prompt (no keys)
print("[4] Clean prompt (no keys detected):")
clean_handler = ZkGuardCallbackHandler(log_fn=lambda msg: print(f"    {msg}"))
clean_handler.on_llm_start(
    serialized={},
    prompts=["What is the weather today?"],
    run_id=uuid4(),
)
print(f"    Leaks detected: {clean_handler.leak_count}")
print()

print("=== Demo Complete ===")
