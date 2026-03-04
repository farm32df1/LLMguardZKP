"""zkguard for everyone — no setup, one line.

This is for people who just want to protect their API keys
when using LLMs. No Rust knowledge needed, no complex setup.

Install:
    cd bindings/python
    pip install maturin
    maturin develop
"""

import zkguard

# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 1: You're about to paste code into ChatGPT/Claude
# ═══════════════════════════════════════════════════════════════════════════════

code = """
import requests

def call_api():
    headers = {"x-api-key": "sk-ant-api03-""" + "A" * 93 + """"}
    response = requests.get("https://api.anthropic.com/v1/messages", headers=headers)
    return response.json()
"""

# One line. That's it.
safe_code = zkguard.clean(code)
print("=== Your code, safe to paste into any LLM ===")
print(safe_code)
print()

# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 2: Quick check — does my text have keys?
# ═══════════════════════════════════════════════════════════════════════════════

print("=== Quick checks ===")
print(f"Has keys: {zkguard.has_keys(safe_code)}")          # False (already cleaned)
print(f"Has keys: {zkguard.has_keys('AKIAIOSFODNN7EXAMPLE')}")  # True
print()

# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 3: What keys did you find?
# ═══════════════════════════════════════════════════════════════════════════════

text = "Use sk-ant-api03-" + "B" * 93 + " and AKIAIOSFODNN7EXAMPLE"
found = zkguard.scan(text)
print("=== Found keys ===")
for key in found:
    print(f"  {key['provider']} at position {key['position']}")
print()

# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 4: Protect your OpenAI/Anthropic calls automatically
# ═══════════════════════════════════════════════════════════════════════════════

def fake_openai_call(messages=None):
    """Pretend this is openai.chat.completions.create()"""
    print(f"  [LLM received]: {messages[0]['content'][:60]}...")
    return "I can help with that API error."

# Wrap it — now all calls are auto-protected
safe_call = zkguard.wrap_fn(fake_openai_call)

print("=== Auto-protected LLM call ===")
api_key = "sk-ant-api03-" + "C" * 93
safe_call(messages=[
    {"role": "user", "content": f"Debug this: my key is {api_key} and it returns 403"},
])
print("  (The LLM never saw your real key)")
print()

# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 5: Get detailed report
# ═══════════════════════════════════════════════════════════════════════════════

report = zkguard.safe_prompt(f"Use {api_key} to call the API")
print("=== Detailed report ===")
print(f"  Clean text: {report['text']}")
print(f"  Keys found: {report['found']}")
print(f"  Providers:  {report['providers']}")
