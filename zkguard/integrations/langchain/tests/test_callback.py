"""Tests for ZkGuardCallbackHandler."""

import pytest
from uuid import uuid4
from unittest.mock import MagicMock

import zkguard


# Skip all tests if langchain-core not installed
langchain_core = pytest.importorskip("langchain_core")

from langchain_core.outputs import LLMResult, Generation
from zkguard_langchain import ZkGuardCallbackHandler


ANTHROPIC_KEY = "sk-ant-api03-" + "A" * 93
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


class TestCallbackDetection:
    def test_detects_key_in_prompt(self):
        handler = ZkGuardCallbackHandler()
        handler.on_llm_start(
            serialized={},
            prompts=[f"Use key {ANTHROPIC_KEY} here"],
            run_id=uuid4(),
        )
        assert handler.leak_count == 1
        assert handler.detected_keys[0]["provider"] == "Anthropic"
        assert handler.detected_keys[0]["source"] == "LLM input (prompt 0)"

    def test_detects_multiple_keys(self):
        handler = ZkGuardCallbackHandler()
        handler.on_llm_start(
            serialized={},
            prompts=[f"Key1: {ANTHROPIC_KEY} Key2: {AWS_KEY}"],
            run_id=uuid4(),
        )
        assert handler.leak_count == 2
        providers = {k["provider"] for k in handler.detected_keys}
        assert "Anthropic" in providers
        assert "AWS Access Key" in providers

    def test_no_false_positive(self):
        handler = ZkGuardCallbackHandler()
        handler.on_llm_start(
            serialized={},
            prompts=["Hello, world! No secrets here."],
            run_id=uuid4(),
        )
        assert handler.leak_count == 0

    def test_raise_on_leak(self):
        handler = ZkGuardCallbackHandler(raise_on_leak=True)
        with pytest.raises(ValueError, match="API key"):
            handler.on_llm_start(
                serialized={},
                prompts=[f"Key: {ANTHROPIC_KEY}"],
                run_id=uuid4(),
            )

    def test_custom_log_fn(self):
        logs = []
        handler = ZkGuardCallbackHandler(log_fn=logs.append)
        handler.on_llm_start(
            serialized={},
            prompts=[f"Key: {AWS_KEY}"],
            run_id=uuid4(),
        )
        assert len(logs) == 1
        assert "AWS Access Key" in logs[0]

    def test_detects_key_in_llm_output(self):
        handler = ZkGuardCallbackHandler()
        result = LLMResult(
            generations=[[Generation(text=f"Here is your key: {ANTHROPIC_KEY}")]]
        )
        handler.on_llm_end(response=result, run_id=uuid4())
        assert handler.leak_count == 1
        assert handler.detected_keys[0]["source"] == "LLM output [0][0]"

    def test_reset(self):
        handler = ZkGuardCallbackHandler()
        handler.on_llm_start(
            serialized={},
            prompts=[f"Key: {AWS_KEY}"],
            run_id=uuid4(),
        )
        assert handler.leak_count == 1
        handler.reset()
        assert handler.leak_count == 0
        assert len(handler.detected_keys) == 0

    def test_chat_model_start(self):
        handler = ZkGuardCallbackHandler()
        msg = MagicMock()
        msg.content = f"Use {ANTHROPIC_KEY}"
        handler.on_chat_model_start(
            serialized={},
            messages=[[msg]],
            run_id=uuid4(),
        )
        assert handler.leak_count == 1
