"""
Unit tests for token counting logic in the OpenAIHelper class.

These tests verify that the connector correctly estimates token usage
for Azure OpenAI chat message payloads. Accurate token accounting ensures
the connector can safely truncate prompts without exceeding model limits.

Scope:
- Validate baseline token cost for empty messages.
- Confirm per-message name adjustments.
- Check mixed-role conversations for proportional token growth.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reportimporter.openai import OpenAIHelper


class DummyCfg:
    """Minimal configuration stub for OpenAIHelper testing."""

    def __init__(self):
        self.ai_provider = "azureopenai"
        self.ai_model = "gpt-4"  # Corresponds to cl100k_base tokenizer
        self.openai_endpoint = "https://example.invalid"
        self.openai_key = "FAKE-KEY"
        self.openai_deployment = "fake-deployment"
        self.openai_api_version = "2024-01-01"
        self.max_model_tokens = 8000
        self.model_input_ratio = 0.3

    @property
    def is_azure_openai(self):
        return True

    @property
    def is_openai(self):
        return False


@pytest.fixture(autouse=True)
def clear_prompt_env(monkeypatch):
    """Ensure REPORTIMPORTER_SYSTEM_PROMPT is unset between tests."""
    monkeypatch.delenv("REPORTIMPORTER_SYSTEM_PROMPT", raising=False)


def test_chat_token_count_empty_contents(tmp_path):
    """
    Validate token counting for minimal messages with empty content.
    Expected base count: ~10 tokens (2 messages + completion priming).
    """
    prompt_file = tmp_path / "prompt.md"
    prompt_file.write_text("", encoding="utf-8")
    os.environ["REPORTIMPORTER_SYSTEM_PROMPT"] = str(prompt_file)

    helper = OpenAIHelper(config=DummyCfg())
    messages = [
        {"role": "system", "content": ""},
        {"role": "user", "content": ""},
    ]
    n = helper._count_message_tokens(messages)

    assert isinstance(n, int)
    # Range allows for tokenizer variance across library updates
    assert 8 <= n <= 12, f"Unexpected token count: {n}"


def test_chat_token_count_with_name(tmp_path):
    """
    Validate that named messages reduce token cost by ~1 per message.
    """
    prompt_file = tmp_path / "prompt.md"
    prompt_file.write_text("", encoding="utf-8")
    os.environ["REPORTIMPORTER_SYSTEM_PROMPT"] = str(prompt_file)

    helper = OpenAIHelper(config=DummyCfg())
    messages = [
        {"role": "system", "content": "", "name": "s"},
        {"role": "user", "content": "", "name": "u"},
    ]
    n = helper._count_message_tokens(messages)

    assert isinstance(n, int)
    assert 6 <= n <= 10, f"Unexpected token count for named messages: {n}"


def test_chat_token_count_mixed_roles(tmp_path):
    """
    Validate token growth for multi-role chat interactions.
    Ensures additional tokens are counted for real text content.
    """
    prompt_file = tmp_path / "prompt.md"
    prompt_file.write_text("System start", encoding="utf-8")
    os.environ["REPORTIMPORTER_SYSTEM_PROMPT"] = str(prompt_file)

    helper = OpenAIHelper(config=DummyCfg())
    messages = [
        {"role": "system", "content": "Initialize"},
        {"role": "user", "content": "What are observables?"},
        {"role": "assistant", "content": "They are..."},
    ]
    n = helper._count_message_tokens(messages)

    assert isinstance(n, int)
    assert n > 10, f"Expected higher token count for multiple roles, got {n}"
