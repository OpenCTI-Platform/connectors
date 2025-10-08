"""
Unit tests for OpenAIHelper relation extraction logic
in reportimporter.openai.

Purpose:
Validate that OpenAIHelper.openai_extract_relations() integrates correctly
with the internal _call_model_relations() routine, merges spans properly,
and returns a well-structured dictionary.

Scope:
- Verify basic span-based extraction structure.
- Confirm event loop integration does not raise.
- Ensure expected entity and relation schema in output.
"""

import sys
from pathlib import Path
from unittest.mock import patch

# Ensure the `src` directory is importable (consistent with other test files)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reportimporter.configparser import ConfigParser
from reportimporter.openai import OpenAIHelper


class DummyConfig(ConfigParser):
    """Minimal configuration stub for OpenAIHelper testing."""

    def __init__(self):
        self._config = {}
        self.ai_provider = "azureopenai"
        self.ai_model = "gpt-4o"
        self.openai_endpoint = "https://fake-endpoint"
        self.openai_key = "test-key"
        self.openai_deployment = "fake-deployment"
        self.openai_api_version = "2024-01-01"
        self.max_model_tokens = 12000
        self.input_token_limit = 100
        self.completion_token_limit = 50
        self.create_indicator = False
        self.web_service_url = "https://fake"
        self.pdf_ocr_enabled = True
        self.licence_key_base64 = None
        self.model_input_ratio = 0.3

    @property
    def is_azure_openai(self):
        return True

    @property
    def is_openai(self):
        return False


def _run_extract(helper: OpenAIHelper, text: str) -> dict:
    """
    Patch _call_model_relations() to return a minimal valid structure,
    simulating a successful model response.
    """
    fake_response = {
        "metadata": {
            "span_based_entities": [
                {
                    "id": "t=ipv4-addr;h=abc123",
                    "text": "203.0.113.7",
                    "label": "IPv4-Addr",
                    "type": "IPv4-Addr.value",
                }
            ]
        },
        "relations": [
            {
                "type": "related-to",
                "from_id": "t=ipv4-addr;h=abc123",
                "to_id": "t=ipv4-addr;h=abc123",
            }
        ],
    }
    with patch.object(
        OpenAIHelper, "_call_model_relations", return_value=fake_response
    ):
        return helper.openai_extract_relations(text)


def test_openai_extract_relations_merges_spans_event_loop():
    """
    Ensure openai_extract_relations() produces a valid structured output
    and merges span data without raising exceptions.
    """
    helper = OpenAIHelper(config=DummyConfig())
    text = "Sample with 203.0.113.7 and http://example.com/."

    out = _run_extract(helper, text)

    assert isinstance(out, dict), f"Expected dict output, got {type(out)}"
    spans = (out.get("metadata") or {}).get("span_based_entities") or []

    assert spans, f"Expected spans in output, got none (out={out})"
    assert any(
        s.get("type") == "IPv4-Addr.value" for s in spans
    ), f"Expected IPv4-Addr.value span, got: {[s.get('type') for s in spans]}"
