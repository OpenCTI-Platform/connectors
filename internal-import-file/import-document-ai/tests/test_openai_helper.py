"""
Unit tests for OpenAIHelper relation extraction and NDJSON parsing (synchronous version).

Purpose:
Validate synchronous OpenAIHelper behavior after async removal:
- NDJSON parsing and normalization
- Relation extraction via patched _call_model_relations()
- Chat completion content handling and span mapping
- Incident mapping
"""

import io
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure `src` directory is importable (consistent with other test files)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import reportimporter.core
from reportimporter.configparser import ConfigParser
from reportimporter.openai import OpenAIHelper

# Silence connector ping loops during tests
mp = pytest.MonkeyPatch()
mp.setattr(
    reportimporter.core.OpenCTIConnectorHelper,
    "start_pinging",
    lambda *a, **k: None,
    raising=False,
)

SYSTEM_PROMPT = "Extract STIX entities."


@pytest.fixture
def dummy_config():
    """Provide a minimal deterministic config for OpenAIHelper testing."""

    class DummyConfig(ConfigParser):
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

    return DummyConfig()


@pytest.fixture
def simple_helper(dummy_config):
    """Return an initialized OpenAIHelper instance for tests."""
    return OpenAIHelper(config=dummy_config)


def test_relations_ndjson_merge(simple_helper):
    """Validate NDJSON per-chunk merge into full relations structure."""
    ndjson = "\n".join(
        [
            '{"id":"h1","type":"observable","label":"Email-Addr.value","value":"admin@example.com","start_offset":10,"end_offset":30}',
            '{"type":"relationship","label":"related-to","from_id":"h1","to_id":"h1"}',
        ]
    )

    with patch.object(simple_helper, "call_openai", return_value=ndjson), patch.object(
        simple_helper,
        "build_hints_and_chunks",
        return_value=[{"text": "abcdef" * 50, "start": 0, "end": 300, "hints": []}],
    ):
        out = simple_helper.openai_extract_relations("dummy")
        spans = (out.get("metadata") or {}).get("span_based_entities") or []
        assert any(
            s.get("label") == "Email-Addr.value" for s in spans
        ), f"Expected Email-Addr span, got: {spans}"


def test_parse_ndjson_any_basic(simple_helper):
    """Ensure _parse_ndjson_any() correctly parses valid NDJSON lines."""
    ndjson = "\n".join(
        [
            '{"label":"Malware.name","value":"Emotet","type":"entity"}',
            '{"type":"relationship","label":"related-to","from_id":"a","to_id":"b"}',
        ]
    )
    results = simple_helper._parse_ndjson_any(ndjson)
    assert any(
        obj.get("label") == "Malware.name" for obj in results
    ), "Missing Malware.name entity"
    assert any(
        obj.get("type") == "relationship" for obj in results
    ), "Missing relationship entry"


def test_parse_ndjson_any_with_code_fence(simple_helper):
    """Handle NDJSON input wrapped in Markdown code fences."""
    ndjson = """
    ```json
    {"label": "Malware.name", "value": "Emotet", "type": "entity"}
    ```
    """
    results = simple_helper._parse_ndjson_any(ndjson)
    assert len(results) == 1, f"Expected single object, got {len(results)}"


def test_call_openai_success(simple_helper):
    """Validate that chat completion returns content correctly."""
    fake_content = '{"category": "malware", "match": "Emotet"}\n'
    fake_completion = MagicMock()
    fake_completion.choices = [MagicMock(message=MagicMock(content=fake_content))]

    with patch.object(
        simple_helper.client.chat.completions, "create", return_value=fake_completion
    ):
        result = simple_helper.call_openai(
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": "Test"},
            ],
            chunk_index=1,
        )
        assert fake_content in result, "Chat completion content missing from result"


def test_process_chunk_and_extract_flow(simple_helper):
    """Test full chunk processing and relation extraction end-to-end."""
    fake_content = '{"type": "entity", "category": "malware", "match": "Emotet"}\n'
    fake_completion = MagicMock()
    fake_completion.choices = [MagicMock(message=MagicMock(content=fake_content))]

    with patch.object(
        simple_helper.client.chat.completions, "create", return_value=fake_completion
    ), patch.object(
        simple_helper,
        "_call_model_relations",
        return_value={
            "metadata": {
                "span_based_entities": [
                    {
                        "id": "span-1",
                        "text": "Emotet",
                        "label": "Malware.name",
                        "type": "entity",
                    }
                ]
            },
            "relations": [],
        },
    ), patch.object(
        simple_helper,
        "build_hints_and_chunks",
        return_value=[{"text": "abcdef" * 50, "start": 0, "end": 300, "hints": []}],
    ):
        results = simple_helper.openai_extract_relations("testdata")
        assert isinstance(
            results, dict
        ), "Expected dict output from openai_extract_relations"
        spans = (results.get("metadata") or {}).get("span_based_entities") or []
        assert isinstance(spans, list), "Expected list of span entities"

        fake_file = io.BytesIO(b"dummy data")
        results = simple_helper.openai_extract_relations(fake_file)
        assert isinstance(results, dict), "Expected dict output for file input"


def test_incident_mapper_creates_incident(simple_helper):
    """Confirm Incident entities are mapped properly from NDJSON."""
    ndjson = '{"type":"entity","category":"Incident","match":"SolarWinds breach"}\n'
    with patch.object(simple_helper, "call_openai", return_value=ndjson), patch.object(
        simple_helper,
        "build_hints_and_chunks",
        return_value=[{"text": "dummy", "start": 0, "end": 5, "hints": []}],
    ):
        out = simple_helper.openai_extract_relations("dummy")
        spans = (out.get("metadata") or {}).get("span_based_entities") or []
        assert any(
            s.get("label") == "Incident" for s in spans
        ), f"Expected Incident label in spans, got {spans}"
