"""
Unit tests for LLMHelper relation extraction and NDJSON parsing (synchronous version).

Purpose:
Validate synchronous LLMHelper behavior after async removal:
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
from reportimporter.llmhelper import LLMHelper, TokenEncoder


@pytest.fixture(autouse=True)
def disable_connector_ping_loop(monkeypatch):
    """Silence connector ping loops without leaking the patch past each test."""
    monkeypatch.setattr(
        reportimporter.core.OpenCTIConnectorHelper,
        "start_pinging",
        lambda *a, **k: None,
        raising=False,
    )


SYSTEM_PROMPT = "Extract STIX entities."


@pytest.fixture
def dummy_config():
    """Provide a minimal deterministic config for LLMHelper testing."""

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
    """Return an initialized LLMHelper instance for tests."""
    return LLMHelper(config=dummy_config)


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
        return_value=[
            {
                "text": "abcdef" * 50,
                "start": 0,
                "end": 300,
                "hints": [{"id": "dummy", "label": "dummy"}],
            }
        ],
    ):
        out = simple_helper.openai_extract_relations("dummy")
        spans = (out.get("metadata") or {}).get("span_based_entities") or []
        assert any(
            s.get("label") == "Email-Addr.value" for s in spans
        ), f"Expected Email-Addr span, got: {spans}"


def test_lowercase_observable_label_is_canonicalized(simple_helper):
    ndjson = '{"label":"domain-name.value","value":"Example.COM"}'

    with patch.object(simple_helper, "call_openai", return_value=ndjson):
        out = simple_helper._call_model_relations(
            {"text": "Example.COM", "start": 0, "end": 11, "hints": []},
            0,
        )

    spans = (out.get("metadata") or {}).get("span_based_entities") or []
    assert spans == [
        {
            "id": "llm::observable::domain-name.value::example.com",
            "text": "Example.COM",
            "label": "Domain-Name.value",
            "type": "observable",
        }
    ]


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
        return_value=[
            {
                "text": "abcdef" * 50,
                "start": 0,
                "end": 300,
                "hints": [{"id": "dummy", "label": "dummy"}],
            }
        ],
    ):
        out = simple_helper.openai_extract_relations("dummy")
        spans = (out.get("metadata") or {}).get("span_based_entities") or []
        assert any(
            s.get("label") == "Incident" for s in spans
        ), f"Expected Incident label in spans, got {spans}"


def test_relation_guidance_balances_labels_not_uses_only():
    """Guidance should include multiple relation labels when mapping supports them."""
    helper = LLMHelper.__new__(LLMHelper)
    helper.allowed_relations = {
        ("INTRUSION-SET", "ATTACK-PATTERN"): {"USES"},
        ("INTRUSION-SET", "ORGANIZATION"): {"TARGETS"},
        ("CAMPAIGN", "THREAT-ACTOR-GROUP"): {"ATTRIBUTED-TO"},
        ("INFRASTRUCTURE", "COUNTRY"): {"LOCATED-AT"},
    }

    guidance = helper._build_relation_guidance()

    assert "Active OpenCTI relation labels:" in guidance
    assert "USES" in guidance
    assert "TARGETS" in guidance
    assert "ATTRIBUTED-TO" in guidance


def test_token_encoder_fallback_paths(monkeypatch):
    def _raise(*args, **kwargs):
        raise LookupError("no tokenizer")

    monkeypatch.setattr("reportimporter.llmhelper.tiktoken.encoding_for_model", _raise)
    monkeypatch.setattr("reportimporter.llmhelper.tiktoken.get_encoding", _raise)

    encoder = TokenEncoder("unknown-model", chars_per_token=2)

    assert encoder.encode("") == []
    assert encoder.encode("abcd") == ["ab", "cd"]
    assert encoder.decode(["ab", "cd"]) == "abcd"
    assert encoder.count("abc") == 2
    assert encoder.is_tiktoken() is False
    assert encoder.get_encoder() is None


def test_prompt_loading_cache_and_fallback(monkeypatch, tmp_path):
    prompt_path = tmp_path / "prompt.md"
    prompt_path.write_text("hello prompt", encoding="utf-8")
    json_list_path = tmp_path / "prompt-list.json"
    json_list_path.write_text('{"content": ["one", "two"]}', encoding="utf-8")
    json_string_path = tmp_path / "prompt-string.json"
    json_string_path.write_text('"single"', encoding="utf-8")
    invalid_path = tmp_path / "prompt-invalid.json"
    invalid_path.write_text('{"unexpected": true}', encoding="utf-8")

    assert LLMHelper._load_prompt_from_disk(json_list_path) == "one\ntwo"
    assert LLMHelper._load_prompt_from_disk(json_string_path) == "single"
    with pytest.raises(ValueError):
        LLMHelper._load_prompt_from_disk(invalid_path)
    with pytest.raises(FileNotFoundError):
        LLMHelper._load_prompt_from_disk(tmp_path / "missing.md")

    assert LLMHelper._resolve_prompt_path(str(prompt_path)) == prompt_path
    relative_path = LLMHelper._resolve_prompt_path("relative.md")
    assert relative_path == Path.cwd() / "relative.md"

    LLMHelper._SYSTEM_PROMPT = None
    LLMHelper._PROMPT_CACHE.clear()
    assert LLMHelper._ensure_system_prompt_loaded(str(prompt_path)) == "hello prompt"

    LLMHelper._SYSTEM_PROMPT = None
    assert LLMHelper._ensure_system_prompt_loaded(str(prompt_path)) == "hello prompt"

    LLMHelper._SYSTEM_PROMPT = None
    LLMHelper._PROMPT_CACHE.clear()
    fallback = LLMHelper._ensure_system_prompt_loaded(str(tmp_path / "missing.md"))
    assert "cyber-threat intelligence extractor" in fallback
