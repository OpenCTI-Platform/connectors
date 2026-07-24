"""
Unit tests for Ollama provider integration in LLMHelper.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reportimporter.llmhelper import LLMHelper


class DummyCfg:
    def __init__(self):
        self.ai_provider = "ollama"
        self.ai_model = "llama3.1:8b"
        self.ollama_host = "http://localhost:11434"
        self.ollama_pull_on_start = True
        self.manual_context_window = None
        self.max_model_tokens = None
        self.model_input_ratio = 0.3

    @property
    def is_azure_openai(self):
        return False

    @property
    def is_openai(self):
        return False

    @property
    def is_ollama(self):
        return True


def test_ollama_pull_precedes_model_info(monkeypatch, tmp_path):
    prompt_path = tmp_path / "prompt.md"
    prompt_path.write_text("", encoding="utf-8")
    os.environ["REPORTIMPORTER_SYSTEM_PROMPT"] = str(prompt_path)

    calls = []

    class FakeOllamaClient:
        def __init__(self, host):
            self.host = host

        def pull(self, model):
            calls.append(("pull", model))

        def show(self, model):
            calls.append(("show", model))
            return {"model_info": {"context_length": 16384}}

        def chat(self, model, messages, options):
            return {"done": True, "done_reason": "stop", "message": {"content": "{}"}}

    monkeypatch.setattr("reportimporter.llmhelper.OllamaClient", FakeOllamaClient)

    helper = LLMHelper(config=DummyCfg())

    assert calls[:2] == [("pull", "llama3.1:8b"), ("show", "llama3.1:8b")]
    assert helper.max_model_tokens == 16384


def test_ollama_call_openai_returns_content(monkeypatch, tmp_path):
    prompt_path = tmp_path / "prompt.md"
    prompt_path.write_text("", encoding="utf-8")
    os.environ["REPORTIMPORTER_SYSTEM_PROMPT"] = str(prompt_path)

    class FakeOllamaClient:
        def __init__(self, host):
            self.host = host

        def pull(self, model):
            return None

        def show(self, model):
            return {"model_info": {"context_length": 8192}}

        def chat(self, model, messages, options):
            return {
                "done": True,
                "done_reason": "stop",
                "message": {
                    "content": '{"type":"entity","label":"Malware.name","value":"Emotet"}'
                },
            }

    monkeypatch.setattr("reportimporter.llmhelper.OllamaClient", FakeOllamaClient)

    helper = LLMHelper(config=DummyCfg())
    out = helper.call_openai(
        messages=[
            {"role": "system", "content": "x"},
            {"role": "user", "content": "y"},
        ],
        chunk_index=1,
    )

    assert out is not None
    assert "Malware.name" in out
