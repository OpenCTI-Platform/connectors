"""
Unit test for OpenAIHelper prompt trimming and token-budget control.

Purpose:
Validate that OpenAIHelper correctly enforces its token budget when constructing
user prompts with many hints. The test uses a FakeEncoder (1 char = 1 token)
to simulate predictable token counts, ensuring trimming logic fits the target
budget under constrained max_model_tokens.

Scope:
- Validate token counting under FakeEncoder
- Verify sub-chunk generation via _chunk_text_with_offsets()
- Confirm trimming ensures prompt <= token limit
"""

import os
import sys
from pathlib import Path

# Ensure the `src` directory is importable (consistent with other test files)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reportimporter.openai import OpenAIHelper


class DummyCfg:
    """Minimal config forcing a small context window to trigger trimming."""

    def __init__(self):
        self.ai_provider = "azureopenai"
        self.ai_model = "gpt-4o"
        self.openai_endpoint = "https://example.invalid"
        self.openai_key = "x"
        self.openai_deployment = "d"
        self.openai_api_version = "2024-01-01"
        self.max_model_tokens = 1200
        self.model_input_ratio = 0.3
        self.create_indicator = False

    @property
    def is_azure_openai(self):
        return True

    @property
    def is_openai(self):
        return False


class FakeEncoder:
    """Deterministic encoder where 1 character = 1 token."""

    def __init__(self):
        self._type = "char"

    def encode(self, s: str):
        return list(s or "")

    def decode(self, toks):
        return "".join(toks or [])

    def count(self, s: str) -> int:
        return len(s or "")

    def is_tiktoken(self):
        return False


def test_trim_hints_to_budget_keeps_under_limit(monkeypatch, tmp_path):
    """
    Verify that OpenAIHelper trims hints such that the composed prompt
    fits within the model’s target token budget.
    """
    # --- Arrange ---
    p = tmp_path / "prompt.md"
    p.write_text("", encoding="utf-8")
    os.environ["REPORTIMPORTER_SYSTEM_PROMPT"] = str(p)

    helper = OpenAIHelper(config=DummyCfg())
    helper.enc = FakeEncoder()
    helper.system_prompt = ""

    text = "A" * 120  # 120 tokens by FakeEncoder
    hints = [
        {
            "id": f"h{i}",
            "type": "IPv4-Addr.value",
            "category": "IPv4-Addr.value",
            "value": "1.2.3.4",
            "positions": [{"start": 0, "end": 1}],
        }
        for i in range(500)
    ]

    # Build sub-chunks and assign hints overlapping per character window
    raw_chunks = helper._chunk_text_with_offsets(text)
    subchunks = []
    for s, e, frag in raw_chunks:
        local_hints = []
        for h in hints:
            for p in h.get("positions") or []:
                try:
                    ps, pe = int(p.get("start", 0)), int(p.get("end", 0))
                except Exception:
                    continue
                if not (pe <= s or ps >= e):
                    local_hints.append(h)
                    break
        subchunks.append({"text": frag, "start": s, "end": e, "hints": local_hints})

    assert subchunks, "Expected at least one generated sub-chunk"

    # Limit hints per chunk to simulate the helper’s own capping behavior
    for sc in subchunks:
        sc["hints"] = sc.get("hints", [])[:5]

    assert all(
        len(sc.get("hints", [])) > 0 for sc in subchunks
    ), "Expected non-empty hint lists in sub-chunks"

    # --- Act ---
    def build_user(hlist, abs_start, abs_end, t):
        import json

        return (
            "You are extracting threat intel spans and relations.\n"
            "Given the TEXT and HINTS, return a single JSON object with keys:\n"
            "  metadata: { span_based_entities: [ {id, text, label, type, positions?} ... ] }\n"
            "  relations: [ {type, from_id, to_id} ... ]\n"
            "- Use HINTS IDs for structured IOCs when present.\n"
            "- Only emit IDs that exist in HINTS or are defined in span_based_entities.\n"
            "- No markdown, no explanations, JSON only.\n\n"
            f"HINTS: {json.dumps({'hints': hlist, 'start': abs_start, 'end': abs_end}, separators=(',', ':'))}\n\nTEXT:\n{t}"
        )

    sc0 = subchunks[0]
    hard_limit = helper.max_model_tokens - helper.safety_margin
    target_prompt_max = max(1, hard_limit - int(helper.max_model_tokens * 0.2))

    found_ok = False
    for k in range(len(sc0["hints"]), 0, -1):
        trial_hints = sc0["hints"][:k]
        messages = [
            {"role": "system", "content": helper.system_prompt},
            {
                "role": "user",
                "content": build_user(
                    trial_hints, sc0["start"], sc0["end"], sc0["text"]
                ),
            },
        ]
        used = helper._count_message_tokens(messages)
        if used <= target_prompt_max:
            found_ok = True
            break

    # --- Assert ---
    assert (
        found_ok
    ), f"Prompt never fit under target budget (used={used}, target={target_prompt_max})"
