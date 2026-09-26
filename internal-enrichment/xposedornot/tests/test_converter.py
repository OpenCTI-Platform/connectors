# -*- coding: utf-8 -*-
"""Unit tests for the STIX converter (Note building, helpers).

The runtime requirements are installed by tests/test-requirements.txt, so a
broken import fails the suite rather than skipping it.
"""

import json
import os
import re

from connectors_sdk.models import TLPMarking
from src.xposedornot.client_api import _normalise_free
from src.xposedornot.converter_to_stix import (
    ConverterToStix,
    ObservableNote,
    _md_cell,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SOURCE_ID = "email-addr--3f8a3b62-32e9-5efc-8e18-4b34ba6c4f36"


def _result():
    with open(
        os.path.join(FIXTURES, "breach_analytics.json"), "r", encoding="utf-8"
    ) as fh:
        return _normalise_free(json.load(fh))


def test_note_contains_breach_table_and_summary():
    converter = ConverterToStix(ConverterToStix.make_author())
    note = converter.build_note(
        SOURCE_ID, _result(), markings=[TLPMarking(level="amber")]
    )
    stix = note.to_stix2_object()
    content = stix["content"]
    assert "**Breaches found:** 2" in content
    assert "**First exposure:** 2025 — **Latest:** 2026" in content
    assert "**Overall risk:** Critical (100/100)" in content
    assert "At least one breach stored passwords in plaintext" in content
    assert "| Breach | Date | Records | Domain | Industry | Exposed data" in content
    assert "| AlienStealerLogs | 2025 | 299,646,818 |" in content
    assert SOURCE_ID in stix["object_refs"]
    assert "XposedOrNot — exposed in 2 data breach(es)" == stix["abstract"]


def test_note_created_is_anchored_while_modified_advances():
    import time

    from src.xposedornot.converter_to_stix import EPOCH_ANCHOR, stable_timestamp

    converter = ConverterToStix(ConverterToStix.make_author())
    first = converter.build_note(
        SOURCE_ID,
        _result(),
        markings=[TLPMarking(level="amber")],
        observed_at="2024-05-01T10:00:00.000Z",
    ).to_stix2_object()
    time.sleep(1.1)
    second = converter.build_note(
        SOURCE_ID,
        _result(),
        markings=[TLPMarking(level="amber")],
        observed_at="2024-05-01T10:00:00.000Z",
    ).to_stix2_object()
    assert first["id"] == second["id"]
    assert first["created"] == second["created"]
    assert first["content"] == second["content"]
    assert first["created"].isoformat().startswith("2024-05-01T10:00:00")
    assert second["modified"] > first["modified"] >= first["created"]

    fallback = converter.build_note(
        SOURCE_ID, _result(), markings=[TLPMarking(level="amber")]
    ).to_stix2_object()
    assert fallback["created"] == EPOCH_ANCHOR
    assert fallback["modified"] > EPOCH_ANCHOR
    assert stable_timestamp("not-a-date") == EPOCH_ANCHOR
    assert stable_timestamp(None) == EPOCH_ANCHOR
    assert stable_timestamp("2024-05-01T10:00:00+00:00").year == 2024


def test_note_is_deterministic_across_runs():
    converter = ConverterToStix(ConverterToStix.make_author())
    id_one = converter.build_note(
        SOURCE_ID, _result(), markings=[TLPMarking(level="amber")]
    ).to_stix2_object()["id"]
    id_two = converter.build_note(
        SOURCE_ID, _result(), markings=[TLPMarking(level="amber")]
    ).to_stix2_object()["id"]
    assert id_one == id_two


def test_note_id_is_unique_per_source_observable():
    converter = ConverterToStix(ConverterToStix.make_author())
    other_id = "email-addr--22222222-2222-4222-8222-222222222222"
    id_a = converter.build_note(
        SOURCE_ID, _result(), markings=[TLPMarking(level="amber")]
    ).to_stix2_object()["id"]
    id_b = converter.build_note(
        other_id, _result(), markings=[TLPMarking(level="amber")]
    ).to_stix2_object()["id"]
    assert id_a != id_b


def test_note_id_survives_changed_breach_content():
    converter = ConverterToStix(ConverterToStix.make_author())
    before = converter.build_note(
        SOURCE_ID, _result(), markings=[TLPMarking(level="amber")]
    ).to_stix2_object()
    changed = _result()
    changed["breaches"] = changed["breaches"][:1]
    changed["risk_score"] = 42
    after = converter.build_note(
        SOURCE_ID, changed, markings=[TLPMarking(level="amber")]
    ).to_stix2_object()
    assert before["id"] == after["id"] == ObservableNote.stable_id(SOURCE_ID)
    assert before["id"].startswith("note--")
    assert before["content"] != after["content"]
    assert "<!--" not in after["content"]
    assert after["object_refs"] == [SOURCE_ID]
    assert after["created_by_ref"] == converter.author.id
    assert after["note_types"] == ["analysis"]


def test_plaintext_detection_matches_the_live_vocabulary():
    for risk in ("plaintext", "PlainText", " plaintext ", "plaintextpassword"):
        assert ConverterToStix.has_plaintext_exposure([{"password_risk": risk}])
    for risk in ("unknown", "hardtocrack", "easytocrack", None, ""):
        assert not ConverterToStix.has_plaintext_exposure([{"password_risk": risk}])


def test_note_table_is_capped_with_an_overflow_row():
    from src.xposedornot.converter_to_stix import (
        DEFAULT_MAX_TABLE_ROWS as MAX_TABLE_ROWS,
    )

    breaches = [
        {
            "name": "B%d" % i,
            "date": "2024",
            "records": i,
            "domain": "d.test",
            "industry": "Misc",
            "password_risk": "unknown",
            "verified": "Yes",
            "data_classes": ["Email addresses"],
        }
        for i in range(MAX_TABLE_ROWS + 25)
    ]
    converter = ConverterToStix(ConverterToStix.make_author())
    content = converter.build_note(
        SOURCE_ID,
        {"breaches": breaches, "risk_label": None, "risk_score": None},
        markings=[TLPMarking(level="amber")],
    ).to_stix2_object()["content"]
    rows = [line for line in content.splitlines() if re.match(r"^\| B\d+ \|", line)]
    assert len(rows) == MAX_TABLE_ROWS
    assert "and 25 more breach(es)" in content
    assert f"**Breaches found:** {len(breaches)}" in content


def test_breach_table_is_ordered_newest_first():
    """The README and the schema both promise newest first; assert the order."""
    from src.xposedornot.converter_to_stix import breach_year

    breaches = [
        {
            "name": f"B{year}",
            "date": str(year),
            "records": 1,
            "domain": "d.test",
            "industry": "Misc",
            "password_risk": "unknown",
            "verified": "Yes",
            "data_classes": ["Email addresses"],
        }
        for year in (2011, 2026, 2019, 2004)
    ]
    converter = ConverterToStix(ConverterToStix.make_author())
    content = converter.build_note(
        SOURCE_ID,
        {"breaches": breaches, "risk_label": None, "risk_score": None},
        markings=[TLPMarking(level="amber")],
    ).to_stix2_object()["content"]
    years = [int(m) for m in re.findall(r"^\| B\d+ \| (\d{4}) \|", content, re.M)]
    assert years == [2026, 2019, 2011, 2004]
    assert breach_year({"date": "2026-01-02"}) == 2026
    assert breach_year({"date": None}) is None
    assert breach_year({}) is None


def test_note_table_cap_is_configurable():
    breaches = [
        {
            "name": "B%d" % i,
            "date": str(1990 + i),
            "records": i,
            "domain": "d.test",
            "industry": "Misc",
            "password_risk": "unknown",
            "verified": "Yes",
            "data_classes": ["Email addresses"],
        }
        for i in range(60)
    ]
    payload = {"breaches": breaches, "risk_label": None, "risk_score": None}

    capped = (
        ConverterToStix(ConverterToStix.make_author(), max_table_rows=10)
        .build_note(SOURCE_ID, payload, markings=[TLPMarking(level="amber")])
        .to_stix2_object()["content"]
    )
    rows = [line for line in capped.splitlines() if re.match(r"^\| B\d+ \|", line)]
    assert len(rows) == 10 and "and 50 more breach(es)" in capped

    uncapped = (
        ConverterToStix(ConverterToStix.make_author(), max_table_rows=0)
        .build_note(SOURCE_ID, payload, markings=[TLPMarking(level="amber")])
        .to_stix2_object()["content"]
    )
    rows = [line for line in uncapped.splitlines() if re.match(r"^\| B\d+ \|", line)]
    assert len(rows) == 60 and "more breach(es)" not in uncapped


def test_helpers():
    result = _result()
    assert ConverterToStix.years(result["breaches"]) == (2025, 2026)
    assert ConverterToStix.has_plaintext_exposure(result["breaches"]) is True
    assert _md_cell("a|b\nc") == "a\\|b c"
    assert _md_cell(None) == "—"


def test_table_cells_survive_every_line_breaking_character():
    """Breach names come from the third-party API and must not break the table.

    Only "\n" was neutralised, but str.splitlines also breaks on carriage
    return, vertical tab, form feed, NEL and the Unicode line/paragraph
    separators, so a name carrying one of those split the row in two and
    corrupted the rest of the note.
    """
    import re

    from src.xposedornot.converter_to_stix import ConverterToStix

    converter = ConverterToStix(author=ConverterToStix.make_author())

    def columns(line):
        return len(re.findall(r"(?<!\\)\|", line))

    for breaker in (
        "\n",
        "\r",
        "\r\n",
        "\x0b",
        "\x0c",
        "\x85",
        "\u2028",
        "\u2029",
        "\x1c",
        "\x00",
        "\t",
        " | ",
    ):
        result = {
            "breaches": [
                {
                    "name": f"Acme{breaker}| Injected | 2030 |",
                    "date": "2024",
                    "records": 5,
                    "domain": "d.test",
                    "industry": "Food",
                    "password_risk": "hashed",
                    "verified": "Yes",
                    "data_classes": ["Email"],
                }
            ],
            "risk_score": 5,
        }
        note = converter.build_note(
            "email-addr--11111111-1111-4111-8111-111111111111", result, markings=[]
        )
        rows = [line for line in note.content.splitlines() if line.startswith("|")]
        data = rows[2:]
        assert len(data) == 1, (breaker, data)
        assert columns(data[0]) == columns(rows[0]), (breaker, data[0])


def test_note_score_uses_the_same_validation_as_the_observable():
    """An unusable score must not appear in the Note as though it were valid.

    `usable_score` kept the observable's score empty for an out-of-range
    value while the Note still rendered `(150/100)`, presenting malformed API
    data as a valid percentage and contradicting the observable beside it.
    """
    from src.xposedornot.converter_to_stix import ConverterToStix

    converter = ConverterToStix(author=ConverterToStix.make_author())
    for unusable in (150, -5, "high", 3.7, True, None):
        result = {
            "breaches": [{"name": "B"}],
            "risk_label": "Critical",
            "risk_score": unusable,
        }
        note = converter.build_note(
            "email-addr--11111111-1111-4111-8111-111111111111", result, markings=[]
        )
        line = next(l for l in note.content.splitlines() if "Overall risk" in l)
        assert "/100" not in line, (unusable, line)
        assert "Critical" in line

    result = {"breaches": [{"name": "B"}], "risk_label": "Critical", "risk_score": 77}
    note = converter.build_note(
        "email-addr--11111111-1111-4111-8111-111111111111", result, markings=[]
    )
    assert "(77/100)" in note.content


def test_risk_label_cannot_open_a_new_markdown_block():
    """The risk label is untrusted API text on a line of its own.

    Only table cells were flattened, so a label carrying a newline ended the
    current block and rendered whatever followed as a heading of its own.
    """
    from src.xposedornot.converter_to_stix import ConverterToStix

    converter = ConverterToStix(author=ConverterToStix.make_author())
    for label in (
        "Critical\n## Injected heading",
        "Critical\r## Injected",
        "Critical\u2028## Injected",
        {"k": "v"},
        ["a"],
    ):
        result = {
            "breaches": [{"name": "B"}],
            "risk_label": label,
            "risk_score": 50,
        }
        note = converter.build_note(
            "email-addr--11111111-1111-4111-8111-111111111111", result, markings=[]
        )
        risk_lines = [l for l in note.content.splitlines() if "Overall risk" in l]
        assert len(risk_lines) == 1, label
        assert not [
            l
            for l in note.content.splitlines()
            if "Injected" in l and not l.startswith("**Overall risk:**")
        ], label
