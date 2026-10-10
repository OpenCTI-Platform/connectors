from datetime import datetime, timedelta, timezone

import pytest
from connectors_sdk.models import TLPMarking
from src.xposedornot.converter_to_stix import (
    EPOCH_ANCHOR,
    MAX_DETAILS_CHARS,
    TABLE_COLUMNS,
    ConverterToStix,
    ObservableNote,
    breach_year,
    stable_timestamp,
)

from tests.conftest import BREACHED, OBSERVABLE_ID


def converter(max_table_rows=50):
    return ConverterToStix(ConverterToStix.make_author(), max_table_rows=max_table_rows)


def note_for(result, max_table_rows=50, observed_at="2024-05-01T10:00:00.000Z"):
    return converter(max_table_rows).build_note(
        OBSERVABLE_ID,
        result,
        markings=[TLPMarking(level="amber")],
        observed_at=observed_at,
    )


def breach(**overrides):
    return {**BREACHED["breaches"][0], **overrides}


def test_note_summarises_the_exposure():
    note = note_for(BREACHED)
    content = note.content
    assert "**Breaches found:** 1" in content
    assert "**First exposure:** 2024 — **Latest:** 2024" in content
    assert "**Total records across breaches:** 2,699,339" in content
    assert "**Overall risk:** Critical (100/100)" in content
    assert "stored passwords in plaintext" in content
    assert "| " + " | ".join(TABLE_COLUMNS) + " |" in content
    assert (
        "| Sysco | 2024-05-01 | 2,699,339 | sysco.com | Food | Email addresses, Names | plaintext | Yes | Sysco was breached. |"
        in content
    )
    assert note.abstract == "XposedOrNot — exposed in 1 data breach(es)"
    assert note.labels == ["xposedornot", "data-breach"]


def test_note_without_a_score_has_no_risk_line():
    content = note_for({**BREACHED, "risk_label": None, "risk_score": None}).content
    assert "Overall risk" not in content


def test_description_is_truncated_and_cells_are_escaped():
    long = "x" * (MAX_DETAILS_CHARS + 20)
    content = note_for(
        {**BREACHED, "breaches": [breach(details=long, name="a|b\nc", domain=None)]}
    ).content
    assert "x" * (MAX_DETAILS_CHARS - 1) + "…" in content and long not in content
    assert "| a\\|b c |" in content and "| — |" in content


def test_table_is_capped_newest_first_with_an_overflow_row():
    breaches = [breach(name=f"b{year}", date=str(year)) for year in (2001, 2020, 2010)]
    content = note_for({**BREACHED, "breaches": breaches}, max_table_rows=2).content
    assert content.index("b2020") < content.index("b2010") and "b2001" not in content
    assert "_… and 1 more breach(es); see xposedornot.com for the full list_" in content
    everything = note_for({**BREACHED, "breaches": breaches}, max_table_rows=0).content
    assert "b2001" in everything and "more breach(es)" not in everything


def test_note_id_and_created_are_stable_and_modified_advances():
    first = note_for(BREACHED).to_stix2_object()
    second = note_for(BREACHED).to_stix2_object()
    assert first["id"] == second["id"] == ObservableNote.stable_id(OBSERVABLE_ID)
    assert first["created"] == second["created"]
    assert first["created"] == datetime(2024, 5, 1, 10, tzinfo=timezone.utc)
    assert second["modified"] >= first["modified"] >= first["created"]
    assert first["object_refs"] == [OBSERVABLE_ID]


def test_unusable_observed_at_falls_back_to_the_epoch():
    future = datetime.now(timezone.utc) + timedelta(days=1)
    assert stable_timestamp(None) == EPOCH_ANCHOR
    assert stable_timestamp("not a date") == EPOCH_ANCHOR
    assert stable_timestamp(future) == EPOCH_ANCHOR
    naive = datetime(2020, 1, 1)
    assert stable_timestamp(naive) == naive.replace(tzinfo=timezone.utc)
    assert (
        note_for(BREACHED, observed_at=None).to_stix2_object()["created"]
        == EPOCH_ANCHOR
    )


@pytest.mark.parametrize(
    "date, expected",
    [("2024-05-01", 2024), ("0001", None), ("9999", None), (None, None), ("x", None)],
)
def test_breach_year(date, expected):
    assert breach_year({"date": date}) == expected


@pytest.mark.parametrize(
    "risk, expected",
    [
        ("plaintext", True),
        (" PlainText ", True),
        ("plaintextpassword", True),
        ("hardtocrack", False),
        (None, False),
    ],
)
def test_plaintext_exposure_vocabulary(risk, expected):
    assert (
        ConverterToStix.has_plaintext_exposure([breach(password_risk=risk)]) is expected
    )


def test_unusable_record_counts_are_dashes_and_not_summed():
    breaches = [
        breach(records=True),
        breach(records=-5),
        breach(records=None),
        breach(records=10),
    ]
    content = note_for({**BREACHED, "breaches": breaches}).content
    assert "**Total records across breaches:** 10" in content
    assert content.count("| — |") >= 3
