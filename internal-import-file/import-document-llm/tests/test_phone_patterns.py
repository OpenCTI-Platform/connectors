"""
Unit tests for phone number extraction and normalization
via reportimporter.regex_scanner.scan_structured_iocs().

Purpose:
Validate that the regex scanner correctly detects and normalizes
telephone numbers in diverse formats, while rejecting false positives.

Scope:
- Contiguous national numbers
- Numbers with separators and parentheses
- International E.164 normalization
- Rejection of short digit sequences not representing phone numbers
"""

import sys
from pathlib import Path

# Ensure the `src` directory is importable (consistent with other test files)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reportimporter.regex_scanner import scan_structured_iocs


def _get_phone_norm(text: str):
    """Return normalized and raw phone numbers extracted from text."""
    spans = scan_structured_iocs(text)
    phones = [s for s in spans if s.type == "Phone-Number"]
    return [s.normalized_value for s in phones], [s.raw_value for s in phones]


def test_contiguous_national_number():
    """
    Validate detection of contiguous national numbers without separators.
    Expected: at least one detected and optionally normalized to E.164.
    """
    text = "Call us at 08005551234 for support."
    norms, raws = _get_phone_norm(text)

    assert len(raws) >= 1, "Expected at least one phone number detected"
    assert len(norms) >= 1, "Expected normalized output (E.164 or fallback)"


def test_parentheses_and_separators():
    """
    Verify correct parsing of numbers with separators and parentheses,
    and E.164 normalization for international formats.
    """
    examples = [
        "(512) 555-1234",
        "512-555-1234",
        "512 555 1234",
        "+1 (512) 555-1234",
        "+44 20 7946 0958",
    ]
    for ex in examples:
        norms, raws = _get_phone_norm(ex)

        assert len(raws) >= 1, f"No phone detected in '{ex}'"
        # Explicit international numbers should normalize to E.164
        if ex.startswith("+"):
            assert any(
                n.startswith("+") for n in norms
            ), f"Expected E.164 normalization for '{ex}'"


def test_mixed_digits_and_text_not_matched():
    """
    Ensure short numeric sequences or mixed digits not resembling phones
    are not falsely detected.
    """
    text = "Ref 2021 or invoice 1234567 should not match as phone"
    norms, raws = _get_phone_norm(text)

    assert len(raws) == 0, f"Unexpected phone match in '{text}'"
