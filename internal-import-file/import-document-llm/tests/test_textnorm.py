"""
Unit tests for reportimporter.textnorm

These tests validate the text normalization routines that prepare raw
documents for structured IOC extraction. The tests ensure that line
unwrapping, targeted refanging, and whitespace compaction all behave
as expected and maintain correct TransformMap consistency.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest
from reportimporter.textnorm import (
    TransformMap,
    compact_whitespace,
    refang_targeted,
    unwrap_soft_wraps,
)

# ----------------------------------------------------------------------------------
# Soft unwrap tests — verify correct merging of lines and paragraph preservation
# ----------------------------------------------------------------------------------


def test_unwrap_soft_wraps_merges_lines():
    """Single line breaks should unwrap to spaces; hyphen+newline sequences should merge words."""
    text = "This is a sen-\ntence that continues\non another line."
    result, tm = unwrap_soft_wraps(text)
    assert "sentence" in result
    assert "that continues on another line." in result
    assert isinstance(tm, TransformMap)


def test_unwrap_soft_wraps_preserves_paragraphs():
    """Double newlines should remain as paragraph boundaries."""
    text = "First paragraph.\n\nSecond paragraph."
    result, _ = unwrap_soft_wraps(text)
    assert result == "First paragraph.\n\nSecond paragraph."


# ----------------------------------------------------------------------------------
# Refang tests — verify targeted de-obfuscation of URLs, dots, and at-signs
# ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "input_text,expected",
    [
        ("hxxp://evil[.]com", "http://evil.com"),
        ("HXXPS://secure[.]site", "https://secure.site"),
        ("user[@]example[.]org", "user@example.org"),
        ("example(dot)com", "example.com"),
    ],
)
def test_refang_targeted_variants(input_text, expected):
    """Common obfuscation forms should be restored with correct TransformMap."""
    result, tm = refang_targeted(input_text)
    assert result == expected
    assert isinstance(tm, TransformMap)


def test_refang_targeted_mixed_sequence():
    """Multiple patterns within the same string should all be refanged."""
    text = "Visit hxxp://evil[.]com or mail user[@]evil[.]com"
    result, _ = refang_targeted(text)
    assert "http://evil.com" in result
    assert "user@evil.com" in result


# ----------------------------------------------------------------------------------
# Whitespace compaction tests — validate collapsing behavior
# ----------------------------------------------------------------------------------


def test_compact_whitespace_reduces_gaps():
    """Runs of multiple spaces or tabs should be reduced to a single space."""
    text = "A   B\t\tC"
    result, _ = compact_whitespace(text)
    assert result == "A B C"


def test_compact_whitespace_preserves_newlines():
    """Newlines should remain unaffected by whitespace collapsing."""
    text = "Line1  \nLine2\t\tLine3"
    result, _ = compact_whitespace(text)
    assert result == "Line1 \nLine2 Line3"


# ----------------------------------------------------------------------------------
# Integration tests — combine unwrap, refang, and whitespace in sequence
# ----------------------------------------------------------------------------------


def test_combined_pipeline_preserves_mapping():
    """Sequential use of unwrap_soft_wraps, refang_targeted, and compact_whitespace
    should yield consistent and readable normalized text."""
    text = "Hxxp://evil[.]com\ncontinues here.\n\nNext para with  extra   spaces."
    unwrapped, tm1 = unwrap_soft_wraps(text)
    refanged, tm2 = refang_targeted(unwrapped, tm1)
    compacted, tm3 = compact_whitespace(refanged, tm2)

    assert "http://evil.com continues here." in compacted
    assert "Next para with extra spaces." in compacted
    assert isinstance(tm3, TransformMap)
