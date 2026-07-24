"""Unit tests for reportimporter.textnorm TransformMap and refang helpers."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from reportimporter.textnorm import (
    TransformMap,
    compact_whitespace,
    refang_targeted,
    unwrap_soft_wraps,
)


class TestTransformMap:
    def test_empty_passthrough(self):
        tm = TransformMap()
        assert tm.raw_to_cleaned(5) == 5
        assert tm.cleaned_to_raw(5) == 5

    def test_within_segment(self):
        tm = TransformMap()
        tm.add_segment(0, 10, 0, 5)
        assert tm.raw_to_cleaned(0) == 0
        assert tm.raw_to_cleaned(3) == 3
        assert tm.raw_to_cleaned(8) == 4  # clamped to last cleaned index
        assert tm.cleaned_to_raw(0) == 0
        assert tm.cleaned_to_raw(4) == 4

    def test_zero_length_segments(self):
        tm = TransformMap()
        tm.add_segment(0, 5, 2, 2)  # cleaned out_len == 0
        assert tm.raw_to_cleaned(3) == 2
        tm2 = TransformMap()
        tm2.add_segment(2, 2, 0, 5)  # raw in_len == 0
        assert tm2.cleaned_to_raw(3) == 2

    def test_before_first_segment(self):
        tm = TransformMap()
        tm.add_segment(5, 10, 3, 8)
        assert tm.raw_to_cleaned(0) == 3
        assert tm.cleaned_to_raw(0) == 5

    def test_after_last_segment(self):
        tm = TransformMap()
        tm.add_segment(0, 5, 0, 5)
        assert tm.raw_to_cleaned(100) == 5
        assert tm.cleaned_to_raw(100) == 5


class TestTextTransforms:
    def test_unwrap_hyphenation(self):
        out, _ = unwrap_soft_wraps("hyphen-\nation")
        assert out == "hyphenation"

    def test_unwrap_single_newline_to_space(self):
        out, _ = unwrap_soft_wraps("line1\nline2")
        assert out == "line1 line2"

    def test_unwrap_double_newline_preserved(self):
        out, _ = unwrap_soft_wraps("para1\n\npara2")
        assert out == "para1\n\npara2"

    def test_refang_targeted(self):
        out, _ = refang_targeted("hxxps://evil[.]com a(at)b[dot]com")
        assert "https://evil.com" in out
        assert "a@b.com" in out

    def test_refang_hxxp(self):
        out, _ = refang_targeted("hxxp://x.io")
        assert out == "http://x.io"

    def test_compact_whitespace(self):
        out, _ = compact_whitespace("a    b\t\tc")
        assert out == "a b c"
