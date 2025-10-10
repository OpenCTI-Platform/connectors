"""
Text normalization utilities for threat-intel document processing.

Provides:
- TransformMap: track raw<->cleaned offsets
- unwrap_soft_wraps: unwraps hyphenated/newline text
- refang_targeted: targeted de-obfuscation (URLs, dots, at-signs)
- compact_whitespace: collapse spaces/tabs

Note: This module intentionally avoids aggressive Unicode folding to
preserve homoglyphs. For homoglyph normalization, use higher-level routines.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import StringIO


@dataclass(frozen=True)
class Segment:
    """Mapping segment between raw and cleaned text indices."""

    raw_start: int
    raw_end: int
    cleaned_start: int
    cleaned_end: int


class TransformMap:
    """
    Bi-directional offset mapping between raw and cleaned text.

    Notes:
        - Intended for use with small to medium text documents (<1e6 chars).
        - Mapping lookups are O(n_segments), where n_segments is the number of
          modified regions (typically << total text length).
        - Designed for traceable NLP preprocessing, not large-scale analytics.
    """

    def __init__(self) -> None:
        self._segments: list[Segment] = []

    def get_segments(self) -> list[Segment]:
        """Get the list of mapping segments."""
        return self._segments

    def add_segment(
        self, raw_start: int, raw_end: int, cleaned_start: int, cleaned_end: int
    ) -> None:
        """Add a new mapping segment."""
        self._segments.append(Segment(raw_start, raw_end, cleaned_start, cleaned_end))

    def raw_to_cleaned(self, raw_index: int) -> int:
        """Translate a raw text offset to the cleaned text offset.

        Complexity:
            O(n_segments), where n_segments is typically small.
        """
        for seg in self._segments:
            if seg.raw_start <= raw_index < seg.raw_end:
                in_off = raw_index - seg.raw_start
                out_len = max(0, seg.cleaned_end - seg.cleaned_start)
                if out_len == 0:
                    return seg.cleaned_start
                # clamp to last available cleaned index in the segment
                return seg.cleaned_start + min(in_off, max(out_len - 1, 0))
        if not self._segments:
            return raw_index
        if raw_index < self._segments[0].raw_start:
            return self._segments[0].cleaned_start
        return self._segments[-1].cleaned_end

    def cleaned_to_raw(self, cleaned_index: int) -> int:
        """Translate a cleaned text offset back to the raw text offset.

        Complexity:
            O(n_segments), linear in the number of mapping segments.
        """
        for seg in self._segments:
            if seg.cleaned_start <= cleaned_index < seg.cleaned_end:
                out_off = cleaned_index - seg.cleaned_start
                in_len = max(0, seg.raw_end - seg.raw_start)
                if in_len == 0:
                    return seg.raw_start
                # clamp to last available raw index in the segment
                return seg.raw_start + min(out_off, max(in_len - 1, 0))
        if not self._segments:
            return cleaned_index
        if cleaned_index < self._segments[0].cleaned_start:
            return self._segments[0].raw_start
        return self._segments[-1].raw_end


def unwrap_soft_wraps(text: str) -> tuple[str, TransformMap]:
    """Unwrap soft line breaks while preserving paragraph boundaries.

    Rules:
    - "-\\n<word>" → seamless join (unwrap hyphenation)
    - Single newlines between lines → space
    - Double newlines → preserved as paragraph breaks
    """
    tm = TransformMap()
    raw_i = 0
    cleaned_io = StringIO()
    cleaned_i = 0
    n = len(text)
    run_start = 0

    def flush_run(upto: int) -> None:
        nonlocal run_start, cleaned_i
        if upto > run_start:
            seg = text[run_start:upto]
            cleaned_io.write(seg)
            tm.add_segment(run_start, upto, cleaned_i, cleaned_i + len(seg))
            cleaned_i += len(seg)
        run_start = upto

    while raw_i < n:
        if (
            text[raw_i] == "-"
            and raw_i + 2 < n
            and text[raw_i + 1] == "\n"
            and text[raw_i + 2].isalnum()
        ):
            flush_run(raw_i)
            tm.add_segment(raw_i, raw_i + 2, cleaned_i, cleaned_i)  # drop "-\n"
            raw_i += 2
            run_start = raw_i
            continue
        if text[raw_i] == "\n":
            if raw_i + 1 < n and text[raw_i + 1] == "\n":
                flush_run(raw_i)
                cleaned_io.write("\n\n")
                tm.add_segment(raw_i, raw_i + 2, cleaned_i, cleaned_i + 2)
                cleaned_i += 2
                raw_i += 2
            else:
                flush_run(raw_i)
                cleaned_io.write(" ")
                tm.add_segment(raw_i, raw_i + 1, cleaned_i, cleaned_i + 1)
                cleaned_i += 1
                raw_i += 1
            run_start = raw_i
            continue
        raw_i += 1

    flush_run(n)
    return cleaned_io.getvalue(), tm


def refang_targeted(
    text: str, base_map: TransformMap | None = None
) -> tuple[str, TransformMap]:
    """Refang common obfuscations (targeted replacements) with mapping updates.

    Patterns (case-insensitive):
    - hxxp://, hxxps:// → http(s)://
    - [.] , (.) , {dot}, [dot] → .
    - [@], (at), {at} → @
    """
    tm = base_map or TransformMap()
    raw_i = 0
    cleaned_i = max((s.cleaned_end for s in tm.get_segments()), default=0)
    n = len(text)
    out = StringIO()
    run_start = 0

    def emit_segment(rs: int, re: int, out_str: str) -> None:
        """Map raw[rs:re] -> out_str (half-open)."""
        nonlocal cleaned_i
        out.write(out_str)
        tm.add_segment(rs, re, cleaned_i, cleaned_i + len(out_str))
        cleaned_i += len(out_str)

    def flush_run(upto: int) -> None:
        """Flush raw[run_start:upto] verbatim (half-open)."""
        nonlocal run_start
        if upto > run_start:
            emit_segment(run_start, upto, text[run_start:upto])
        run_start = upto

    while raw_i < n:
        tail8 = text[raw_i : raw_i + 8].lower()
        tail7 = text[raw_i : raw_i + 7].lower()

        # hxxps:// (8 chars) -> https://
        if tail8.startswith("hxxps://"):
            flush_run(raw_i)
            emit_segment(raw_i, raw_i + 8, "https://")
            raw_i += 8
            run_start = raw_i
            continue

        # hxxp:// (7 chars) -> http://
        if tail7.startswith("hxxp://"):
            flush_run(raw_i)
            emit_segment(raw_i, raw_i + 7, "http://")
            raw_i += 7
            run_start = raw_i
            continue

        # [.] / (.) / {dot} / [dot] / (dot) -> "."
        if (
            text.startswith("[.]", raw_i)
            or text.startswith("(.)", raw_i)
            or text[raw_i : raw_i + 5].lower() in {"{dot}", "[dot]", "(dot)"}
        ):
            flush_run(raw_i)
            repl_len = 3 if text.startswith(("[.]", "(.)"), raw_i) else 5
            emit_segment(raw_i, raw_i + repl_len, ".")
            raw_i += repl_len
            run_start = raw_i
            continue

        # [@] / (at) / {at} -> "@"
        if text.startswith("[@]", raw_i) or text[raw_i : raw_i + 4].lower() in {
            "(at)",
            "{at}",
        }:
            flush_run(raw_i)
            repl_len = 3 if text.startswith("[@]", raw_i) else 4
            emit_segment(raw_i, raw_i + repl_len, "@")
            raw_i += repl_len
            run_start = raw_i
            continue

        raw_i += 1

    flush_run(n)
    return out.getvalue(), tm


def compact_whitespace(
    text: str, base_map: TransformMap | None = None
) -> tuple[str, TransformMap]:
    """Collapse runs of spaces/tabs into a single space. Preserve newlines."""
    tm = base_map or TransformMap()
    raw_i = 0
    cleaned_i = max((s.cleaned_end for s in tm.get_segments()), default=0)
    n = len(text)
    out = StringIO()

    def emit_range(rs: int, re: int) -> None:
        """Emit raw[rs:re] verbatim (half-open)."""
        nonlocal cleaned_i
        if re > rs:
            seg = text[rs:re]
            out.write(seg)
            tm.add_segment(rs, re, cleaned_i, cleaned_i + len(seg))
            cleaned_i += len(seg)

    last = 0
    while raw_i < n:
        if text[raw_i] in (" ", "\t"):
            # flush up to (but not including) the first whitespace
            emit_range(last, raw_i)
            ws_start = raw_i
            while raw_i < n and text[raw_i] in (" ", "\t"):
                raw_i += 1
            # collapse to a single space
            out.write(" ")
            tm.add_segment(ws_start, raw_i, cleaned_i, cleaned_i + 1)
            cleaned_i += 1
            last = raw_i
        else:
            raw_i += 1

    emit_range(last, n)
    return out.getvalue(), tm
