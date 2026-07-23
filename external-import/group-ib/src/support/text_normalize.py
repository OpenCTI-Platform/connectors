"""Description / free-text normalization shared across adapters.

Group-IB TI API returns Report and Threat-Actor descriptions as HTML with
double-escaped newlines and inline tags. ``normalize_description`` strips
HTML, decodes escaped newlines, flattens single newlines inside a paragraph
to spaces, and collapses runs of blank lines to one paragraph break. The
result is a markdown-friendly multi-paragraph string with no literal ``\\n``
sequences and no inline HTML.
"""

from __future__ import annotations

import html
from typing import Any

from connector.settings import (
    DESC_BR_RE,
    DESC_CLOSE_LI_RE,
    DESC_CLOSE_P_RE,
    DESC_HSPACE_RE,
    DESC_OPEN_LI_RE,
    DESC_OPEN_P_RE,
    DESC_PARA_RE,
    DESC_TAG_RE,
)


def normalize_description(value: Any) -> str:
    """Clean an upstream HTML/text description for OpenCTI rendering."""
    if not value:
        return ""
    s = str(value)
    # Unwrap nested literal-escapes (``\\\\n`` -> ``\\n`` -> ``\n``).
    for _ in range(3):
        new = (
            s.replace("\\r\\n", "\n")
            .replace("\\n", "\n")
            .replace("\\t", " ")
            .replace("\\r", "")
        )
        if new == s:
            break
        s = new
    s = DESC_BR_RE.sub("\n", s)
    s = DESC_CLOSE_P_RE.sub("\n\n", s)
    s = DESC_OPEN_P_RE.sub("", s)
    s = DESC_CLOSE_LI_RE.sub("\n", s)
    s = DESC_OPEN_LI_RE.sub("- ", s)
    s = DESC_TAG_RE.sub("", s)
    s = html.unescape(s)
    s = DESC_HSPACE_RE.sub(" ", s)
    paragraphs = DESC_PARA_RE.split(s)
    cleaned: list[str] = []
    for para in paragraphs:
        flat = para.replace("\r", " ").replace("\n", " ").strip()
        flat = DESC_HSPACE_RE.sub(" ", flat)
        if flat:
            cleaned.append(flat)
    return "\n\n".join(cleaned)
