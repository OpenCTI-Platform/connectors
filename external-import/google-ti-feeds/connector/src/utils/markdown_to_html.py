"""Convert GTI text fields, which mix HTML and Markdown, to HTML for OpenCTI content."""

import re

from markdown import markdown  # type: ignore[import-untyped]

# Markdown syntax that marks a field as Markdown even when it is wrapped in HTML tags.
MARKDOWN_PATTERNS = tuple(
    re.compile(pattern, re.MULTILINE)
    for pattern in (
        r"^#{1,6}\s",  # heading
        r"\*\*[^*\n]+\*\*",  # bold
        r"(?<!\*)\*(?!\*)[^*\n]+\*(?!\*)",  # italic
        r"^\s*[-*+]\s",  # bullet list
        r"^\s*\d+\.\s",  # numbered list
        r"\[[^\]]+\]\([^)]+\)",  # link
        r"^\s*\|?\s*:?-{3,}:?\s*\|",  # table delimiter row
        r"^\s*(?:```|~~~)",  # fenced code block
    )
)
# HTML code and preformatted elements hold literal text, e.g. wildcard IOCs such
# as *.example.com, which is not Markdown syntax.
HTML_LITERAL_PATTERN = re.compile(
    r"<(code|pre)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL
)
MARKDOWN_EXTENSIONS = ["tables", "fenced_code", "sane_lists"]


def is_html(text: str) -> bool:
    """Return whether the text is HTML without Markdown syntax.

    The content of HTML code and preformatted elements is ignored.
    """
    stripped = text.strip()
    if not (stripped.startswith("<") and stripped.endswith(">")):
        return False
    prose = HTML_LITERAL_PATTERN.sub("", stripped)
    return not any(pattern.search(prose) for pattern in MARKDOWN_PATTERNS)


def markdown_to_html(text: str | None) -> str:
    """Convert Markdown or mixed Markdown and HTML to HTML.

    HTML is returned as is: converting it would turn indented HTML into code blocks.
    Markdown tables, fenced code blocks and lists are supported.

    Args:
        text: The GTI text field.

    Returns:
        The HTML, or an empty string for empty text.

    """
    if not text or not text.strip():
        return ""
    if is_html(text):
        return text
    return str(markdown(text, extensions=MARKDOWN_EXTENSIONS))
