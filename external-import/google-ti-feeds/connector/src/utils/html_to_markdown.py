"""Convert GTI HTML text fields to Markdown for OpenCTI fields rendered as Markdown."""

from connector.src.utils.markdown_to_html import is_html
from markdownify import markdownify  # type: ignore[import-untyped]


def html_to_markdown(text: str | None) -> str:
    """Return the text as Markdown, converting it only when it is HTML.

    OpenCTI renders note content as Markdown, so HTML shows as raw tags. Text
    that is already Markdown, or mixes Markdown with HTML, is returned as is:
    converting it would collapse its line breaks and escape its syntax.
    """
    if not text or not text.strip():
        return text or ""
    if not is_html(text):
        return text
    converted = str(markdownify(text, heading_style="ATX")).strip()
    return converted or text
