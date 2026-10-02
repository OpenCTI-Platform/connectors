"""Utility to convert mixed markdown/HTML content to clean HTML.

GTI report content often contains a mix of HTML and markdown formatting.
This module converts any markdown portions to proper HTML so that OpenCTI
renders the content correctly in its Content tab.
"""

import re

import markdown  # type: ignore


def _is_pure_html(text: str) -> bool:
    """Check if text is already pure HTML with no markdown.

    Args:
        text: The content string to check

    Returns:
        True if text appears to be fully HTML with no markdown syntax

    """
    # Strip leading/trailing whitespace for checking
    stripped = text.strip()
    if not stripped:
        return True

    # If it starts with an HTML tag and has no markdown-style headings,
    # bold/italic markers, or list markers outside of tags, it's likely pure HTML
    has_html_wrapper = stripped.startswith("<") and stripped.endswith(">")
    has_markdown_headings = bool(re.search(r"(?m)^#{1,6}\s", stripped))
    has_markdown_bold = bool(re.search(r"\*\*[^*]+\*\*", stripped))
    has_markdown_italic = bool(re.search(r"(?<!\*)\*(?!\*)[^*]+\*(?!\*)", stripped))
    has_markdown_lists = bool(re.search(r"(?m)^[\s]*[-*+]\s", stripped))
    has_markdown_numbered_lists = bool(re.search(r"(?m)^[\s]*\d+\.\s", stripped))
    has_markdown_links = bool(re.search(r"\[([^\]]+)\]\(([^)]+)\)", stripped))

    has_markdown = (
        has_markdown_headings
        or has_markdown_bold
        or has_markdown_italic
        or has_markdown_lists
        or has_markdown_numbered_lists
        or has_markdown_links
    )

    return has_html_wrapper and not has_markdown


def markdown_to_html(content: str) -> str:
    """Convert mixed markdown/HTML content to clean HTML.

    Handles content that may be:
    - Pure HTML (returned as-is)
    - Pure markdown (converted to HTML)
    - Mixed markdown and HTML (markdown portions converted)

    Uses the Python `markdown` library with extensions for:
    - tables: Support for markdown tables
    - fenced_code: Support for ```code blocks```
    - sane_lists: Better list handling

    Args:
        content: The content string, potentially a mix of markdown and HTML

    Returns:
        Clean HTML string

    """
    if not content or not content.strip():
        return content

    # If it's already pure HTML, return as-is
    if _is_pure_html(content):
        return content

    # Use the markdown library with useful extensions
    md = markdown.Markdown(
        extensions=[
            "tables",
            "fenced_code",
            "sane_lists",
        ]
    )

    return md.convert(content)
