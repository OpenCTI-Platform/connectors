"""Test module for the HTML to Markdown conversion of GTI text fields."""

import pytest
from connector.src.utils.html_to_markdown import html_to_markdown


def test_html_is_converted_to_markdown() -> None:
    """HTML paragraphs, links and emphasis become Markdown."""
    # Given HTML text
    text = '<p>See <a href="https://example.com/a">this</a>.</p><p><em>Note</em></p>'

    # When converted
    result = html_to_markdown(text)

    # Then it is Markdown, without tags
    assert result == "See [this](https://example.com/a).\n\n*Note*"  # noqa: S101


@pytest.mark.parametrize(
    "text",
    [
        "Plain text comment.",
        "## Heading\n\n- item one\n- item two",
        "<p>Mixed</p>\n\n- a Markdown list",
        "<p>Mixed</p>\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n<p>End</p>",
        "<p>Mixed</p>\n\n```\nrule x {}\n```\n\n<p>End</p>",
    ],
)
def test_non_html_text_is_returned_as_is(text: str) -> None:
    """Plain, Markdown and mixed text keep their line breaks and syntax."""
    assert html_to_markdown(text) == text  # noqa: S101


def test_html_with_wildcard_iocs_in_code_is_converted() -> None:
    """Wildcard IOCs in HTML code elements do not leave the note as raw HTML."""
    # Given an HTML analyst comment quoting wildcard IOCs in code elements
    text = "<p>Blocks <code>*.evil.com</code> and <code>*.bad.net/*</code></p>"

    # When converted
    result = html_to_markdown(text)

    # Then it is Markdown, with the IOCs as inline code
    assert result == "Blocks `*.evil.com` and `*.bad.net/*`"  # noqa: S101


@pytest.mark.parametrize("text", [None, "", "   "])
def test_empty_text(text: str | None) -> None:
    """Empty values are returned as an empty or unchanged string."""
    assert html_to_markdown(text) == (text or "")  # noqa: S101
