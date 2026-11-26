"""Tests for the conversion of GTI text fields to HTML."""

import pytest
from connector.src.utils.markdown_to_html import is_html, markdown_to_html


@pytest.mark.parametrize(
    "html",
    [
        "<p>First</p>\n\n    <p>Second</p>",
        "<div><h1>Title</h1><p>Body</p></div>",
    ],
)
def test_html_is_kept_as_is(html: str) -> None:
    """HTML is not converted, so indented tags are not turned into code blocks."""
    # Given HTML content
    # When it is converted
    # Then it is unchanged
    assert markdown_to_html(html) == html  # noqa: S101


def test_markdown_table_is_converted() -> None:
    """Markdown tables are rendered as HTML tables."""
    # Given a Markdown table
    text = "| a | b |\n|---|---|\n| 1 | 2 |"
    # When it is converted
    html = markdown_to_html(text)
    # Then it is an HTML table
    assert html.startswith("<table>")  # noqa: S101
    assert "<td>2</td>" in html  # noqa: S101


def test_html_with_markdown_is_converted() -> None:
    """Markdown inside HTML-wrapped content is still converted."""
    # Given HTML-wrapped content with a Markdown heading
    text = "<p>Intro</p>\n\n## Details\n\n<p>End</p>"
    # When it is converted
    # Then the heading is rendered
    assert "<h2>Details</h2>" in markdown_to_html(text)  # noqa: S101
    assert not is_html(text)  # noqa: S101


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("<p>Intro</p>\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n<p>End</p>", "<td>2</td>"),
        ("<p>Intro</p>\n\n```\nrule x {}\n```\n\n<p>End</p>", "<pre><code>"),
    ],
)
def test_markdown_blocks_between_html_are_converted(text: str, expected: str) -> None:
    """Markdown tables and fenced code blocks between HTML paragraphs are rendered."""
    # Given HTML paragraphs around a Markdown table or fenced code block
    # When it is converted
    # Then the block is rendered and the HTML paragraphs kept
    html = markdown_to_html(text)
    assert expected in html  # noqa: S101
    assert "<p>End</p>" in html  # noqa: S101


@pytest.mark.parametrize(
    "html",
    [
        "<p>Blocks <code>*.evil.com</code> and <code>*.bad.net/*</code></p>",
        "<div><p>Rule</p>\n<pre>\n# comment\n- **/*.dll\n</pre></div>",
    ],
)
def test_html_with_literal_code_is_kept_as_is(html: str) -> None:
    """Markdown-like text in HTML code and pre elements does not make it Markdown."""
    # Given HTML whose code elements hold wildcard IOCs or comment lines
    # When it is converted
    # Then it is unchanged
    assert is_html(html)  # noqa: S101
    assert markdown_to_html(html) == html  # noqa: S101


@pytest.mark.parametrize("text", [None, "", "   "])
def test_empty_text(text: str | None) -> None:
    """Empty text gives an empty string."""
    # Given empty text
    # When it is converted
    # Then the result is empty
    assert markdown_to_html(text) == ""  # noqa: S101
