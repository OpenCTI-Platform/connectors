import time
from unittest.mock import MagicMock

from feedly.opencti_connector.connector import (
    _MARKDOWN_MAX_CHAR_RUN,
    FeedlyConnector,
    _sanitize_markdown_input,
)
from markdown import markdown


def test_long_backtick_run_no_longer_hangs():
    # Without the guard, this pins the CPU for minutes (catastrophic backtracking).
    text = "`" * 50000 + "x"
    start = time.perf_counter()
    markdown(_sanitize_markdown_input(text))
    assert time.perf_counter() - start < 5.0


def test_long_bracket_run_no_longer_hangs():
    text = "[" * 50000
    start = time.perf_counter()
    markdown(_sanitize_markdown_input(text))
    assert time.perf_counter() - start < 5.0


def test_long_symbol_runs_are_collapsed():
    for char in ("`", "[", "<", "*"):
        collapsed = _sanitize_markdown_input(char * 500)
        assert collapsed == char * _MARKDOWN_MAX_CHAR_RUN


def test_long_input_is_not_truncated():
    # No report text may be dropped: a large input without pathological symbol runs
    # is returned unchanged (only degenerate symbol runs are ever shortened).
    text = "word " * 100000  # ~500 KB of normal text
    assert _sanitize_markdown_input(text) == text


def test_long_symbol_run_is_shortened_but_surrounding_text_kept():
    text = "before " + "`" * 500 + " after"
    sanitized = _sanitize_markdown_input(text)
    assert sanitized == "before " + "`" * _MARKDOWN_MAX_CHAR_RUN + " after"


def test_alphanumeric_runs_are_preserved():
    # Letters/digits are not Markdown-active; long runs (e.g. base64) must be kept.
    text = "A" * 500
    assert _sanitize_markdown_input(text) == text


def test_short_symbol_runs_are_preserved():
    # A horizontal rule and normal formatting must be left intact.
    for text in ("-" * _MARKDOWN_MAX_CHAR_RUN, "# Title\n\n**bold** `code` [x](y)\n"):
        assert _sanitize_markdown_input(text) == text


def test_non_string_and_empty_passthrough():
    assert _sanitize_markdown_input(None) is None
    assert _sanitize_markdown_input("") == ""


def test_normal_content_output_is_unchanged():
    samples = [
        "# Title\n\nSome **bold**, _italic_, `code`, and a [link](http://x).\n\n- a\n- b\n",
        "A sentence with C:\\*.exe and a wildcard *.evil.com and a fence ``` here.",
        "Table:\n\n| a | b |\n|---|---|\n| 1 | 2 |\n",
    ]
    for sample in samples:
        assert markdown(sample) == markdown(_sanitize_markdown_input(sample))


def test_process_bundle_sanitizes_report_description_without_hanging():
    connector = FeedlyConnector.__new__(FeedlyConnector)
    connector.cti_helper = MagicMock()
    report = {
        "type": "report",
        "id": "report--00000000-0000-4000-8000-000000000000",
        "name": "My Report",
        "description": "`" * 50000 + "x",
        "published": "2024-01-01T00:00:00Z",
        "external_references": [{"source_name": "feedly"}],
        "object_refs": [],
    }
    bundle = {"type": "bundle", "id": "bundle--x", "objects": [report]}

    start = time.perf_counter()
    connector._make_reports_content_instead_of_descriptions(bundle)

    assert time.perf_counter() - start < 5.0
    assert report["content"]  # HTML content was produced
    assert report["description"] == "My Report"  # description replaced by the name
    # A warning is emitted when the guard alters pathological content.
    connector.cti_helper.log_warning.assert_called_once()
