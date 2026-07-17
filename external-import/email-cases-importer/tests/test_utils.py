"""Unit tests for connector.utils."""

import hashlib

import pytest

from connector.utils import (
    collapse_blank_lines,
    compute_file_hashes,
    extract_passwords,
    matches_subject_filter,
    normalize_subject,
    sanitize_html,
)

# ---------------------------------------------------------------------------
# extract_passwords
# ---------------------------------------------------------------------------


class TestExtractPasswords:
    def test_basic_extraction(self):
        body = "Hello\n---BEGIN PASSWORD---hunter2---END PASSWORD---\nbye"
        assert extract_passwords(
            body, "---BEGIN PASSWORD---", "---END PASSWORD---"
        ) == ["hunter2"]

    def test_multiple_passwords(self):
        body = "[BEGIN]p1[END] some text [BEGIN]p2[END]"
        assert extract_passwords(body, "[BEGIN]", "[END]") == ["p1", "p2"]

    def test_returns_empty_when_no_match(self):
        assert extract_passwords("nothing here", "[BEGIN]", "[END]") == []

    def test_returns_empty_when_prefix_or_suffix_blank(self):
        assert extract_passwords("body", "", "[END]") == []
        assert extract_passwords("body", "[BEGIN]", "") == []

    def test_strip_whitespace_removes_internal_whitespace(self):
        body = "[BEGIN]hun ter\n2[END]"
        assert extract_passwords(body, "[BEGIN]", "[END]", strip_whitespace=True) == [
            "hunter2"
        ]

    def test_strip_whitespace_false_keeps_internal(self):
        body = "[BEGIN]hun ter[END]"
        assert extract_passwords(body, "[BEGIN]", "[END]", strip_whitespace=False) == [
            "hun ter"
        ]

    def test_html_entities_decoded_in_body(self):
        # &amp; in body should be unescaped to & before matching
        body = "[BEGIN]a&amp;b[END]"
        assert extract_passwords(body, "[BEGIN]", "[END]") == ["a&b"]

    def test_skips_empty_match(self):
        body = "[BEGIN]   [END]"
        assert extract_passwords(body, "[BEGIN]", "[END]") == []

    def test_dotall_matches_across_newlines(self):
        body = "[BEGIN]line1\nline2[END]"
        # default strip_whitespace=False keeps the newline-bearing match
        assert extract_passwords(body, "[BEGIN]", "[END]") == ["line1\nline2"]

    def test_regex_special_chars_in_markers_are_escaped(self):
        body = "*PWD*hunter2*END*"
        assert extract_passwords(body, "*PWD*", "*END*") == ["hunter2"]


# ---------------------------------------------------------------------------
# normalize_subject
# ---------------------------------------------------------------------------


class TestNormalizeSubject:
    def test_empty_string(self):
        assert normalize_subject("") == ""

    def test_no_prefix(self):
        assert normalize_subject("Security Alert") == "Security Alert"

    def test_strips_re_prefix(self):
        assert normalize_subject("RE: Security Alert") == "Security Alert"

    def test_strips_fwd_prefix(self):
        assert normalize_subject("FWD: Security Alert") == "Security Alert"

    def test_strips_multiple_prefixes(self):
        assert normalize_subject("RE: FW: RE: Alert") == "Alert"

    def test_case_insensitive(self):
        assert normalize_subject("re: Alert") == "Alert"
        assert normalize_subject("Re: Alert") == "Alert"

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("AW: Test", "Test"),  # German RE
            ("WG: Test", "Test"),  # German FW
            ("TR: Test", "Test"),  # French FW
            ("RV: Test", "Test"),  # Spanish FW
            ("ENC: Test", "Test"),  # Portuguese FW
            ("VS: Test", "Test"),  # Norwegian/Swedish FW
        ],
    )
    def test_localized_prefixes(self, raw, expected):
        assert normalize_subject(raw) == expected

    def test_strips_whitespace(self):
        assert normalize_subject("   Alert   ") == "Alert"


# ---------------------------------------------------------------------------
# sanitize_html
# ---------------------------------------------------------------------------


class TestCollapseBlankLines:
    def test_empty_returns_empty(self):
        assert collapse_blank_lines("") == ""
        assert collapse_blank_lines(None) is None  # type: ignore[arg-type]

    def test_no_blank_lines_unchanged(self):
        assert collapse_blank_lines("a\nb\nc") == "a\nb\nc"

    def test_single_blank_line_preserved(self):
        # One blank line between paragraphs is a paragraph break — keep it
        assert collapse_blank_lines("a\n\nb") == "a\n\nb"

    def test_many_blank_lines_collapsed(self):
        # Classic Outlook-explosion: 10 newlines → 2 (one blank line)
        assert collapse_blank_lines("a\n\n\n\n\n\n\n\n\n\nb") == "a\n\nb"

    def test_whitespace_only_lines_treated_as_blank(self):
        # Lines containing only spaces/tabs should still collapse
        assert collapse_blank_lines("a\n   \n\t\n   \nb") == "a\n\nb"

    def test_crlf_normalized(self):
        assert collapse_blank_lines("a\r\n\r\n\r\n\r\nb") == "a\n\nb"

    def test_leading_trailing_blanks_trimmed(self):
        assert collapse_blank_lines("\n\n\nhello\n\n\n") == "hello"


class TestSanitizeHtml:
    def test_empty_returns_empty(self):
        assert sanitize_html("") == ""

    def test_strips_tags(self):
        assert sanitize_html("<b>hello</b>") == "hello"

    def test_removes_style_block(self):
        html_in = "<style>body{color:red}</style>visible"
        assert "color:red" not in sanitize_html(html_in)
        assert "visible" in sanitize_html(html_in)

    def test_removes_script_block(self):
        html_in = "<script>alert(1)</script>safe"
        assert "alert" not in sanitize_html(html_in)
        assert "safe" in sanitize_html(html_in)

    def test_br_becomes_newline(self):
        assert sanitize_html("a<br>b") == "a\nb"

    def test_p_becomes_double_newline(self):
        assert "para1" in sanitize_html("<p>para1</p><p>para2</p>")

    def test_decodes_html_entities(self):
        assert sanitize_html("a &amp; b") == "a & b"


# ---------------------------------------------------------------------------
# compute_file_hashes
# ---------------------------------------------------------------------------


class TestComputeFileHashes:
    def test_known_hashes(self):
        data = b"hello"
        out = compute_file_hashes(data)
        assert out["MD5"] == hashlib.md5(data).hexdigest()  # noqa: S324
        assert out["SHA-1"] == hashlib.sha1(data).hexdigest()  # noqa: S324
        assert out["SHA-256"] == hashlib.sha256(data).hexdigest()

    def test_empty_bytes(self):
        out = compute_file_hashes(b"")
        # all three hashes should still be returned
        assert set(out.keys()) == {"MD5", "SHA-1", "SHA-256"}
        assert all(isinstance(v, str) and v for v in out.values())


# ---------------------------------------------------------------------------
# matches_subject_filter
# ---------------------------------------------------------------------------


class TestMatchesSubjectFilter:
    def test_empty_filters_matches_all(self):
        # Empty list means "accept any subject" — intuitive "no filter" semantics.
        assert matches_subject_filter("anything", []) is True
        assert matches_subject_filter("", []) is True
        assert matches_subject_filter("INC-1234 fired", []) is True

    def test_exact_match(self):
        assert (
            matches_subject_filter("Alert", [{"type": "exact", "value": "Alert"}])
            is True
        )

    def test_exact_no_match(self):
        assert (
            matches_subject_filter("alert", [{"type": "exact", "value": "Alert"}])
            is False
        )

    def test_contains_match(self):
        assert (
            matches_subject_filter(
                "Big Alert Today", [{"type": "contains", "value": "Alert"}]
            )
            is True
        )

    def test_regex_match(self):
        assert (
            matches_subject_filter(
                "INC-1234 fired", [{"type": "regex", "value": r"INC-\d+"}]
            )
            is True
        )

    def test_invalid_regex_is_skipped(self):
        # Bad regex should not raise — function continues to the next filter
        filters = [
            {"type": "regex", "value": "["},  # invalid
            {"type": "exact", "value": "ok"},
        ]
        assert matches_subject_filter("ok", filters) is True

    def test_unknown_filter_type_returns_false(self):
        assert (
            matches_subject_filter("subj", [{"type": "wat", "value": "subj"}]) is False
        )
