from __future__ import annotations

from support.text_normalize import normalize_description


class TestFalsyInputs:
    def test_empty_string(self):
        assert normalize_description("") == ""

    def test_none(self):
        assert normalize_description(None) == ""

    def test_zero_returns_empty(self):
        # ``0`` is falsy → early-return "" by design.
        assert normalize_description(0) == ""

    def test_empty_list(self):
        assert normalize_description([]) == ""

    def test_false(self):
        assert normalize_description(False) == ""


class TestPlainText:
    def test_simple_string_unchanged(self):
        assert normalize_description("Hello world") == "Hello world"

    def test_strips_leading_trailing_whitespace(self):
        assert normalize_description("   hello   ") == "hello"

    def test_non_string_coerced_to_str(self):
        # int falls through coerce path (str(123) -> "123").
        assert normalize_description(123) == "123"


class TestEscapedNewlineUnwrapping:
    def test_double_escaped_newline(self):
        # ``\\n`` (literal two chars in source) becomes a real newline.
        text = "first\\nsecond"
        assert normalize_description(text) == "first second"

    def test_double_escaped_crlf(self):
        text = "first\\r\\nsecond"
        assert normalize_description(text) == "first second"

    def test_double_escaped_tab_becomes_space(self):
        assert normalize_description("a\\tb") == "a b"

    def test_double_escaped_carriage_return_dropped(self):
        # \\r without \\n is stripped (becomes "").
        assert normalize_description("a\\rb") == "ab"

    def test_repeated_escaped_newlines_make_paragraphs(self):
        # ``\\n\\n\\n`` in the wire payload should still collapse to a single
        # paragraph break after the inline single-newline flattening pass.
        text = "p1\\n\\n\\np2"
        assert normalize_description(text) == "p1\n\np2"

    def test_blank_line_creates_paragraph_break(self):
        text = "para1\\n\\npara2"
        assert normalize_description(text) == "para1\n\npara2"


class TestHTMLTagStripping:
    def test_strips_bold(self):
        assert normalize_description("<b>hi</b>") == "hi"

    def test_strips_inline_anchor(self):
        out = normalize_description('<a href="http://example.com">link</a>')
        assert out == "link"

    def test_br_becomes_newline_then_space(self):
        # <br/> within a single paragraph becomes \n which then collapses to ' '.
        assert normalize_description("a<br/>b") == "a b"

    def test_br_self_closing_variants(self):
        for tag in ("<br>", "<br/>", "<br />", "<BR>", "<Br />"):
            assert normalize_description(f"a{tag}b") == "a b"

    def test_p_becomes_paragraph_break(self):
        text = "<p>one</p><p>two</p>"
        assert normalize_description(text) == "one\n\ntwo"

    def test_li_becomes_dashed_bullet(self):
        text = "<ul><li>first</li><li>second</li></ul>"
        out = normalize_description(text)
        # <li> opens with "- ", </li> closes with \n. Adjacent items end up on
        # separate lines that flatten inside one paragraph (single \n -> space).
        assert "- first" in out
        assert "- second" in out

    def test_strips_unknown_tag(self):
        assert normalize_description("<weirdtag>x</weirdtag>") == "x"


class TestHTMLEntities:
    def test_named_entity(self):
        assert normalize_description("a&amp;b") == "a&b"

    def test_numeric_entity(self):
        assert normalize_description("&#8364;") == "€"

    def test_nbsp_collapses_to_space(self):
        # &nbsp; -> \xa0, which DESC_HSPACE_RE collapses to ' '.
        assert normalize_description("a&nbsp;b") == "a b"


class TestWhitespaceCollapse:
    def test_multiple_spaces_collapsed(self):
        assert normalize_description("a    b") == "a b"

    def test_tabs_collapsed(self):
        assert normalize_description("a\t\tb") == "a b"

    def test_mixed_horizontal_whitespace(self):
        assert normalize_description("a \t  b") == "a b"

    def test_single_newline_inside_paragraph_becomes_space(self):
        assert normalize_description("a\nb") == "a b"


class TestParagraphSplitting:
    def test_two_newlines_makes_paragraph(self):
        assert normalize_description("first\n\nsecond") == "first\n\nsecond"

    def test_three_newlines_still_one_paragraph_break(self):
        assert normalize_description("first\n\n\nsecond") == "first\n\nsecond"

    def test_paragraphs_each_trimmed(self):
        out = normalize_description("  first  \n\n  second  ")
        assert out == "first\n\nsecond"

    def test_blank_paragraphs_dropped(self):
        out = normalize_description("a\n\n   \n\nb")
        assert out == "a\n\nb"


class TestRealisticUpstreamPayload:
    def test_html_description_with_escaped_newlines(self):
        # Shape we see from the TI API: HTML body with double-escaped \\n.
        raw = (
            "<p>Threat overview.\\n\\nMultiple campaigns observed.</p>"
            "<p>Details below.</p>"
        )
        out = normalize_description(raw)
        assert "Threat overview." in out
        assert "Multiple campaigns observed." in out
        assert "Details below." in out
        assert "\\n" not in out
        assert "<" not in out and ">" not in out

    def test_html_with_anchor_and_entities(self):
        raw = '<p>See <a href="http://example.com">report&nbsp;here</a>.</p>'
        out = normalize_description(raw)
        assert out == "See report here."

    def test_no_literal_backslash_n_in_output(self):
        text = "line1\\nline2\\nline3"
        out = normalize_description(text)
        assert "\\n" not in out
