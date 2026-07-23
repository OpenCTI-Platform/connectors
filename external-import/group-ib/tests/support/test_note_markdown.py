from __future__ import annotations

from support.note_markdown import MISSING, MarkdownNote, display


class TestDisplay:
    def test_none_returns_dash(self):
        assert display(None) == MISSING

    def test_none_custom_empty(self):
        assert display(None, empty="N/A") == "N/A"

    def test_empty_string_returns_dash(self):
        assert display("") == MISSING

    def test_whitespace_only_string_returns_dash(self):
        assert display("   \t  ") == MISSING

    def test_plain_string_trimmed(self):
        assert display("  hello  ") == "hello"

    def test_int_value(self):
        assert display(42) == "42"

    def test_zero_int(self):
        assert display(0) == "0"

    def test_empty_list_returns_dash(self):
        assert display([]) == MISSING

    def test_single_element_list(self):
        assert display(["alpha"]) == "alpha"

    def test_single_element_list_blank_returns_dash(self):
        assert display([""]) == MISSING
        assert display(["   "]) == MISSING

    def test_multi_element_list_joined(self):
        assert display(["a", "b", "c"]) == "a, b, c"

    def test_multi_element_list_strips_each(self):
        assert display(["  a  ", " b "]) == "a, b"

    def test_multi_element_list_skips_blank(self):
        assert display(["a", "", "  ", "b"]) == "a, b"

    def test_multi_element_list_all_blank_returns_dash(self):
        assert display(["", "  ", "\t"]) == MISSING


class TestMarkdownNoteBuilders:
    def test_empty_build(self):
        nb = MarkdownNote()
        assert nb.build() == ""

    def test_raw_single_line(self):
        out = MarkdownNote().raw("hello").build()
        assert out == "hello\n"

    def test_chain_returns_same_instance(self):
        nb = MarkdownNote()
        assert nb.raw("x") is nb
        assert nb.h2("y") is nb
        assert nb.kv("k", "v") is nb

    def test_gap_inserts_blank_between_content(self):
        out = MarkdownNote().raw("a").gap().raw("b").build()
        assert out == "a\n\nb\n"

    def test_gap_collapses_when_last_line_is_blank(self):
        nb = MarkdownNote().raw("a").gap().gap().raw("b")
        # second gap is a no-op (last line already blank).
        assert nb.build() == "a\n\nb\n"

    def test_gap_on_empty_buffer_noop(self):
        nb = MarkdownNote().gap()
        assert nb.build() == ""

    def test_h2(self):
        out = MarkdownNote().h2("Section").build()
        assert out == "## Section\n"

    def test_h2_prepends_gap_when_content_present(self):
        out = MarkdownNote().raw("intro").h2("Sec").build()
        assert out == "intro\n\n## Sec\n"

    def test_h3(self):
        out = MarkdownNote().h3("Sub").build()
        assert out == "### Sub\n"

    def test_kv_basic(self):
        out = MarkdownNote().kv("Type", "value").build()
        assert out == "- **Type:** value\n"

    def test_kv_none_uses_dash(self):
        out = MarkdownNote().kv("Type", None).build()
        assert out == f"- **Type:** {MISSING}\n"

    def test_kv_custom_cell(self):
        out = MarkdownNote().kv("Hex", 255, cell=lambda v: f"0x{v:x}").build()
        assert out == "- **Hex:** 0xff\n"

    def test_paragraph(self):
        out = MarkdownNote().paragraph("Body text").build()
        assert out == "Body text\n"

    def test_paragraph_empty_skipped(self):
        out = MarkdownNote().raw("kept").paragraph("").build()
        assert out == "kept\n"

    def test_bullet(self):
        out = MarkdownNote().bullet("item").build()
        assert out == "- item\n"

    def test_bullet_empty_skipped(self):
        out = MarkdownNote().bullet("").build()
        assert out == ""

    def test_indented_default_prefix(self):
        out = MarkdownNote().indented("line").build()
        assert out == "  line\n"

    def test_indented_custom_prefix(self):
        out = MarkdownNote().indented("line", prefix=">>> ").build()
        assert out == ">>> line\n"

    def test_indented_empty_skipped(self):
        out = MarkdownNote().indented("").build()
        assert out == ""

    def test_extend(self):
        out = MarkdownNote().extend(["one", "two", "three"]).build()
        assert out == "one\ntwo\nthree\n"

    def test_table_no_rows(self):
        out = MarkdownNote().table(["A", "B"], []).build()
        assert out == "| A | B |\n| --- | --- |\n"

    def test_table_with_rows(self):
        nb = MarkdownNote().table(
            ["Name", "Score"],
            [("alpha", 1), ("beta", 2)],
        )
        out = nb.build()
        lines = out.rstrip("\n").splitlines()
        assert lines == [
            "| Name | Score |",
            "| --- | --- |",
            "| alpha | 1 |",
            "| beta | 2 |",
        ]

    def test_table_uses_display_for_none(self):
        out = MarkdownNote().table(["k"], [(None,)]).build()
        assert MISSING in out

    def test_table_custom_cell(self):
        out = MarkdownNote().table(["k"], [(7,)], cell=lambda v: f"<{v}>").build()
        assert "| <7> |" in out


class TestMarkdownNoteIntegration:
    def test_realistic_compound_note(self):
        """Smoke test: a typical incident-note shape rendering end-to-end."""
        nb = (
            MarkdownNote()
            .raw("# Compromised account group details")
            .kv("Login", "alice@example.com")
            .kv("Source type", None)
            .kv("Tags", ["leak", "stealer"])
            .h2("Events")
            .table(
                ["Date", "Malware"],
                [("2024-01-01", "MalwareGamma"), ("2024-02-01", None)],
            )
            .h2("Notes")
            .paragraph("Free-form analyst commentary.")
        )
        out = nb.build()
        assert out.endswith("\n")
        assert "# Compromised account group details" in out
        assert "- **Login:** alice@example.com" in out
        assert f"- **Source type:** {MISSING}" in out
        assert "- **Tags:** leak, stealer" in out
        assert "## Events" in out
        assert "| Date | Malware |" in out
        assert "| 2024-01-01 | MalwareGamma |" in out
        assert f"| 2024-02-01 | {MISSING} |" in out
        assert "## Notes" in out
        assert "Free-form analyst commentary." in out

    def test_build_idempotent(self):
        nb = MarkdownNote().raw("x").h2("y")
        assert nb.build() == nb.build()
