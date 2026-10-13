import json
import re

import pytest
from connector.stix_builder import (
    bundle,
    make_autonomous_system,
    make_domain,
    make_external_reference,
    make_ipv4,
    make_ipv6,
    make_note,
    make_relationship,
    md_code,
    md_fence,
    md_prose,
    md_text,
    network_observable_for,
    stix_id,
    tlp_marking,
)


def test_stix_id_is_deterministic():
    a = stix_id("note", "stairwell-ai-triage|file--abc")
    b = stix_id("note", "stairwell-ai-triage|file--abc")
    assert a == b
    assert a.startswith("note--")


def test_tlp_marking_default_amber():
    assert "marking-definition--" in tlp_marking("amber")
    assert tlp_marking("AMBER") == tlp_marking("amber")
    assert tlp_marking("not-a-tlp") == tlp_marking("amber")


def test_make_ipv4_and_ipv6_have_correct_type():
    v4 = make_ipv4("8.8.8.8")
    v6 = make_ipv6("2001:db8::1")
    assert v4["type"] == "ipv4-addr"
    assert v4["value"] == "8.8.8.8"
    assert v6["type"] == "ipv6-addr"
    assert v6["value"] == "2001:db8::1"
    assert v4["object_marking_refs"] == [tlp_marking("amber")]


def test_network_observable_for_picks_ipv6_by_colon():
    assert network_observable_for("8.8.8.8", "ip", "amber")["type"] == "ipv4-addr"
    assert network_observable_for("2001:db8::1", "ip", "amber")["type"] == "ipv6-addr"
    assert (
        network_observable_for("evil.com", "hostname", "amber")["type"] == "domain-name"
    )
    assert network_observable_for("http://evil.com/x", "url", "amber")["type"] == "url"
    assert network_observable_for("", "ip", "amber") is None
    assert network_observable_for("x", "unknown-kind", "amber") is None


def test_make_domain_and_asn_basic_shape():
    d = make_domain("evil.com")
    asn = make_autonomous_system(15169, name="GOOGLE")
    assert d["type"] == "domain-name"
    assert d["value"] == "evil.com"
    assert asn["type"] == "autonomous-system"
    assert asn["number"] == 15169
    assert asn["name"] == "GOOGLE"


def test_make_relationship_deterministic_id():
    a = make_relationship("file--x", "ipv4-addr--y")
    b = make_relationship("file--x", "ipv4-addr--y")
    assert a["id"] == b["id"]
    assert a["relationship_type"] == "related-to"


def test_make_note_includes_object_refs_and_tlp():
    note = make_note(
        seed="stairwell-test|file--x",
        abstract="Test",
        content="body",
        object_refs=["file--x"],
        tlp="green",
    )
    assert note["type"] == "note"
    assert note["object_refs"] == ["file--x"]
    assert note["object_marking_refs"] == [tlp_marking("green")]


def test_bundle_dedupes_by_id_and_serializes():
    objs = [
        make_ipv4("8.8.8.8"),
        make_ipv4("8.8.8.8"),  # duplicate
        make_domain("evil.com"),
    ]
    payload = json.loads(bundle(objs))
    assert payload["type"] == "bundle"
    ids = {o["id"] for o in payload["objects"]}
    assert len(ids) == 2  # ipv4 dedup'd


def test_make_external_reference():
    ref = make_external_reference("Stairwell", "https://app.stairwell.com/x", "desc")
    assert ref["source_name"] == "Stairwell"
    assert ref["url"] == "https://app.stairwell.com/x"
    assert ref["description"] == "desc"


@pytest.mark.parametrize(
    "value, in_table, want",
    [
        ("evil.exe", False, "`evil.exe`"),
        ("a`b", False, "``a`b``"),
        ("`x", False, "`` `x ``"),
        ("a``b", False, "```a``b```"),
        ("line1\nline2\r\n# heading", False, "`line1 line2 # heading`"),
        ("a|b", False, "`a|b`"),
        ("a|b", True, "`a\\|b`"),
        ("", False, ""),
    ],
)
def test_md_code_keeps_value_inside_one_code_span(value, in_table, want):
    assert md_code(value, in_table=in_table) == want


@pytest.mark.parametrize(
    "value, want",
    [
        ("GOOGLE LLC", "GOOGLE LLC"),
        ("2000-03-30", "2000-03-30"),
        ("[click](http://evil.example/x)", "\\[click\\](http\\://evil.example/x)"),
        ("![i](https://t.example/p.png)", "\\!\\[i\\](https\\://t.example/p.png)"),
        ("see www.evil.example", "see www\\.evil.example"),
        ("mail a@evil.example", "mail a\\@evil.example"),
        ("<img src=x>", "\\<img src=x\\>"),
        ("a|b *c* _d_ ~e~ `f`", "a\\|b \\*c\\* \\_d\\_ \\~e\\~ \\`f\\`"),
        ("one\n\n# two", "one # two"),
        ("back\\[x]", "back\\\\\\[x\\]"),
    ],
)
def test_md_text_neutralises_inline_markdown(value, want):
    assert md_text(value) == want


def test_md_fence_is_longer_than_any_backtick_run_in_content():
    assert md_fence("plain") == "```\nplain\n```"
    content = "a\n```\n[x](http://evil)\n````"
    fenced = md_fence(content)
    assert fenced == "`````\n" + content + "\n`````"


def test_md_prose_keeps_formatting_but_disables_links_and_images():
    summary = (
        "## Verdict\n\n**Malicious** dropper.\n\n"
        "- Beacons to http://c2.example/a and www.c2.example\n"
        "- [Report](https://evil.example) ![px](https://t.example/p.png)\n"
        "- <https://auto.example> ops@evil.example\n"
        "\\[escaped](http://still.example)\n\n"
        "[ref]: https://ref.example"
    )
    out = md_prose(summary)
    assert out.startswith("## Verdict\n\n**Malicious** dropper.\n\n- Beacons")
    # Each construct must be absent unless its first character is escaped.
    for construct in (
        r"\]\(",
        r"!\[",
        r"<http",
        r"https?:",
        r"www\.",
        r"ops@",
        r"^\[ref",
    ):
        assert not re.search(r"(?<!\\)" + construct, out, re.M), construct
    assert "\\\\\\[escaped\\]" in out


@pytest.mark.parametrize("backslashes", [0, 1, 2, 3, 4, 5])
@pytest.mark.parametrize("opener", ["[", "<"])
def test_md_prose_brackets_stay_escaped_after_any_backslash_run(backslashes, opener):
    raw = "\\" * backslashes + opener
    out = md_prose(raw)
    # The opener is literal only if an odd number of backslashes precede it.
    assert out.endswith(opener)
    before = out[: -len(opener)]
    run = len(before) - len(before.rstrip("\\"))
    assert run % 2 == 1, (raw, out)


def test_md_prose_leaves_backslashes_elsewhere_alone():
    assert md_prose("`C:\\Users\\x` and \\*") == "`C:\\Users\\x` and \\*"
