import json
import re

import pytest
import stix2
from connector.stix_builder import (
    STAIRWELL_IDENTITY_ID,
    bundle,
    make_autonomous_system,
    make_domain,
    make_external_reference,
    make_file_by_sha256,
    make_grouping,
    make_identity_system,
    make_indicator,
    make_ip,
    make_ipv4,
    make_ipv6,
    make_note,
    make_relationship,
    make_report,
    make_sighting,
    make_url,
    md_code,
    md_fence,
    md_prose,
    md_text,
    network_observable_for,
    tlp_marking,
    tlp_marking_object,
    valid_hash,
)
from connectors_sdk.models import TLPMarking
from pycti import (
    Grouping,
    Identity,
    Indicator,
    Note,
    Report,
    StixCoreRelationship,
    StixSightingRelationship,
)


def test_sdo_and_sro_ids_are_opencti_canonical():
    """Every SDO/SRO ID is the one pycti generates for that object."""
    rel = make_relationship("file--x", "ipv4-addr--y", "related-to")
    assert rel["id"] == StixCoreRelationship.generate_id(
        "related-to", "file--x", "ipv4-addr--y"
    )
    note = make_note("Abstract", "body", ["file--x"], "green")
    assert note["id"] == Note.generate_id(None, "body", "Abstract")
    pattern = "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"
    assert make_indicator(pattern, "n", "2026-01-01T00:00:00.000Z")["id"] == (
        Indicator.generate_id(pattern)
    )
    assert STAIRWELL_IDENTITY_ID == Identity.generate_id("Stairwell", "organization")
    asset = make_identity_system("assets/X1", name="RISER")
    assert asset["id"] == Identity.generate_id("assets/X1", "system")
    sighting = make_sighting(
        "file--x",
        [asset["id"]],
        "2026-01-01T00:00:00.000Z",
        "2026-01-02T00:00:00.000Z",
        2,
    )
    assert sighting["id"] == StixSightingRelationship.generate_id(
        "file--x", [asset["id"]]
    )
    created = "2026-05-06T01:02:03.456789+00:00"
    grouping = make_grouping("G", ["file--x"], created, context="malware-analysis")
    assert grouping["id"] == Grouping.generate_id("G", "malware-analysis", created)
    report = make_report("R", ["file--x"], "2026-05-06T00:00:00.000Z")
    assert report["id"] == Report.generate_id("R", "2026-05-06T00:00:00.000Z")


def test_sco_ids_follow_the_stix_spec():
    """SCO IDs match what the stix2 library derives from the same properties."""
    assert make_ipv4("8.8.8.8")["id"] == stix2.IPv4Address(value="8.8.8.8").id
    assert make_ipv6("2001:db8::1")["id"] == stix2.IPv6Address(value="2001:db8::1").id
    assert make_domain("evil.com")["id"] == stix2.DomainName(value="evil.com").id
    assert (
        make_url("http://evil.com/x")["id"] == stix2.URL(value="http://evil.com/x").id
    )
    assert (
        make_autonomous_system(64500)["id"] == stix2.AutonomousSystem(number=64500).id
    )
    sco = make_file_by_sha256("a" * 64, md5="b" * 32)
    assert sco["id"] == stix2.File(hashes={"SHA-256": "a" * 64}).id


def test_sighting_id_ignores_moving_first_and_last_seen():
    a = make_sighting(
        "file--x",
        ["identity--y"],
        "2026-01-01T00:00:00.000Z",
        "2026-01-02T00:00:00.000Z",
        1,
    )
    b = make_sighting(
        "file--x",
        ["identity--y"],
        "2026-01-01T00:00:00.000Z",
        "2026-03-09T00:00:00.000Z",
        7,
    )
    assert a["id"] == b["id"]


@pytest.mark.parametrize(
    "level", ["clear", "white", "green", "amber", "amber+strict", "red"]
)
def test_tlp_ids_and_objects_are_the_sdk_marking_definitions(level):
    sdk = json.loads(TLPMarking(level=level).to_stix2_object().serialize())
    ours = tlp_marking_object(level)
    assert tlp_marking(level) == sdk["id"] == ours["id"]
    # The SDK stamps clear/amber+strict definitions with the time they were built.
    skip = {"created", "modified"}
    assert {k: v for k, v in ours.items() if k not in skip} == {
        k: v for k, v in sdk.items() if k not in skip
    }


def test_tlp_clear_uses_the_standard_stix_marking_id():
    assert (
        tlp_marking("clear")
        == "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    )


def test_bundle_carries_the_marking_definitions_its_objects_reference():
    payload = json.loads(
        bundle([make_ipv4("8.8.8.8", tlp="green"), make_domain("a.example", tlp="red")])
    )
    markings = {
        o["id"] for o in payload["objects"] if o["type"] == "marking-definition"
    }
    assert markings == {tlp_marking("green"), tlp_marking("red")}


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
    ids = {o["id"] for o in payload["objects"] if o["type"] != "marking-definition"}
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


@pytest.mark.parametrize(
    "algo, value, ok",
    [
        ("SHA-256", "A" * 64, True),
        ("SHA-256", "a" * 63, False),
        ("SHA-256", "g" * 64, False),
        ("SHA-256", "a" * 63 + ")", False),
        ("SHA-1", "b" * 40, True),
        ("SHA-1", "b" * 41, False),
        ("MD5", "c" * 32, True),
        ("MD5", "c" * 31 + " ", False),
        ("MD5", None, False),
        ("SHA-512", "d" * 128, False),
    ],
)
def test_valid_hash(algo, value, ok):
    assert valid_hash(algo, value) is ok


def test_file_sco_rejects_bad_sha256_and_drops_bad_optional_hashes():
    with pytest.raises(ValueError):
        make_file_by_sha256("a" * 63 + ")")
    sco = make_file_by_sha256("A" * 64, sha1="b" * 39, md5="C" * 32)
    assert sco["hashes"] == {"SHA-256": "a" * 64, "MD5": "c" * 32}


@pytest.mark.parametrize(
    "value, want_type, want_value",
    [
        ("1.2.3.4", "ipv4-addr", "1.2.3.4"),
        ("2001:DB8::1", "ipv6-addr", "2001:db8::1"),
        ("1.2.3.4:80", None, None),
        ("999.1.1.1", None, None),
        ("not an ip", None, None),
        ("", None, None),
    ],
)
def test_make_ip_validates_and_normalises(value, want_type, want_value):
    sco = make_ip(value, tlp="green")
    if want_type is None:
        assert sco is None
    else:
        assert (sco["type"], sco["value"]) == (want_type, want_value)
    assert network_observable_for(value, "ip", "green") == sco


@pytest.mark.parametrize(
    "value, ok",
    [
        ("http://c2.example.com/a?b=1", True),
        ("https://Example.com", True),
        ("ftp://files.example.net/x", True),
        ("hxxp://defanged.example", False),
        ("javascript:alert(1)", False),
        ("http://", False),
        ("http://exa mple.com/", False),
        ("http://example.com/\x00", False),
        ("http://example.com/a b", False),
        ("not a url", False),
        ("http://user@", False),
        ("http://:80/path", False),
        ("http://example.com:notaport/", False),
        ("http://example.com:99999/", False),
        ("http://example.com:0/", False),
        ("http://example.com:8080/x", True),
        ("http://user:pw@example.com/", True),
        ("http://[2001:db8::1]:8443/", True),
        ("http://10.0.0.1/", True),
        pytest.param("http://" + "a" * 2100 + ".com", False, id="overlong"),
    ],
)
def test_make_url_accepts_only_well_formed_urls(value, ok):
    sco = make_url(value, tlp="green")
    assert (sco is not None) is ok
    assert (network_observable_for(value, "url", "green") is not None) is ok


def test_make_domain_lowercases_so_one_domain_is_one_object():
    upper, lower = make_domain("MX1.Example.COM"), make_domain("mx1.example.com")
    assert upper == lower
    assert upper["value"] == "mx1.example.com"


def test_file_id_is_anchored_to_sha256_whatever_other_hashes_are_known():
    bare = make_file_by_sha256("a" * 64)
    full = make_file_by_sha256("a" * 64, sha1="c" * 40, md5="b" * 32)
    assert bare["id"] == full["id"] == stix2.File(hashes={"SHA-256": "a" * 64}).id
    assert full["hashes"] == {"SHA-256": "a" * 64, "SHA-1": "c" * 40, "MD5": "b" * 32}


def test_grouping_created_matches_the_id_inputs():
    created = "2026-05-06T01:02:03.456789+00:00"
    grouping = make_grouping("G", ["file--x"], created, context="malware-analysis")
    assert grouping["created"] == created
    assert grouping["id"] == Grouping.generate_id(
        "G", "malware-analysis", grouping["created"]
    )


def test_asset_identity_is_keyed_by_its_stable_token():
    named = make_identity_system("assets/A1", name="DESKTOP")
    renamed = make_identity_system("assets/A1", name="LAPTOP")
    unnamed = make_identity_system("assets/A1")
    other = make_identity_system("assets/B2", name="DESKTOP")
    # A rename, or a response without the name, keeps one identity per asset;
    # two assets sharing a display name stay distinct.
    assert named["id"] == renamed["id"] == unnamed["id"] != other["id"]
    assert named["id"] == Identity.generate_id("assets/A1", "system")
    assert named["name"] == "assets/A1"
    # OpenCTI also deduplicates identities by alias, so a display name shared
    # by two hosts must not be one; it is kept in the description instead.
    assert "x_opencti_aliases" not in named and "x_opencti_aliases" not in other
    assert "DESKTOP" in named["description"]
    assert "description" not in unnamed
    assert make_identity_system("assets/A1", "DESKTOP", "given")["description"] == (
        "given"
    )


@pytest.mark.parametrize(
    "value, want",
    [
        ("mx.example.com", "mx.example.com"),
        ("MX.Example.COM.", "mx.example.com"),
        ("_sip._tcp.example.com", "_sip._tcp.example.com"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("10 mx.example.com", None),
        ("exa mple.com", None),
        ("-bad.example.com", None),
        ("bad-.example.com", None),
        ("a" * 64 + ".example.com", None),
        ("example..com", None),
        ("localhost", None),
        ("", None),
        pytest.param("a." * 130 + "com", None, id="overlong"),
    ],
)
def test_make_domain_validates_and_normalises(value, want):
    sco = make_domain(value, tlp="green")
    assert (sco and sco["value"]) == want
    assert network_observable_for(value, "hostname", "green") == sco


def test_make_sighting_accepts_any_iterable_of_refs():
    kwargs = dict(first_seen="2026-01-01T00:00:00Z", last_seen="2026-01-01T00:00:00Z")
    from_list = make_sighting("file--1", ["identity--a"], count=1, **kwargs)
    from_iter = make_sighting("file--1", iter(["identity--a"]), count=1, **kwargs)
    assert from_iter["where_sighted_refs"] == ["identity--a"]
    assert from_iter["id"] == from_list["id"]
