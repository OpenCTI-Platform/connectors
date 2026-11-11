import json

import pytest
import stix2
from connector.stix_builder import (
    STAIRWELL_IDENTITY_ID,
    make_domain,
    make_external_reference,
    make_file_by_sha256,
    make_grouping,
    make_indicator,
    make_ip,
    make_ipv4,
    make_ipv6,
    make_note,
    make_relationship,
    make_report,
    make_url,
    stairwell_identity,
    tlp_marking,
    valid_hash,
    with_markings,
)
from connectors_sdk.models import TLPMarking
from pycti import (
    Grouping,
    Identity,
    Indicator,
    Note,
    StixCoreRelationship,
)


def test_sdo_and_sro_ids_are_opencti_canonical():
    """Every SDO/SRO ID is the one pycti generates for that object."""
    rel = make_relationship(
        "file--cda9dbca-d6ff-5c9f-b701-a9f1c371022b",
        "ipv4-addr--68c179b6-d6cc-50dd-935b-1cd97ad84288",
        "related-to",
    )
    assert rel["id"] == StixCoreRelationship.generate_id(
        "related-to",
        "file--cda9dbca-d6ff-5c9f-b701-a9f1c371022b",
        "ipv4-addr--68c179b6-d6cc-50dd-935b-1cd97ad84288",
    )
    note = make_note(
        "Abstract", "body", ["file--cda9dbca-d6ff-5c9f-b701-a9f1c371022b"], "green"
    )
    assert note["id"] == Note.generate_id(None, "body", "Abstract")
    pattern = "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"
    assert make_indicator(pattern, "n", "2026-01-01T00:00:00.000Z")["id"] == (
        Indicator.generate_id(pattern)
    )
    assert STAIRWELL_IDENTITY_ID == Identity.generate_id("Stairwell", "organization")
    author = stairwell_identity()
    assert author["id"] == STAIRWELL_IDENTITY_ID
    assert author["created"] == author["modified"] == "2026-01-01T00:00:00.000Z"
    created = "2026-05-06T01:02:03.456789+00:00"
    grouping = make_grouping(
        "G",
        ["file--cda9dbca-d6ff-5c9f-b701-a9f1c371022b"],
        created,
        context="malware-analysis",
    )
    assert grouping["id"] == Grouping.generate_id("G", "malware-analysis", created)
    # The SDK's report ID derives from the name and publication date.
    report = make_report(
        "R", ["file--cda9dbca-d6ff-5c9f-b701-a9f1c371022b"], "2026-05-06T00:00:00.000Z"
    )
    again = make_report("R", [], "2026-05-06T00:00:00.000Z")
    later = make_report("R", [], "2026-05-07T00:00:00.000Z")
    assert report["id"] == again["id"] != later["id"]


def test_sco_ids_follow_the_stix_spec():
    """SCO IDs match what the stix2 library derives from the same properties."""
    assert make_ipv4("8.8.8.8")["id"] == stix2.IPv4Address(value="8.8.8.8").id
    assert make_ipv6("2001:db8::1")["id"] == stix2.IPv6Address(value="2001:db8::1").id
    assert make_domain("evil.com")["id"] == stix2.DomainName(value="evil.com").id
    assert (
        make_url("http://evil.com/x")["id"] == stix2.URL(value="http://evil.com/x").id
    )
    sco = make_file_by_sha256("a" * 64, md5="b" * 32)
    assert sco["id"] == stix2.File(hashes={"SHA-256": "a" * 64}).id


@pytest.mark.parametrize(
    "level", ["clear", "white", "green", "amber", "amber+strict", "red"]
)
def test_tlp_ids_are_the_sdk_marking_definitions(level):
    sdk = json.loads(TLPMarking(level=level).to_stix2_object().serialize())
    assert tlp_marking(level) == sdk["id"]


def test_bundle_carries_the_marking_definitions_its_objects_reference():
    objects = with_markings(
        [make_ipv4("8.8.8.8", tlp="green"), make_domain("a.example", tlp="red")]
    )
    markings = {o["id"] for o in objects if o["type"] == "marking-definition"}
    assert markings == {tlp_marking("green"), tlp_marking("red")}


def test_tlp_clear_uses_the_standard_stix_marking_id():
    assert (
        tlp_marking("clear")
        == "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    )


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


def test_make_relationship_deterministic_id():
    a = make_relationship(
        "file--cda9dbca-d6ff-5c9f-b701-a9f1c371022b",
        "ipv4-addr--68c179b6-d6cc-50dd-935b-1cd97ad84288",
    )
    b = make_relationship(
        "file--cda9dbca-d6ff-5c9f-b701-a9f1c371022b",
        "ipv4-addr--68c179b6-d6cc-50dd-935b-1cd97ad84288",
    )
    assert a["id"] == b["id"]
    assert a["relationship_type"] == "related-to"


def test_make_note_includes_object_refs_and_tlp():
    note = make_note(
        abstract="Test",
        content="body",
        object_refs=["file--cda9dbca-d6ff-5c9f-b701-a9f1c371022b"],
        tlp="green",
    )
    assert note["type"] == "note"
    assert note["object_refs"] == ["file--cda9dbca-d6ff-5c9f-b701-a9f1c371022b"]
    assert note["object_marking_refs"] == [tlp_marking("green")]


def test_make_external_reference():
    ref = make_external_reference("Stairwell", "https://app.stairwell.com/x", "desc")
    assert ref == {
        "source_name": "Stairwell",
        "url": "https://app.stairwell.com/x",
        "description": "desc",
    }
    assert make_external_reference("Stairwell", "https://x.example") == {
        "source_name": "Stairwell",
        "url": "https://x.example",
    }


def test_indicator_accepts_nanosecond_api_timestamps():
    pattern = "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"
    indicator = make_indicator(
        pattern,
        "n",
        "2025-04-29T19:42:30.534916301Z",
        valid_until="2025-07-28T19:42:30.534916301+00:00",
    )
    assert indicator["valid_from"] == "2025-04-29T19:42:30.534916Z"
    assert indicator["valid_until"] == "2025-07-28T19:42:30.534916Z"


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
        ("2606:4700:4700::1111", "ipv6-addr", "2606:4700:4700::1111"),
        ("2606:4700:4700:0::1111", "ipv6-addr", "2606:4700:4700::1111"),
        ("1.2.3.4:80", None, None),
        # Addresses that are not publicly routable say nothing about a file
        # or a domain: strings in malware and sinkholed DNS answers are full
        # of them.
        ("127.0.0.1", None, None),
        ("0.0.0.0", None, None),
        ("224.0.0.1", None, None),
        ("239.255.255.250", None, None),
        ("ff02::1", None, None),
        ("fec0::1", None, None),
        ("4000::1", None, None),
        ("3fff::1", None, None),
        ("::ffff:8.8.8.8", None, None),
        ("10.1.2.3", None, None),
        ("192.168.0.1", None, None),
        ("169.254.1.1", None, None),
        ("::1", None, None),
        ("fe80::1", None, None),
        ("2001:db8::1", None, None),
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
    grouping = make_grouping(
        "G",
        ["file--cda9dbca-d6ff-5c9f-b701-a9f1c371022b"],
        created,
        context="malware-analysis",
    )
    assert grouping["created"] == created
    assert grouping["id"] == Grouping.generate_id(
        "G", "malware-analysis", grouping["created"]
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
        # Dotted strings from file contents that are not host names: an
        # address, a version number, a file name.
        ("1.2.3.4", None),
        ("0.0.0.0", None),
        ("6.1.7601", None),
        ("kernel32.dll", None),
        ("readme.txt", None),
        ("invoice.pdf", None),
        ("svchost.exe", None),
        ("example.123", None),
        ("example.c_m", None),
        ("example.xn--p1ai", "example.xn--p1ai"),
        pytest.param("a." * 130 + "com", None, id="overlong"),
    ],
)
def test_make_domain_validates_and_normalises(value, want):
    sco = make_domain(value, tlp="green")
    assert (sco and sco["value"]) == want
