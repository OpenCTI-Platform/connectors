"""Tests for `ShodanConnector._generate_stix_asn`.

Shodan returns the top-level `asn` field either as a prefixed string
(e.g. `"AS25569"`) or as an integer (e.g. `25569`), and it may be absent,
null, or malformed.
"""

from types import SimpleNamespace

import pytest
from connector import ShodanConnector

_AUTHOR_ID = "identity--f0d2ba5a-4d1f-5a7f-8ba6-1a4b1a5b6c7d"
_OBSERVABLE_ID = "ipv4-addr--0c3a1b6e-5ec2-5a19-9b17-2d5ee3d1c0f1"
_SCORE = 50


def _connector(*, use_isp_name_for_asn: bool = False) -> ShodanConnector:
    conn = object.__new__(ShodanConnector)
    conn.shodan_identity = SimpleNamespace(id=_AUTHOR_ID)
    conn.stix_objects = []
    conn.stix_entity = {"id": _OBSERVABLE_ID}
    conn.score = _SCORE
    conn.use_isp_name_for_asn = use_isp_name_for_asn
    return conn


def _asns(conn):
    return [obj for obj in conn.stix_objects if obj["type"] == "autonomous-system"]


def _relationships(conn):
    return [
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in conn.stix_objects
        if obj["type"] == "relationship"
    ]


@pytest.mark.parametrize(
    ("raw_asn", "expected_number", "expected_name"),
    [
        (25569, 25569, "AS25569"),
        ("AS123", 123, "AS123"),
        ("as123", 123, "AS123"),
        ("123", 123, "AS123"),
        ("  AS123  ", 123, "AS123"),
    ],
    ids=["int", "AS123", "as123", "123", "whitespace"],
)
def test_valid_asn_builds_autonomous_system_and_relationship(
    raw_asn, expected_number, expected_name
):
    conn = _connector()

    conn._generate_stix_asn({"asn": raw_asn, "isp": "Example ISP"})

    (asn,) = _asns(conn)
    assert asn["number"] == expected_number
    assert asn["name"] == expected_name
    assert asn["x_opencti_created_by_ref"] == _AUTHOR_ID
    assert asn["x_opencti_score"] == _SCORE
    assert _relationships(conn) == [(_OBSERVABLE_ID, "belongs-to", asn["id"])]


def test_use_isp_name_for_asn_uses_isp_field():
    conn = _connector(use_isp_name_for_asn=True)

    conn._generate_stix_asn({"asn": 25569, "isp": "Example ISP"})

    (asn,) = _asns(conn)
    assert asn["number"] == 25569
    assert asn["name"] == "Example ISP"
    assert _relationships(conn) == [(_OBSERVABLE_ID, "belongs-to", asn["id"])]


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"asn": None},
        {"asn": ""},
        {"asn": "   "},
        {"asn": "AS"},
        {"asn": True},
        {"asn": False},
        {"asn": "invalid"},
        {"asn": -123},
        {"asn": "-123"},
        {"asn": "AS-123"},
    ],
    ids=[
        "missing_key",
        "none",
        "empty",
        "whitespace_only",
        "bare_prefix",
        "bool_true",
        "bool_false",
        "invalid",
        "negative_int",
        "negative_str",
        "negative_prefixed_str",
    ],
)
def test_missing_or_invalid_asn_produces_nothing(data):
    conn = _connector()

    conn._generate_stix_asn(data)

    assert conn.stix_objects == []
