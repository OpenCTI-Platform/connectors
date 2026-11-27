"""Tests for the infrastructure relationships of IOC delta entries (GTI_INDICATOR_INFRASTRUCTURE)."""

import logging
from typing import Any
from unittest.mock import MagicMock

import pytest
from connector.src.custom.convert_to_stix.indicator.convert_to_stix_indicator import (
    ConvertToSTIXIndicator,
)
from connector.src.custom.mappers.gti_iocs.ioc_infrastructure import (
    ALLOWED_INFRASTRUCTURE_CATEGORIES,
    INFRASTRUCTURE_RULES,
    related_value,
)
from connector.src.custom.models.gti.gti_ioc_delta_model import IOCDeltaRelationshipData

DOMAIN = "evil-cdn.com"
IP = "185.0.2.10"
SHA256 = "a" * 64


def _rule(ioc_type: str, field: str) -> Any:
    return next(
        rule
        for rule in INFRASTRUCTURE_RULES
        if rule.ioc_type == ioc_type and rule.field == field
    )


def _converter(
    categories: list[str], limit: int = 10, descriptions: bool = True
) -> ConvertToSTIXIndicator:
    config = MagicMock(
        relationship_descriptions=descriptions,
        indicator_min_score=None,
        indicator_require_malware_family=False,
        indicator_require_threat_actor=False,
        indicator_min_verdict="any",
        indicator_scoring="threat_score",
        extended_descriptions=False,
        ioc_tags_as_labels=False,
        indicator_subentities=[],
        indicator_infrastructure=categories,
        indicator_infrastructure_limit=limit,
    )
    return ConvertToSTIXIndicator(
        config=config, logger=logging.getLogger(__name__), tlp_level="white"
    )


def _items(*ids: str) -> list[dict[str, str]]:
    return [{"type": "item", "id": item_id} for item_id in ids]


def _relationships(objects: list[Any]) -> list[Any]:
    return [
        obj
        for obj in objects
        if obj.type == "relationship" and obj.relationship_type != "indicates"
    ]


@pytest.mark.parametrize(
    "ioc_type, field, ioc_value, item_id, expected",
    [
        ("domain", "resolutions", DOMAIN, f"{IP}{DOMAIN}", IP),
        ("ip_address", "resolutions", IP, f"{IP}{DOMAIN}", DOMAIN),
        ("domain", "resolutions", DOMAIN, f"{IP}other.com", None),
        ("domain", "subdomains", DOMAIN, f"www.{DOMAIN}", f"www.{DOMAIN}"),
        ("domain", "subdomains", DOMAIN, IP, None),
        ("domain", "downloaded_files", DOMAIN, SHA256, SHA256),
        ("domain", "downloaded_files", DOMAIN, "not-a-hash", None),
        ("file", "contacted_ips", SHA256, "2001:db8::1", "2001:db8::1"),
        ("file", "contacted_ips", SHA256, "999.1.1.1", None),
    ],
)
def test_related_value(
    ioc_type: str, field: str, ioc_value: str, item_id: str, expected: str | None
) -> None:
    """Descriptor IDs give the related value, invalid ones are rejected."""
    # Given a rule and a GTI descriptor ID
    # When the related value is extracted
    # Then it matches the expected observable value
    assert (  # noqa: S101
        related_value(_rule(ioc_type, field), ioc_value, item_id) == expected
    )


def test_to_one_relationship_is_a_list() -> None:
    """A to-one relationship (an object) or missing data parse as a list."""
    # Given GTI relationship data in its various shapes
    # When it is parsed
    # Then data is always a list
    assert len(IOCDeltaRelationshipData(data={"id": IP}).data) == 1  # noqa: S101
    assert IOCDeltaRelationshipData(data=None).data == []  # noqa: S101


def test_domain_resolutions_and_files() -> None:
    """A domain entry is linked to its resolutions and downloaded files, with reasons."""
    # Given a domain entry with resolutions and downloaded files
    converter = _converter(["resolutions", "downloaded"])
    entry = {
        "id": DOMAIN,
        "type": "domain",
        "attributes": {},
        "relationships": {
            "resolutions": {"data": _items(f"{IP}{DOMAIN}")},
            "downloaded_files": {"data": _items(SHA256)},
            "subdomains": {"data": _items(f"www.{DOMAIN}")},
        },
    }
    # When it is converted
    objects = converter.convert(entry)
    # Then the domain observable resolves to the IP and is related to the file
    domain = next(obj for obj in objects if obj.type == "domain-name")
    ip = next(obj for obj in objects if obj.type == "ipv4-addr")
    file = next(obj for obj in objects if obj.type == "file")
    resolves_to, related_to = _relationships(objects)
    assert (resolves_to.relationship_type, resolves_to.source_ref) == (  # noqa: S101
        "resolves-to",
        domain.id,
    )
    assert resolves_to.target_ref == ip.id  # noqa: S101
    assert resolves_to.description == (  # noqa: S101
        f"Stated by GTI: GTI lists a DNS resolution of the domain {DOMAIN} to {IP}."
    )
    assert related_to.target_ref == file.id  # noqa: S101
    assert related_to.description == (  # noqa: S101
        f"Stated by GTI: GTI lists the file {SHA256} as downloaded from {DOMAIN}."
    )
    # And disabled categories are ignored
    assert f"www.{DOMAIN}" not in [
        getattr(o, "value", None) for o in objects
    ]  # noqa: S101


def test_file_communicating_direction() -> None:
    """Files communicating with an IP are the source of the relationship."""
    # Given an IP entry with a communicating file
    converter = _converter(["communicating"])
    entry = {
        "id": IP,
        "type": "ip_address",
        "attributes": {},
        "relationships": {"communicating_files": {"data": _items(SHA256)}},
    }
    # When it is converted
    objects = converter.convert(entry)
    # Then the file is the source
    file = next(obj for obj in objects if obj.type == "file")
    (relationship,) = _relationships(objects)
    assert relationship.source_ref == file.id  # noqa: S101


def test_url_last_serving_ip() -> None:
    """A URL entry is linked to the IP that last served it, a to-one relationship."""
    # Given a URL entry with its last serving IP
    converter = _converter(["serving_ip"])
    entry = {
        "id": "url-id",
        "type": "url",
        "attributes": {"url": "http://evil-cdn.com/gate.php"},
        "relationships": {"last_serving_ip_address": {"data": {"id": IP}}},
    }
    # When it is converted
    objects = converter.convert(entry)
    # Then the URL observable is related to the IP
    url = next(obj for obj in objects if obj.type == "url")
    (relationship,) = _relationships(objects)
    assert relationship.source_ref == url.id  # noqa: S101


def test_limit_and_duplicates() -> None:
    """Each list is deduplicated, then capped."""
    # Given a file entry with repeated and many contacted domains
    converter = _converter(["contacted"], limit=2)
    entry = {
        "id": SHA256,
        "type": "file",
        "attributes": {"sha256": SHA256},
        "relationships": {
            "contacted_domains": {
                "data": _items("a.example", "a.example", "b.example", "c.example")
            }
        },
    }
    # When it is converted
    objects = converter.convert(entry)
    # Then two distinct domains are linked
    domains = [obj.value for obj in objects if obj.type == "domain-name"]
    assert domains == ["a.example", "b.example"]  # noqa: S101


def test_disabled_by_default() -> None:
    """Without categories, entries are converted as before."""
    # Given a domain entry with resolutions and no category enabled
    converter = _converter([])
    entry = {
        "id": DOMAIN,
        "type": "domain",
        "attributes": {},
        "relationships": {"resolutions": {"data": _items(f"{IP}{DOMAIN}")}},
    }
    # When it is converted
    # Then only the indicator is produced
    assert [obj.type for obj in converter.convert(entry)] == ["indicator"]  # noqa: S101


def test_no_description_by_default() -> None:
    """Without GTI_RELATIONSHIP_DESCRIPTIONS, the relationships have no description."""
    # Given a converter without relationship descriptions
    converter = _converter(["resolutions"], descriptions=False)
    entry = {
        "id": DOMAIN,
        "type": "domain",
        "attributes": {},
        "relationships": {"resolutions": {"data": _items(f"{IP}{DOMAIN}")}},
    }
    # When it is converted
    (relationship,) = _relationships(converter.convert(entry))
    # Then the relationship has no description
    assert relationship.get("description") is None  # noqa: S101


def test_every_category_has_a_rule() -> None:
    """The allowed categories and the rules cannot drift apart."""
    # Given the categories declared for GTI_INDICATOR_INFRASTRUCTURE
    # When the categories of the rules are collected
    rule_categories = {rule.category for rule in INFRASTRUCTURE_RULES}
    # Then every allowed category enables at least one rule, and no rule uses another
    assert rule_categories == set(ALLOWED_INFRASTRUCTURE_CATEGORIES)  # noqa: S101
