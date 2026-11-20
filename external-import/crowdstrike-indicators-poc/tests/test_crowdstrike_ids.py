"""Tests for the deterministic ids derived from CrowdStrike data."""

import uuid

from crowdstrike_indicators.entities.ids import (
    CROWDSTRIKE_NAMESPACE,
    bundle_id,
    indicates_id,
    indicator_id,
    malware_id,
)
from crowdstrike_indicators.transform import create_indicator as transformer

INDICATOR_ID = "indicator--f975582d-ec64-5f6c-ac8c-1fdea0f69e0b"
MALWARE_ID = "malware--06d31b08-d590-5298-8440-23b86775f679"


def test_namespace_is_pinned():
    assert CROWDSTRIKE_NAMESPACE == uuid.UUID("772e62ec-40d9-5c7b-8696-73937645c55b")
    assert CROWDSTRIKE_NAMESPACE == uuid.uuid5(uuid.NAMESPACE_DNS, "crowdstrike.com")


def test_indicator_id_is_unchanged():
    assert indicator_id("domain_malicious-7.example") == INDICATOR_ID


def test_malware_id_is_pinned():
    assert malware_id("ExampleFamily4") == MALWARE_ID


def test_malware_id_is_case_sensitive():
    assert malware_id("QakBot") != malware_id("Qakbot")


def test_indicates_id_is_pinned():
    assert indicates_id(INDICATOR_ID, MALWARE_ID) == (
        "relationship--79f5eb30-3ca5-59fd-8d03-33e43f40bba6"
    )


def test_prefixes_keep_object_kinds_apart():
    name = "domain_malicious-7.example"
    assert malware_id(name).split("--")[1] != indicator_id(name).split("--")[1]


def test_moved_names_stay_importable_from_the_transformer():
    assert transformer.CROWDSTRIKE_NAMESPACE is CROWDSTRIKE_NAMESPACE
    assert transformer.indicator_id is indicator_id


def test_bundle_id_is_pinned():
    assert bundle_id(INDICATOR_ID) == "bundle--fe24cab3-d021-56f9-af58-867c5a0cdb23"
