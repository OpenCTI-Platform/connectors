"""Tests for the malware family name classifier."""

import json
from pathlib import Path

import pytest
from connector.family_names import is_malware_family_name

# Real family names seen in live hunting hits and in the recorded feed.
REAL = [
    "Copak",
    "Sdum",
    "Satan",
    "Synaptics",
    "Impacket",
    "AsyncRat",
    "Socks",
    "VBClone",
    "Mole",
    "Outbreak",
    "EICAR",
    "AgentTesla",
    "CobaltStrike",
    "XWorm",
    "LummaC2",
    "Mimikatz",
    "Emotet",
    "Qakbot",
]

# Engine label style names. The first five were measured in live hunting hits.
LABELS = [
    "Trojan.Packed2",
    "PUA.Generic",
    "Trojan.JS.Agent",
    "Phishing.HTML.Doc",
    "HkcAURkA",
    "Trojan",
    "Agent",
    "Generic",
    "GenericKD",
    "Heur.Suspicious",
    "Win32/Agent",
    "Trojan:Win32/Wacatac",
    "Backdoor[Gen]",
    "Gen",
    "Adware",
    "Riskware",
    "Unknown",
    "malware",
    "Variant",
    "Packed",
    "TrojanDownloader",
    "Win64 Trojan",
    "xkqzvtplw",
    "aBcDeFgH",
    "c0d3x9z2b1",
    "",
    "   ",
    "abc",
]


@pytest.mark.parametrize("name", REAL)
def test_real_family_names_are_accepted(name):
    assert is_malware_family_name(name)


@pytest.mark.parametrize("name", LABELS)
def test_engine_labels_are_rejected(name):
    assert not is_malware_family_name(name)


@pytest.mark.parametrize("value", [None, 123, 4.5, ["Copak"], {"a": 1}])
def test_non_text_is_rejected(value):
    assert not is_malware_family_name(value)


def test_surrounding_whitespace_is_ignored():
    assert is_malware_family_name("  Copak ")


def test_very_long_names_are_rejected():
    assert not is_malware_family_name("Copak" * 20)


def test_family_names_in_fixtures_are_accepted():
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    names = set()
    for path in fixtures.glob("taxii_objects_*_page*.json"):
        for bundle in json.loads(path.read_text()).get("objects", []):
            for obj in bundle["objects"]:
                if obj["type"] == "malware":
                    names.add(obj["name"])
    assert {"Socks", "VBClone", "Mole", "AsyncRat", "Outbreak"} <= names
    assert all(is_malware_family_name(name) for name in names)
