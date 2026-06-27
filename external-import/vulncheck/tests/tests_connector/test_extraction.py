"""Per-source ingestion -> STIX conversion tests.

Each test feeds a minimal fake entity through a source's ``_extract_stix_from_*``
with a real ``ConverterToStix`` (mock helper) and asserts the emitted STIX
object/relationship types. This exercises the real conversion + create_* paths.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from connector.converter_to_stix import ConverterToStix
from connector.sources import (
    botnets,
    epss,
    exploits,
    initial_access,
    ipintel,
    nistnvd2,
    ransomware,
    snort,
    suricata,
    threat_actors,
    vckev,
    vcnvd2,
)
from connector.util import config as scope

CPE = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
LOG = MagicMock()


@pytest.fixture
def converter(helper):
    return ConverterToStix(helper)


def _types(objs):
    return [getattr(o, "type", None) or o["type"] for o in objs]


def _rel_types(objs):
    return [
        o.relationship_type for o in objs if getattr(o, "type", None) == "relationship"
    ]


def test_botnets(converter):
    entity = SimpleNamespace(
        botnet_name="Mirai", cve=["CVE-2024-0001"], date_added="2024-01-01T00:00:00"
    )
    objs = botnets._extract_stix_from_botnet(
        converter,
        [entity],
        [scope.SCOPE_INFRASTRUCTURE, scope.SCOPE_VULNERABILITY, scope.SCOPE_REPORT],
        LOG,
    )
    assert {"infrastructure", "vulnerability", "report"} <= set(_types(objs))
    assert "related-to" in _rel_types(objs)


def test_epss(converter):
    entity = SimpleNamespace(cve="CVE-2024-0001", epss_score=0.5, epss_percentile=0.9)
    objs = epss._extract_stix_from_epss(converter, [entity], LOG)
    assert _types(objs) == ["vulnerability"]


def test_exploits(converter):
    entity = SimpleNamespace(
        id="CVE-2024-0001",
        in_kev=True,
        epss=SimpleNamespace(epss_score=0.5, epss_percentile=0.9),
        exploits=[
            SimpleNamespace(
                url="http://e", name="poc", date_added="2024-01-01T00:00:00"
            )
        ],
    )
    objs = exploits._extract_stix_from_exploits(
        converter, [entity], [scope.SCOPE_VULNERABILITY, scope.SCOPE_MALWARE], LOG
    )
    assert {"vulnerability", "malware"} <= set(_types(objs))
    assert "exploits" in _rel_types(objs)


def test_initial_access(converter):
    entity = SimpleNamespace(cve="CVE-2024-0001", in_kev=True, vulnerable_cpes=[CPE])
    objs = initial_access._extract_stix_from_initial_access(
        converter, [entity], [scope.SCOPE_VULNERABILITY, scope.SCOPE_SOFTWARE], LOG
    )
    assert {"vulnerability", "software"} <= set(_types(objs))
    assert "has" in _rel_types(objs)


def test_ipintel(converter):
    entity = SimpleNamespace(
        ip="1.2.3.4",
        matches=["c2-name"],
        last_seen="2024-01-01T00:00:00",
        country="United States",
        country_code="US",
    )
    objs = ipintel._extract_stix_from_ipintel(
        converter,
        [entity],
        [scope.SCOPE_IP, scope.SCOPE_INFRASTRUCTURE, scope.SCOPE_LOCATION],
        LOG,
    )
    types = set(_types(objs))
    assert {"ipv4-addr", "infrastructure", "location"} <= types
    assert {"located-at", "consists-of"} <= set(_rel_types(objs))


def test_nistnvd2(converter):
    entity = SimpleNamespace(
        id="CVE-2024-0001",
        descriptions=[SimpleNamespace(lang="en", value="A description")],
        weaknesses=None,
        metrics=None,
        vc_vulnerable_cpes=[CPE],
    )
    objs = nistnvd2._extract_stix_from_nistnvd2(
        entity, [scope.SCOPE_VULNERABILITY, scope.SCOPE_SOFTWARE], converter, LOG
    )
    assert {"vulnerability", "software"} <= set(_types(objs))
    assert "has" in _rel_types(objs)


def test_ransomware(converter):
    entity = SimpleNamespace(
        ransomware_family="LockBit",
        cve=["CVE-2024-0001"],
        date_added="2024-01-01T00:00:00",
    )
    objs = ransomware._extract_stix_from_ransomware(
        converter,
        [entity],
        [scope.SCOPE_MALWARE, scope.SCOPE_VULNERABILITY, scope.SCOPE_REPORT],
        LOG,
    )
    assert {"malware", "vulnerability", "report"} <= set(_types(objs))
    assert "exploits" in _rel_types(objs)


@pytest.mark.parametrize("module", [snort, suricata])
def test_rules(converter, module):
    rule = SimpleNamespace(
        rule='alert tcp any any -> any any (msg:"x"; sid:1;)',
        name="rule-name",
        description="desc",
    )
    fn = getattr(module, f"_extract_stix_from_{module.__name__.split('.')[-1]}")
    objs = fn(converter, LOG, [rule])
    assert _types(objs) == ["indicator"]


def test_threat_actors(converter):
    entity = SimpleNamespace(
        threat_actor_name="APT-Test",
        cve_references=[SimpleNamespace(url="http://ref", cve=["CVE-2024-0001"])],
        date_added="2024-01-01T00:00:00",
        misp_threat_actor=SimpleNamespace(description="a description"),
    )
    objs = threat_actors._extract_stix_from_threat_actors(
        [entity],
        [
            scope.SCOPE_EXTERNAL_REF,
            scope.SCOPE_VULNERABILITY,
            scope.SCOPE_THREAT_ACTOR,
            scope.SCOPE_REPORT,
        ],
        converter,
        LOG,
    )
    assert {"threat-actor", "vulnerability", "report"} <= set(_types(objs))
    assert "targets" in _rel_types(objs)


def test_vckev(converter):
    entity = SimpleNamespace(cve=["CVE-2024-0001"])
    objs = vckev._extract_stix_from_vckev(converter, [entity], LOG)
    assert _types(objs) == ["vulnerability"]


def test_vcnvd2_full(converter):
    technique = SimpleNamespace(
        id="T1059",
        name="Command Execution",
        url="https://attack.mitre.org/techniques/T1059",
        mitigations=[
            SimpleNamespace(
                id="M1038", description="mitigation", mitigation_url="https://m"
            )
        ],
        detections=[
            SimpleNamespace(
                id="DS0017", datasource="Command", datacomponent="Command Execution"
            )
        ],
    )
    entity = SimpleNamespace(
        id="CVE-2024-0001",
        descriptions=[SimpleNamespace(lang="en", value="A description")],
        weaknesses=None,
        metrics=None,
        vc_vulnerable_cpes=[CPE],
        related_attack_patterns=[
            SimpleNamespace(
                capec_id="CAPEC-100", capec_name="Overflow", capec_url="https://capec"
            )
        ],
        mitre_attack_techniques=[technique],
    )
    objs = vcnvd2._extract_stix_from_vcnvd2(
        entity,
        [
            scope.SCOPE_VULNERABILITY,
            scope.SCOPE_SOFTWARE,
            scope.SCOPE_ATTACK_PATTERN,
            scope.SCOPE_COURSE_OF_ACTION,
            scope.SCOPE_DATA_SOURCE,
        ],
        converter,
        LOG,
    )
    types = set(_types(objs))
    assert {
        "vulnerability",
        "software",
        "attack-pattern",
        "course-of-action",
        "x-mitre-data-source",
    } <= types
    assert {"has", "targets", "mitigates", "related-to"} <= set(_rel_types(objs))


def test_scope_gating_skips_out_of_scope(converter):
    """Empty scope -> nothing emitted (representative)."""
    entity = SimpleNamespace(cve="CVE-2024-0001", in_kev=True, vulnerable_cpes=[CPE])
    objs = initial_access._extract_stix_from_initial_access(
        converter, [entity], [], LOG
    )
    assert objs == []
