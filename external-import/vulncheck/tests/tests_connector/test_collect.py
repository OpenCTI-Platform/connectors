"""``collect_*`` orchestration tests: scope check -> iterate -> bundle -> finish.

These complement ``test_extraction`` (which exercises the ``_extract_*`` helpers)
by driving each source's public ``collect_*`` entry point with a mocked client
and ``works`` module, so the in-scope collection/bundling path is covered.
"""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import connector.util.works as works
import pytest
from connector.converter_to_stix import ConverterToStix
from connector.sources import (
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

CPE = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"

# A connector scope wide enough that every source finds an intersection.
ALL_SCOPES = [
    "vulnerability",
    "malware",
    "threat-actor",
    "software",
    "infrastructure",
    "location",
    "ip-addr",
    "indicator",
    "external-reference",
    "attack-pattern",
    "course-of-action",
    "x-mitre-data-source",
    "report",
]

SNORT_RULE = 'alert tcp any any -> any any (msg:"VULNCHECK Test Rule"; sid:1000001;)\n'


def _config(scope=None):
    return SimpleNamespace(
        connector=SimpleNamespace(scope=scope if scope is not None else ALL_SCOPES),
        vulncheck=SimpleNamespace(
            nvd2_last_mod_start_date=None,
            nvd2_last_mod_end_date=None,
            nvd2_pull_history=False,
            nvd2_max_date_range=timedelta(days=120),
        ),
    )


@pytest.fixture
def sent(monkeypatch):
    """Capture bundles sent via works.send_bundle; stub start/finish work."""
    captured = []
    monkeypatch.setattr(works, "start_work", lambda **kw: "work-1")
    monkeypatch.setattr(works, "finish_work", lambda **kw: None)
    monkeypatch.setattr(
        works, "send_bundle", lambda **kw: captured.append(kw["stix_objects"])
    )
    return captured


# (collect_fn, client iter attr, fake entity)
ITER_CASES = [
    (
        epss.collect_epss,
        "iter_epss",
        SimpleNamespace(cve="CVE-2024-0001", epss_score=0.5, epss_percentile=0.9),
    ),
    (
        exploits.collect_exploits,
        "iter_exploits",
        SimpleNamespace(
            id="CVE-2024-0001",
            in_kev=True,
            epss=SimpleNamespace(epss_score=0.5, epss_percentile=0.9),
            exploits=[
                SimpleNamespace(
                    url="http://e", name="poc", date_added="2024-01-01T00:00:00"
                )
            ],
        ),
    ),
    (
        initial_access.collect_initial_access,
        "iter_initial_access",
        SimpleNamespace(cve="CVE-2024-0001", in_kev=True, vulnerable_cpes=[CPE]),
    ),
    (
        ipintel.collect_ipintel,
        "iter_ipintel",
        SimpleNamespace(
            ip="1.2.3.4",
            matches=["c2-name"],
            last_seen="2024-01-01T00:00:00",
            country="United States",
            country_code="US",
        ),
    ),
    (
        ransomware.collect_ransomware,
        "iter_ransomware",
        SimpleNamespace(
            ransomware_family="LockBit",
            cve=["CVE-2024-0001"],
            date_added="2024-01-01T00:00:00",
        ),
    ),
    (
        vckev.collect_vckev,
        "iter_vckev",
        SimpleNamespace(cve=["CVE-2024-0001"]),
    ),
    (
        threat_actors.collect_threat_actors,
        "iter_threat_actors",
        SimpleNamespace(
            threat_actor_name="APT-Test",
            cve_references=[SimpleNamespace(url="http://ref", cve=["CVE-2024-0001"])],
            date_added="2024-01-01T00:00:00",
            misp_threat_actor=SimpleNamespace(description="a description"),
        ),
    ),
]


@pytest.mark.parametrize(
    "collect_fn,attr,entity", ITER_CASES, ids=[c[1] for c in ITER_CASES]
)
def test_collect_iter_sources(collect_fn, attr, entity, helper, sent):
    client = MagicMock()
    getattr(client, attr).return_value = [[entity]]

    collect_fn(_config(), helper, client, ConverterToStix(helper), MagicMock(), {})

    assert sent, f"{collect_fn.__name__} should send a bundle when in scope"


NVD2_CASES = [
    (nistnvd2.collect_nistnvd2, "iter_nistnvd2"),
    (vcnvd2.collect_vcnvd2, "iter_vcnvd2"),
]


@pytest.mark.parametrize("collect_fn,attr", NVD2_CASES, ids=[c[1] for c in NVD2_CASES])
def test_collect_nvd2_sources(collect_fn, attr, helper, sent):
    entity = SimpleNamespace(
        id="CVE-2024-0001",
        descriptions=[SimpleNamespace(lang="en", value="A description")],
        weaknesses=None,
        metrics=None,
        vc_vulnerable_cpes=[CPE],
        related_attack_patterns=None,
        mitre_attack_techniques=None,
    )
    client = MagicMock()
    getattr(client, attr).return_value = [[entity]]

    collect_fn(_config(), helper, client, ConverterToStix(helper), MagicMock(), {})

    assert sent, f"{collect_fn.__name__} should send a bundle when in scope"


@pytest.mark.parametrize(
    "collect_fn,rule_type",
    [(snort.collect_snort, "snort"), (suricata.collect_suricata, "suricata")],
)
def test_collect_rule_sources(collect_fn, rule_type, helper, sent):
    client = MagicMock()
    client.get_rules.return_value = SNORT_RULE

    collect_fn(_config(), helper, client, ConverterToStix(helper), MagicMock(), {})

    client.get_rules.assert_called_once_with(rule_type)
    assert sent, f"{collect_fn.__name__} should send a bundle when in scope"


def test_collect_skips_when_out_of_scope(helper, sent):
    """A connector scope sharing nothing with the source scope -> no work, no calls."""
    client = MagicMock()

    epss.collect_epss(
        _config(scope=["malware"]),
        helper,
        client,
        ConverterToStix(helper),
        MagicMock(),
        {},
    )

    client.iter_epss.assert_not_called()
    assert not sent
