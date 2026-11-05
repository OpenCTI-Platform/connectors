from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from adapters.adapter import DataToSTIXAdapter
from connector.settings import ConfigConnector


def _adapter(
    collection: str, *, is_ioc: bool = False, tlp_color: str = "amber"
) -> DataToSTIXAdapter:
    helper = SimpleNamespace(connector_logger=MagicMock())
    return DataToSTIXAdapter(
        mitre_mapper={},
        collection=collection,
        tlp_color=tlp_color,
        helper=helper,
        is_ioc=is_ioc,
        threat_actor_name=None,
        config=ConfigConnector(),
    )


def _assert_bundle(out):
    """Common bundle sanity check."""
    assert isinstance(out, list)
    assert len(out) > 0


# --- darkweb/forums ----------------------------------------------------------


class TestDarkwebForumsHandler:
    def test_emits_user_account_and_note(self):
        a = _adapter("darkweb/forums")
        event = {
            "forum_post": {
                "id": "post-1",
                "title": "Selling DBs",
                "nickname": "user_alpha",
                "forum": "forum.example.com",
                "categories": ["leaks"],
                "langs": ["en"],
                "description": "Post body content",
            }
        }
        out = a.generate_darkweb_forums(
            event=event,
            json_date_obj={"date-published": "2024-01-01T00:00:00Z"},
            json_eval_obj={"reliability": "B"},
        )
        _assert_bundle(out)
        # User-Account + Note + author Identity + marking at minimum.
        types = {getattr(o, "type", "") for o in out}
        assert "user-account" in types
        assert "note" in types

    def test_handles_post_without_nickname(self):
        # No author → Note still emitted, no User-Account.
        a = _adapter("darkweb/forums")
        out = a.generate_darkweb_forums(
            event={"forum_post": {"id": "post-1", "title": "x"}},
            json_date_obj={},
            json_eval_obj={},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "user-account" not in types
        assert "note" in types


# --- attacks/deface ----------------------------------------------------------


class TestAttacksDefaceHandler:
    def test_creates_incident_and_observables(self):
        a = _adapter("attacks/deface")
        out = a.generate_attacks_deface(
            event={
                "deface": {
                    "id": "def-1",
                    "target_domain": "victim.example.com",
                    "site_url": "https://victim.example.com",
                    "target_ip": {"ip": "192.0.2.1", "country_code": "US"},
                    "threat_actor": {"name": "Zalim", "id": "ta-1"},
                }
            },
            json_date_obj={"detection-date": "2024-01-01T00:00:00Z"},
            json_eval_obj={"severity": "amber"},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "incident" in types
        assert "domain-name" in types
        assert "url" in types

        # Domain-Name --resolves-to--> IP-Addr must be emitted exactly once
        # with the STIX 2.1 canonical direction (domain is the source).
        by_id = {o.id: o for o in out if hasattr(o, "id")}
        resolves = [
            o
            for o in out
            if getattr(o, "type", "") == "relationship"
            and getattr(o, "relationship_type", "") == "resolves-to"
        ]
        assert len(resolves) == 1
        rel = resolves[0]
        assert by_id[rel.source_ref].type == "domain-name"
        assert by_id[rel.target_ref].type == "ipv4-addr"

    def test_target_domain_carrying_ip_creates_no_resolves_to(self):
        # When target_domain is actually an IP it is reclassified to an IP
        # observable in _emit_attack_observable; there is no domain-name
        # left to resolve, so no resolves-to SRO must be emitted.
        a = _adapter("attacks/deface")
        out = a.generate_attacks_deface(
            event={
                "deface": {
                    "id": "def-2",
                    "target_domain": "192.0.2.9",
                    "target_ip": {"ip": "192.0.2.1"},
                }
            },
            json_date_obj={},
            json_eval_obj={},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "domain-name" not in types
        assert not [
            o
            for o in out
            if getattr(o, "type", "") == "relationship"
            and getattr(o, "relationship_type", "") == "resolves-to"
        ]

    def test_skip_when_no_observables(self):
        # Empty target + actor → nothing to emit.
        a = _adapter("attacks/deface")
        out = a.generate_attacks_deface(
            event={"deface": {"id": "x"}},
            json_date_obj={},
            json_eval_obj={},
        )
        assert out == []


# --- attacks/ddos ------------------------------------------------------------


class TestAttacksDdosHandler:
    def test_creates_incident_and_cnc_indicators(self):
        a = _adapter("attacks/ddos")
        out = a.generate_attacks_ddos(
            event={
                "ddos": {
                    "id": "ddos-1",
                    "target": {
                        # Handler reads target/cnc ``ip`` (not ``ipv4``).
                        "domain": "victim.example.com",
                        "ip": "192.0.2.1",
                        "country_code": "US",
                    },
                    "cnc": {
                        "domain": "c2.example.com",
                        "ip": "192.0.2.2",
                        "country_code": "RU",
                    },
                    "malware": {"name": "MalwareDelta"},
                }
            },
            json_date_obj={
                "submission-time": "2024-01-01T00:00:00Z",
                "takedown-time": "2024-01-02T00:00:00Z",
            },
            json_eval_obj={"severity": "amber"},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "incident" in types
        # MalwareDelta malware SDO emitted.
        assert "malware" in types
        # CnC domain/ip are IOCs (cnc_as_indicator defaults True) → Indicator.
        assert "indicator" in types

        # Domain-Name --resolves-to--> IP-Addr must appear for BOTH sides
        # (target victim domain + cnc attacker domain), each with the STIX
        # 2.1 canonical direction (source=domain, target=ipv4-addr).
        by_id = {o.id: o for o in out if hasattr(o, "id")}
        resolves = [
            o
            for o in out
            if getattr(o, "type", "") == "relationship"
            and getattr(o, "relationship_type", "") == "resolves-to"
        ]
        assert len(resolves) == 2
        pairs = {
            (by_id[r.source_ref].value, by_id[r.target_ref].value) for r in resolves
        }
        assert ("victim.example.com", "192.0.2.1") in pairs
        assert ("c2.example.com", "192.0.2.2") in pairs
        for rel in resolves:
            assert by_id[rel.source_ref].type == "domain-name"
            assert by_id[rel.target_ref].type in {"ipv4-addr", "ipv6-addr"}

    def test_no_resolves_to_when_side_lacks_domain(self):
        # target side has only IP; cnc side has only IP → no resolves-to.
        a = _adapter("attacks/ddos")
        out = a.generate_attacks_ddos(
            event={
                "ddos": {
                    "id": "ddos-2",
                    "target": {"ip": "192.0.2.1"},
                    "cnc": {"ip": "192.0.2.2"},
                }
            },
            json_date_obj={"submission-time": "2024-01-01T00:00:00Z"},
            json_eval_obj={},
        )
        _assert_bundle(out)
        assert not [
            o
            for o in out
            if getattr(o, "type", "") == "relationship"
            and getattr(o, "relationship_type", "") == "resolves-to"
        ]


# --- attacks/phishing_group --------------------------------------------------


class TestAttacksPhishingGroupHandler:
    def test_emits_brand_identity_and_observables(self):
        a = _adapter("attacks/phishing_group")
        out = a.generate_attacks_phishing_group(
            event={
                "phishing_group": {
                    "id": "pg-1",
                    "brand": "ExampleCorp",
                    "domain": "phishing.example.com",
                    "ip_list": [{"ip": "192.0.2.1", "country_code": "US"}],
                    # Handler iterates ``phishing_list`` rows.
                    "phishing_list": [
                        {
                            "url": "https://phishing.example.com/login",
                            "domain": {"domain": "phishing.example.com"},
                        }
                    ],
                }
            },
            json_date_obj={"submission-time": "2024-01-01T00:00:00Z"},
            json_eval_obj={},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        # Phishing domain + brand identity + Note.
        assert "domain-name" in types
        assert "identity" in types
        assert "note" in types
        # The phishing_list row URL (an IOC) is emitted.
        assert "url" in types

    def test_phishing_row_emits_resolves_to_for_domain_ip(self):
        # A phishing_list row that carries both a domain and an IP is a
        # hosting pair; connector must emit Domain --resolves-to--> IP.
        a = _adapter("attacks/phishing_group")
        out = a.generate_attacks_phishing_group(
            event={
                "phishing_group": {
                    "id": "pg-2",
                    "brand": "AcmeCorp",
                    "phishing_list": [
                        {
                            "url": "https://phish1.example.com/",
                            "domain": "phish1.example.com",
                            "ip": "192.0.2.10",
                        }
                    ],
                }
            },
            json_date_obj={"submission-time": "2024-01-01T00:00:00Z"},
            json_eval_obj={},
        )
        _assert_bundle(out)
        by_id = {o.id: o for o in out if hasattr(o, "id")}
        resolves = [
            o
            for o in out
            if getattr(o, "type", "") == "relationship"
            and getattr(o, "relationship_type", "") == "resolves-to"
        ]
        assert len(resolves) == 1
        rel = resolves[0]
        assert by_id[rel.source_ref].type == "domain-name"
        assert by_id[rel.source_ref].value == "phish1.example.com"
        assert by_id[rel.target_ref].type == "ipv4-addr"
        assert by_id[rel.target_ref].value == "192.0.2.10"


# --- attacks/phishing_kit ----------------------------------------------------


class TestAttacksPhishingKitHandler:
    def test_emits_file_hash_and_brand(self):
        a = _adapter("attacks/phishing_kit")
        out = a.generate_attacks_phishing_kit(
            event={
                "phishing_kit": {
                    "id": "pk-1",
                    "hash": "d41d8cd98f00b204e9800998ecf8427e",
                    "login": "uploader@example.com",
                    "emails": ["drop@example.com"],
                    "target_brand": ["ExampleCorp"],
                    "downloaded_from": [
                        {"url": "https://example.com/kit.zip", "domain": "example.com"}
                    ],
                }
            },
            json_date_obj={"detection-date": "2024-01-01T00:00:00Z"},
            json_eval_obj={},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        # Kit hash → StixFile.
        assert "file" in types
        # Identity for brand.
        assert "identity" in types


# --- malware/cnc -------------------------------------------------------------


class TestMalwareCncHandler:
    def test_emits_indicators_for_cnc_endpoints(self):
        a = _adapter("malware/cnc", is_ioc=True)
        out = a.generate_malware_cnc(
            event={
                "malware_cnc": {
                    "id": "cnc-1",
                    "cnc": "c2.example.com",
                    "domain": "c2.example.com",
                    "url": "https://c2.example.com/p",
                    "platform": "windows",
                    "ipv4_list": [{"ip": "192.0.2.1"}],
                    "malware_list": [{"name": "MalwareAlpha"}],
                    "threat_actor_list": [{"name": "FIN-X"}],
                }
            },
            json_date_obj={
                "date-first-seen": "2024-01-01T00:00:00Z",
                "date-last-seen": "2024-02-01T00:00:00Z",
            },
            json_eval_obj={},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        # Indicators + malware + threat actor + Note.
        assert "indicator" in types
        assert "malware" in types
        assert "threat-actor" in types

        # Primary is the Domain (priority order in _build_cnc_observable_set:
        # file > domain > url > ipv4 > ipv6); the ip is a secondary. The main
        # _generate_relations call links primary→secondaries via the map,
        # which yields Domain --resolves-to--> IP for the domain-name row.
        by_id = {o.id: o for o in out if hasattr(o, "id")}
        resolves = [
            o
            for o in out
            if getattr(o, "type", "") == "relationship"
            and getattr(o, "relationship_type", "") == "resolves-to"
        ]
        assert len(resolves) >= 1
        for rel in resolves:
            assert by_id[rel.source_ref].type == "domain-name"
            assert by_id[rel.target_ref].type in {"ipv4-addr", "ipv6-addr"}

    def test_file_primary_still_emits_domain_resolves_to_ip(self):
        # When a file hash is present, ``_build_cnc_observable_set`` picks
        # File as primary and the domain drops to secondaries. Regression
        # guard: the connector must still model DNS resolution as
        # Domain --resolves-to--> IP for every CnC IP, canonical direction.
        a = _adapter("malware/cnc", is_ioc=True)
        out = a.generate_malware_cnc(
            event={
                "malware_cnc": {
                    "id": "cnc-2",
                    "domain": "c2.example.com",
                    "file": {"md5": "d41d8cd98f00b204e9800998ecf8427e"},
                    "ipv4_list": [{"ip": "192.0.2.10"}, {"ip": "192.0.2.11"}],
                    "malware_list": [{"name": "MalwareBeta"}],
                }
            },
            json_date_obj={
                "date-first-seen": "2024-01-01T00:00:00Z",
                "date-last-seen": "2024-02-01T00:00:00Z",
            },
            json_eval_obj={},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "file" in types
        assert "domain-name" in types
        assert "ipv4-addr" in types

        by_id = {o.id: o for o in out if hasattr(o, "id")}
        resolves = [
            o
            for o in out
            if getattr(o, "type", "") == "relationship"
            and getattr(o, "relationship_type", "") == "resolves-to"
        ]
        # Two IPs → two resolves-to edges, both sourced at the domain.
        assert len(resolves) == 2
        for rel in resolves:
            assert by_id[rel.source_ref].type == "domain-name"
            assert by_id[rel.source_ref].value == "c2.example.com"
            assert by_id[rel.target_ref].type == "ipv4-addr"
        assert {by_id[r.target_ref].value for r in resolves} == {
            "192.0.2.10",
            "192.0.2.11",
        }


# --- malware/config ----------------------------------------------------------


class TestMalwareConfigHandler:
    def test_emits_incident_and_malware(self):
        a = _adapter("malware/config")
        out = a.generate_malware_config(
            event={
                "malware_config": {
                    "id": "cfg-1",
                    "hash": "d41d8cd98f00b204e9800998ecf8427e",
                    "malware": {"name": "MalwareAlpha", "id": "m-1"},
                    "configSummary": "decoded config blob",
                }
            },
            json_date_obj={
                "date-first-seen": "2024-01-01T00:00:00Z",
                "date-last-seen": "2024-02-01T00:00:00Z",
            },
            json_eval_obj={},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "incident" in types
        assert "malware" in types


# --- compromised/account_group ----------------------------------------------


class TestCompromisedAccountGroupHandler:
    def test_emits_incident_and_user_account(self):
        a = _adapter("compromised/account_group", tlp_color="red")
        # ``_ag_derive_created_time`` uses ``datetime.fromisoformat``, which
        # on Python 3.10 rejects the trailing ``Z`` shorthand for UTC. Pass
        # the explicit ``+00:00`` form so the dates actually parse.
        out = a.generate_compromised_account_group(
            event={
                "account_group": {
                    "login": "alice@example.com",
                    "password": "hunter2",
                    "service": {
                        "url": "https://example.com",
                        "domain": "example.com",
                    },
                    "parsedLogin": {"domain": "corp.local"},
                    "source_type": ["leak"],
                    "events_table": [],
                }
            },
            json_date_obj={
                "date-first-seen": "2024-01-01T00:00:00+00:00",
                "date-last-seen": "2024-02-01T00:00:00+00:00",
            },
            json_eval_obj={"severity": "red"},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "incident" in types
        assert "user-account" in types
        assert "note" in types


# --- compromised/access ------------------------------------------------------


class TestCompromisedAccessHandler:
    def test_emits_incident_with_indicators(self):
        a = _adapter("compromised/access")
        out = a.generate_compromised_access(
            event={
                "access": {
                    "id": "acc-1",
                    "type": "rdp",
                    "description": "Initial-access listing.",
                    "target": {
                        "host": "victim.host",
                        "domain": "victim.example.com",
                        "ip": "192.0.2.1",
                        "provider": "ISP",
                    },
                    "cnc": {
                        "domain": "c2.example.com",
                        "url": "https://c2.example.com/x",
                        "ip": "192.0.2.2",
                    },
                    "malware": {"name": "MalwareGamma", "id": "m-1"},
                    "source": {"name": "shop-x", "externalId": "ext"},
                    "price": {"value": 100, "currency": "USD"},
                }
            },
            json_date_obj={
                "date-first-seen": "2024-01-01T00:00:00Z",
                "date-last-seen": "2024-02-01T00:00:00Z",
            },
            json_eval_obj={"severity": "amber"},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "incident" in types
        assert "indicator" in types  # CNC as indicator

        # CnC domain --resolves-to--> CnC IP (regression guard for the
        # OpenCTI-connectors/issues/5176 sibling site inside the darkweb
        # marketplace CnC block).
        by_id = {o.id: o for o in out if hasattr(o, "id")}
        resolves = [
            o
            for o in out
            if getattr(o, "type", "") == "relationship"
            and getattr(o, "relationship_type", "") == "resolves-to"
        ]
        assert len(resolves) >= 1
        # Every resolves-to must be canonical: source=domain, target=IP.
        for rel in resolves:
            assert by_id[rel.source_ref].type == "domain-name"
            assert by_id[rel.target_ref].type in {"ipv4-addr", "ipv6-addr"}
        # The bug shape (IP source, Domain target) must not appear.
        for rel in resolves:
            assert by_id[rel.source_ref].type != "ipv4-addr"


# --- compromised/bank_card_group --------------------------------------------


class TestCompromisedBankCardGroupHandler:
    def test_emits_payment_card_and_incident(self):
        a = _adapter("compromised/bank_card_group", tlp_color="red")
        out = a.generate_compromised_bank_card_group(
            event={
                "bank_card_group": {
                    "id": "bcg-1",
                    "cardInfo": {
                        "number": "4111111111111111",
                        "type": "credit",
                        "system": "VISA",
                    },
                    "bin": [411111],
                    "issuer": "Bank-X",
                    "country": "US",
                    "malware_list": [{"name": "MalwareGamma"}],
                    "threat_actor_list": [{"name": "FIN-X"}],
                    "events_table": [
                        {
                            "dateDetected": "2024-01-01",
                            "dateCompromised": "2024-01-02",
                            "malware_name": "MalwareGamma",
                            "cnc_domain": "c2.example.com",
                        }
                    ],
                }
            },
            json_date_obj={
                "date-first-seen": "2024-01-01T00:00:00Z",
                "date-last-seen": "2024-02-01T00:00:00Z",
            },
            json_eval_obj={"severity": "red"},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "incident" in types
        # Full card number → native Payment-Card observable linked to incident.
        assert "payment-card" in types


# --- compromised/spd --------------------------------------------------------


class TestCompromisedSpdHandler:
    def test_emits_incident_and_user_account(self):
        a = _adapter("compromised/spd")
        out = a.generate_compromised_spd(
            event={
                "spd": {
                    "id": "spd-1",
                    "type": "phone",
                    "service_type": "casino",
                    "ownerName": "John",
                    "value": {"value": "+15551234567"},
                    "tags": ["Phone"],
                    "country": ["US"],
                }
            },
            json_date_obj={
                "date-first-seen": "2024-01-01T00:00:00Z",
                "date-last-seen": "2024-02-01T00:00:00Z",
            },
            json_eval_obj={"severity": "amber"},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "incident" in types


# --- osi/public_leak --------------------------------------------------------


class TestOsiPublicLeakHandler:
    def test_emits_incident(self):
        a = _adapter("osi/public_leak")
        out = a.generate_osi_public_leak(
            event={
                "public_leak": {
                    "id": "leak-1",
                    "hash": "d41d8cd98f00b204e9800998ecf8427e",
                    "link_list": [
                        {
                            "link": "https://paste.example.com/x",
                            "author": "anon",
                            "title": "creds dump",
                        }
                    ],
                    "data": "leaked body content",
                }
            },
            json_date_obj={"date-created": "2024-01-01T00:00:00Z"},
            json_eval_obj={"severity": "amber"},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "incident" in types


# --- osi/git_repository -----------------------------------------------------


class TestOsiGitRepositoryHandler:
    def test_emits_incident_and_urls(self):
        a = _adapter("osi/git_repository")
        out = a.generate_osi_git_repository(
            event={
                "git_repository": {
                    "id": "r-1",
                    "name": "user/repo",
                    "source": "github",
                    "files": [
                        {
                            "name": ".env",
                            "url": "https://git.example.com/x/y/blob/.env",
                            "hash": "d41d8cd98f00b204e9800998ecf8427e",
                            "revisions": [
                                {
                                    "info": {
                                        "authorEmail": "dev@example.com",
                                        "authorName": "Dev",
                                    }
                                }
                            ],
                            "dataFound": "AWS_KEY",
                        }
                    ],
                }
            },
            json_date_obj={
                "date-detected": "2024-01-01T00:00:00Z",
                "date-created": "2024-01-01T00:00:00Z",
            },
            json_eval_obj={"severity": "amber"},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "incident" in types
        assert "url" in types


# --- osi/vulnerability ------------------------------------------------------


class TestOsiVulnerabilityHandler:
    def test_emits_vulnerability_and_note(self):
        a = _adapter("osi/vulnerability")
        out = a.generate_osi_vulnerability(
            event={
                # CVSS and CPE are read at the EVENT level (cvssv3 /
                # cpe_table), not inside the vulnerability object.
                "vulnerability": {
                    "id": "CVE-2024-1",
                    "title": "RCE",
                    "description": "Critical RCE.",
                    # Extra CVEs come from snake_case cve_list.
                    "cve_list": ["CVE-2024-2"],
                    "references": ["https://advisory.example.com"],
                    "href": "https://advisory.example.com",
                },
                "cvssv3": {
                    "score": 9.8,
                    "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
                "cpe_table": {
                    "cpe_table_list": [
                        {"vendor": "linux", "product": "kernel", "version": "6.0"}
                    ]
                },
            },
            json_date_obj={"date-published": "2024-01-01T00:00:00Z"},
            json_eval_obj={"severity": "green"},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "vulnerability" in types
        assert "note" in types
        # Primary CVE-2024-1 + cve_list CVE-2024-2 → two Vulnerability SDOs.
        vuln_count = sum(1 for o in out if getattr(o, "type", "") == "vulnerability")
        assert vuln_count == 2
        # The Note renders the event-level CVSS score and CPE table.
        note_content = next(o.content for o in out if getattr(o, "type", "") == "note")
        assert "9.8" in note_content
        assert "kernel" in note_content


# --- hi/open_threats --------------------------------------------------------


class TestHiOpenThreatsHandler:
    def test_emits_report_and_observables(self):
        a = _adapter("hi/open_threats")
        out = a.generate_hi_open_threats(
            event={
                "open_threat": {
                    "id": "ot-1",
                    "title": "Public Threat Report",
                    "source": "blog",
                    "sourceType": "vendor",
                    "link": "https://example.com",
                    # Handler reads snake_case threat_actor_list, top-level
                    # domains/ips/urls, cve as dicts with "id", and file dicts
                    # with top-level md5/sha1/sha256.
                    "threat_actor_list": [{"name": "FIN-X", "id": "ta-1"}],
                    "malware": [{"name": "MalwareAlpha", "id": "m-1"}],
                    "cve": [{"id": "CVE-2024-1"}],
                    "tags": ["banking"],
                    "countries": [{"countryCode": "US"}],
                    "domains": ["example.com"],
                    "ips": ["192.0.2.1"],
                    "urls": ["https://example.com/x"],
                    "files": [{"md5": "d41d8cd98f00b204e9800998ecf8427e"}],
                    "text": "report body",
                }
            },
            json_date_obj={
                "date-created": "2024-01-01T00:00:00Z",
                "date-detected": "2024-01-01T00:00:00Z",
            },
            json_eval_obj={},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "report" in types
        # Related SDOs + observables (observables_as_indicators defaults True).
        assert "threat-actor" in types
        assert "malware" in types
        assert "vulnerability" in types
        assert "domain-name" in types
        assert "ipv4-addr" in types
        assert "url" in types
        assert "file" in types
        assert "indicator" in types

    def test_description_in_external_references_flag_moves_body(self):
        # When description_in_external_references=true the Report's
        # description column is emptied and the body is mirrored into an
        # ExternalReference with source_name="Open threat description".
        from unittest.mock import patch

        a = _adapter("hi/open_threats")

        def _flag(collection: str, key: str, default: bool = False) -> bool:
            if key == "description_in_external_references":
                return True
            return default

        with patch.object(a.config, "get_setting_bool", side_effect=_flag):
            out = a.generate_hi_open_threats(
                event={
                    "open_threat": {
                        "id": "ot-2",
                        "title": "Public Threat Report",
                    }
                },
                json_date_obj={"date-created": "2024-01-01T00:00:00Z"},
                json_eval_obj={},
            )
        report = next(o for o in out if getattr(o, "type", "") == "report")
        assert getattr(report, "description", "") == ""
        matches = [
            r
            for r in getattr(report, "external_references", [])
            if r.source_name == "Open threat description"
        ]
        assert len(matches) == 1


# --- ioc/primary ------------------------------------------------------------


class TestIocPrimaryHandler:
    def test_network_ioc_emits_indicators(self):
        a = _adapter("ioc/primary", is_ioc=True, tlp_color="amber")
        out = a.generate_ioc_primary(
            event={
                "ioc_primary": {
                    "type": "network",
                    "domain": [{"domain": "example.com", "riskScore": 80}],
                    "ip": [{"ip": "192.0.2.1", "riskScore": 70}],
                    "url": [{"url": "https://example.com/x", "riskScore": 90}],
                    "malwareList": [{"name": "MalwareAlpha"}],
                    "threatList": [{"name": "FIN-X", "title": "campaign"}],
                }
            },
            json_date_obj={
                "date-first-seen": "2024-01-01T00:00:00Z",
                "date-last-seen": "2024-02-01T00:00:00Z",
            },
            json_eval_obj={},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "indicator" in types

    def test_file_ioc_emits_indicator(self):
        a = _adapter("ioc/primary", is_ioc=True, tlp_color="amber")
        out = a.generate_ioc_primary(
            event={
                "ioc_primary": {
                    "type": "file",
                    "hash": [
                        "d41d8cd98f00b204e9800998ecf8427e",
                        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    ],
                    "riskScore": 60,
                    "malwareList": [{"name": "MalwareAlpha"}],
                }
            },
            json_date_obj={
                "date-first-seen": "2024-01-01T00:00:00Z",
                "date-last-seen": "2024-02-01T00:00:00Z",
            },
            json_eval_obj={},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "indicator" in types


# --- compromised/discord + messenger (chat builders) ------------------------


class TestChatMessageHandlers:
    def test_discord_message_emits_note(self):
        a = _adapter("compromised/discord", tlp_color="red")
        out = a.generate_compromised_discord(
            event={
                "chat_message": {
                    "id": "msg-1",
                    "text": "hello",
                },
                "channel": {
                    "id": "chan-1",
                    "title": "leaks-channel",
                    "type": "channel",
                },
                "author": {
                    "username": "user_alpha",
                    "first_name": "G",
                    "last_name": "B",
                    "id": "u-1",
                },
            },
            json_date_obj={
                "date-published": "2024-01-01T00:00:00Z",
            },
            json_eval_obj={},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        # Author UserAccount + per-message Note.
        assert "note" in types

    def test_telegram_message_emits_note(self):
        a = _adapter("compromised/messenger", tlp_color="red")
        out = a.generate_compromised_messenger(
            event={
                "chat_message": {"id": "msg-1", "text": "hello"},
                "channel": {"id": "chat-1", "title": "x", "type": "supergroup"},
                "author": {
                    "username": "ghoul",
                    "id": "u-1",
                },
            },
            json_date_obj={"date-published": "2024-01-01T00:00:00Z"},
            json_eval_obj={},
        )
        _assert_bundle(out)
        types = {getattr(o, "type", "") for o in out}
        assert "note" in types
