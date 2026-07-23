from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from adapters.adapter import DataToSTIXAdapter
from connector.settings import ConfigConnector


def _adapter(
    collection: str, *, is_ioc: bool = False, threat_actor_name: str | None = None
) -> DataToSTIXAdapter:
    helper = SimpleNamespace(connector_logger=MagicMock())
    return DataToSTIXAdapter(
        mitre_mapper={"T1059": "Command Execution"},
        collection=collection,
        tlp_color="amber",
        helper=helper,
        is_ioc=is_ioc,
        threat_actor_name=threat_actor_name,
        config=ConfigConnector(),
    )


# --- generate_stix_url / domain / ipv4 (basic factories) ---------------------


class TestObservableFactories:
    def test_generate_stix_url(self):
        a = _adapter("apt/threat")
        url_obj = a.generate_stix_url("https://example.com/y")
        # Wrapper around ds.URL — exposes .name and .c_type.
        assert url_obj.name == "https://example.com/y"
        assert url_obj.c_type == "url"

    def test_generate_stix_domain(self):
        a = _adapter("apt/threat")
        d = a.generate_stix_domain("example.com")
        assert d.name == "example.com"
        assert d.c_type == "domain-name"

    def test_generate_stix_ipv4(self):
        a = _adapter("apt/threat")
        ip = a.generate_stix_ipv4("192.0.2.1")
        assert ip.name == "192.0.2.1"
        assert ip.c_type == "ipv4-addr"


# --- generate_stix_malware --------------------------------------------------


class TestGenerateStixMalware:
    def test_empty_returns_empty_list(self):
        a = _adapter("malware/malware")
        assert a.generate_stix_malware(obj={}, json_date_obj={}) == []

    def test_minimal_payload(self):
        a = _adapter("malware/malware")
        out = a.generate_stix_malware(
            obj={"name": "MalwareAlpha"},
            json_date_obj={},
        )
        # ``generate_stix_malware`` returns a list of BaseEntity wrappers
        # (not raw STIX SDOs). Inspect via ``stix_main_object.type``.
        sdo_types = [
            getattr(o.stix_main_object, "type", None)
            for o in out
            if hasattr(o, "stix_main_object")
        ]
        assert "malware" in sdo_types

    def test_no_name_skipped(self):
        # Without a name, the wrapper logs + skips the malware entirely.
        a = _adapter("malware/malware")
        out = a.generate_stix_malware(
            obj={"description": "no name here"},
            json_date_obj={},
        )
        assert out == []

    def test_description_fallback_to_short_description(self):
        # When description is the upstream placeholder, the wrapper
        # substitutes ``shortDescription`` in the SDO's description field.
        a = _adapter("malware/malware")
        out = a.generate_stix_malware(
            obj={
                "name": "X",
                "description": "Sorry, no description yet.",
                "short_description": "Real summary",
            },
            json_date_obj={},
        )
        malware = next(
            o
            for o in out
            if hasattr(o, "stix_main_object") and o.stix_main_object.type == "malware"
        )
        assert malware.stix_main_object.description == "Real summary"

    def test_threat_level_score(self):
        a = _adapter("malware/malware")
        out = a.generate_stix_malware(
            obj={"name": "X", "threat_level": "critical"},
            json_date_obj={},
        )
        malware = next(
            o
            for o in out
            if hasattr(o, "stix_main_object") and o.stix_main_object.type == "malware"
        )
        # ``critical`` → x_opencti_score = 90.
        assert malware.stix_main_object["x_opencti_score"] == 90

    def test_companion_threat_actors(self):
        a = _adapter("malware/malware")
        out = a.generate_stix_malware(
            obj={
                "name": "X",
                "ta_list": [{"name": "FIN-X"}],
                "threat_actor_list": [{"name": "FIN-Y"}],
            },
            json_date_obj={},
        )
        sdo_types = [
            getattr(o.stix_main_object, "type", None)
            for o in out
            if hasattr(o, "stix_main_object")
        ]
        assert "threat-actor" in sdo_types

    def test_linked_malware_dedupe_against_primary_name(self):
        a = _adapter("malware/malware")
        out = a.generate_stix_malware(
            obj={
                "name": "MalwareAlpha",
                "linked_malware": [
                    {"name": "MalwareAlpha"},  # self → must be skipped
                    {"name": "MalwareAlphaV2"},
                ],
            },
            json_date_obj={},
        )
        malware_wrappers = [
            o
            for o in out
            if hasattr(o, "stix_main_object") and o.stix_main_object.type == "malware"
        ]
        # Primary + 1 linked (the self-ref dropped).
        assert len(malware_wrappers) == 2

    def test_linked_malware_different_name_keeps_both(self):
        # When linked_malware names differ from the primary (and aren't
        # collapsed by OpenCTI's own normalisation), both survive.
        a = _adapter("malware/malware")
        out = a.generate_stix_malware(
            obj={
                "name": "MalwareAlpha",
                "linked_malware": [{"name": "MalwareAlphaV2"}],
            },
            json_date_obj={},
        )
        malware_wrappers = [
            o
            for o in out
            if hasattr(o, "stix_main_object") and o.stix_main_object.type == "malware"
        ]
        # Primary + 1 linked sibling.
        assert len(malware_wrappers) == 2

    def test_description_stays_on_sdo_by_default(self):
        # Baseline for the DESCRIPTION_IN_EXTERNAL_REFERENCES flag: default
        # false → description body is set on Malware.description and is NOT
        # mirrored into a "Malware description" ExternalReference on the
        # wrapper (which then feeds the SDO's ``x_opencti_external_references``
        # custom property, per src/models/sdo.py::Malware._generate_sdo).
        a = _adapter("malware/malware")
        out = a.generate_stix_malware(
            obj={"name": "MalwareGamma", "description": "Full description body"},
            json_date_obj={},
        )
        malware = next(
            o
            for o in out
            if hasattr(o, "stix_main_object") and o.stix_main_object.type == "malware"
        )
        assert malware.stix_main_object.description == "Full description body"
        source_names = {
            r.source_name for r in getattr(malware, "external_references", [])
        }
        assert "Malware description" not in source_names

    def test_flag_moves_description_to_external_reference(self):
        # When description_in_external_references=true, the Malware SDO's
        # description column is emptied and the body is mirrored into an
        # ExternalReference (source_name="Malware description") on the wrapper,
        # which the SDO builder embeds into ``x_opencti_external_references``.
        # Mirrors the same-named flag used by apt/threat, hi/threat and the
        # actor handlers.
        from unittest.mock import patch

        a = _adapter("malware/malware")

        def _flag(collection: str, key: str, default: bool = False) -> bool:
            if key == "description_in_external_references":
                return True
            return default

        with patch.object(a.config, "get_setting_bool", side_effect=_flag):
            out = a.generate_stix_malware(
                obj={"name": "MalwareDelta", "description": "Full description body"},
                json_date_obj={},
            )
        malware = next(
            o
            for o in out
            if hasattr(o, "stix_main_object") and o.stix_main_object.type == "malware"
        )
        assert getattr(malware.stix_main_object, "description", "") == ""
        matches = [
            r
            for r in getattr(malware, "external_references", [])
            if r.source_name == "Malware description"
        ]
        assert len(matches) == 1
        assert matches[0].description == "Full description body"


# --- generate_stix_threat_actor + intrusion_set -----------------------------


class TestGenerateStixThreatActor:
    def test_empty_returns_none_tuple(self):
        a = _adapter("apt/threat_actor")
        ta, locs = a.generate_stix_threat_actor(
            obj={}, related_objects=[], json_date_obj={}
        )
        assert ta is None and locs is None

    def test_minimal(self):
        a = _adapter("apt/threat_actor")
        ta, locs = a.generate_stix_threat_actor(
            obj={"name": "FIN-X"},
            related_objects=[],
            json_date_obj={},
        )
        assert ta is not None
        # ThreatActor wrapper carries the Group-IB SDO.
        assert ta.stix_main_object.name == "FIN-X"

    def test_with_country_and_targeted(self):
        a = _adapter("apt/threat_actor")
        ta, locs = a.generate_stix_threat_actor(
            obj={
                "name": "FIN-X",
                "country": "RU",
                "targeted_countries": ["US", "GB"],
                "aliases": ["Group-X"],
            },
            related_objects=[],
            json_date_obj={
                "first-seen": "2020-01-01T00:00:00Z",
                "last-seen": "2024-01-01T00:00:00Z",
            },
        )
        assert ta is not None
        # Base location + 2 targeted locations emitted as wrappers.
        assert locs is not None
        assert len(locs) >= 1


class TestGenerateStixIntrusionSet:
    def test_empty(self):
        a = _adapter("apt/threat_actor")
        is_obj, locs = a.generate_stix_intrusion_set(
            obj={}, related_objects=[], json_date_obj={}
        )
        assert is_obj is None and locs is None

    def test_minimal(self):
        a = _adapter("apt/threat_actor")
        is_obj, locs = a.generate_stix_intrusion_set(
            obj={"name": "Group-X"},
            related_objects=[],
            json_date_obj={},
        )
        assert is_obj is not None
        assert is_obj.stix_main_object.name == "Group-X"


# --- generate_stix_attack_pattern -------------------------------------------


class TestGenerateStixAttackPattern:
    def test_empty(self):
        a = _adapter("apt/threat")
        assert a.generate_stix_attack_pattern(obj={}) == []

    def test_with_mitre_techniques_with_kill_chain(self):
        # ``_generate_mitre_matrix`` reads ``_e.get("kill_chain_phase")``
        # (singular scalar) and feeds it to ``KillChainPhase(c_type=...)``.
        # Provide a real phase name so stix2 sets ``phase_name`` on the
        # resulting sub-object.
        a = _adapter("apt/threat")
        out = a.generate_stix_attack_pattern(
            obj={
                "mitre_matrix_list": [
                    {
                        "attack_pattern": "T1059",
                        "kill_chain_phase": "execution",
                    },
                ]
            }
        )
        # One technique in → one AttackPattern wrapper out, named via the
        # mitre_mapper fixture ({"T1059": "Command Execution"}).
        assert len(out) == 1
        ap = out[0].stix_main_object
        assert ap.type == "attack-pattern"
        assert ap.name == "Command Execution"
        assert len(ap.kill_chain_phases) == 1


# --- generate_stix_network --------------------------------------------------


class TestGenerateStixNetwork:
    def test_empty_returns_four_empty_lists(self):
        a = _adapter("apt/threat")
        out = a.generate_stix_network(obj={}, json_date_obj={}, related_objects=[])
        assert out == ([], [], [], [])

    def test_minimal_network(self):
        a = _adapter("apt/threat")
        # ``generate_stix_network`` builds Indicator SDOs when the IOC
        # flags are on; stix2 rejects ``valid_from == valid_until``, so
        # provide a date_obj with a real TTL window.
        domain_list, url_list, ip_list, ddos_loc = a.generate_stix_network(
            obj={
                "network_list": [
                    {
                        "domain": "example.com",
                        "url": "https://example.com/x",
                        # ``_process_network_entry`` reads ``ip-address``.
                        "ip-address": "192.0.2.1",
                    }
                ],
            },
            json_date_obj={
                "first-seen": "2024-01-01T00:00:00+00:00",
                "last-seen": "2024-02-01T00:00:00+00:00",
                "ttl": 30,
            },
            related_objects=[],
            domain_is_ioc=False,
            url_is_ioc=False,
            ip_is_ioc=False,
        )
        # One entry with all three fields → one observable in each list.
        assert len(domain_list) == 1
        assert len(url_list) == 1
        assert len(ip_list) == 1

    def test_domain_ip_uses_resolves_to_direction(self):
        # STIX 2.1: ``resolves-to`` source MUST be domain-name, target MUST be
        # ipv4/ipv6-addr. Regression guard for OpenCTI-connectors/issues/5176.
        a = _adapter("apt/threat")
        domain_list, _url, ip_list, _ddos = a.generate_stix_network(
            obj={
                "network_list": [
                    {
                        "domain": "example.com",
                        "ip-address": "192.0.2.1",
                        "ipv6-address": "2001:db8::1",
                    }
                ],
            },
            json_date_obj={
                "first-seen": "2024-01-01T00:00:00+00:00",
                "last-seen": "2024-02-01T00:00:00+00:00",
                "ttl": 30,
            },
            related_objects=[],
            domain_is_ioc=False,
            url_is_ioc=False,
            ip_is_ioc=False,
        )
        domain_wrapper = domain_list[0]
        domain_id = domain_wrapper.stix_main_object.id
        ip_ids = {w.stix_main_object.id for w in ip_list}

        resolves_edges = [
            r
            for r in domain_wrapper.stix_relationships
            if r.relationship_type == "resolves-to"
        ]
        assert len(resolves_edges) == 2
        for edge in resolves_edges:
            assert edge.source_ref == domain_id
            assert edge.target_ref in ip_ids

        # No IP wrapper should carry an outbound edge back to the domain —
        # the removed behavior was ``ip related-to domain``.
        for ip_wrapper in ip_list:
            for r in ip_wrapper.stix_relationships:
                assert r.target_ref != domain_id

    def test_url_observable_has_no_self_external_reference(self):
        # Regression guard for OpenCTI-connectors/issues/4526: importing a
        # URL observable must NOT attach that same URL back as an
        # ExternalReference on the observable (clickable-malicious-link risk).
        malicious = "https://evil.example/payload"
        a = _adapter("apt/threat")
        _domain, url_list, _ip, _ddos = a.generate_stix_network(
            obj={"network_list": [{"url": malicious}]},
            json_date_obj={
                "first-seen": "2024-01-01T00:00:00+00:00",
                "last-seen": "2024-02-01T00:00:00+00:00",
                "ttl": 30,
            },
            related_objects=[],
            domain_is_ioc=False,
            url_is_ioc=False,
            ip_is_ioc=False,
        )
        assert len(url_list) == 1
        url_wrapper = url_list[0]

        assert url_wrapper.external_references == []

        for obj in url_wrapper.stix_objects or []:
            if getattr(obj, "type", None) == "url":
                assert not getattr(obj, "external_references", None)
            assert getattr(obj, "url", None) != malicious

    def test_url_observable_uses_entry_portal_link_when_present(self):
        # When the network_list entry ships a Group-IB TI portal_link, it
        # must surface as the URL observable's ExternalReference — the
        # malicious URL value must still never appear there.
        malicious = "https://evil.example/payload"
        portal = "https://tap.group-ib.com/apt/threat/12345"
        a = _adapter("apt/threat")
        _domain, url_list, _ip, _ddos = a.generate_stix_network(
            obj={
                "network_list": [{"url": malicious, "portal_link": portal}],
            },
            json_date_obj={
                "first-seen": "2024-01-01T00:00:00+00:00",
                "last-seen": "2024-02-01T00:00:00+00:00",
                "ttl": 30,
            },
            related_objects=[],
            domain_is_ioc=False,
            url_is_ioc=False,
            ip_is_ioc=False,
        )
        assert len(url_list) == 1
        url_wrapper = url_list[0]

        assert len(url_wrapper.external_references) == 1
        ext_urls = {ref.url for ref in url_wrapper.external_references}
        assert portal in ext_urls
        assert malicious not in ext_urls


# --- generate_stix_file -----------------------------------------------------


class TestGenerateStixFile:
    def test_empty(self):
        a = _adapter("apt/threat")
        assert a.generate_stix_file(obj={}, json_date_obj={}, related_objects=[]) == []

    # Non-empty file_list / bare-dict cases live in test_sdo_file.py, which
    # exercises the real md5/sha1/sha256 keys and asserts exact counts.


# --- generate_stix_yara / suricata ------------------------------------------


class TestGenerateStixYara:
    def test_empty_returns_none(self):
        a = _adapter("malware/yara", is_ioc=True)
        out = a.generate_stix_yara(
            obj={}, related_objects=[], json_date_obj={}, yara_is_ioc=True
        )
        assert out is None

    def test_with_rule(self):
        a = _adapter("malware/yara", is_ioc=True)
        # Payload shape: ``obj.get("yara")`` = rule name, ``obj.get("context")``
        # = body. ``_retrieve_ttl_dates`` reads ``date-modified`` /
        # ``date-created`` (not first-/last-seen) for the TTL window.
        out = a.generate_stix_yara(
            obj={
                "yara": "rule_x",
                "context": "rule rule_x { condition: true }",
            },
            related_objects=[],
            json_date_obj={
                "date-created": "2024-01-01T00:00:00+00:00",
                "date-modified": "2024-01-15T00:00:00+00:00",
                "ttl": 30,
            },
            yara_is_ioc=True,
        )
        # Valid rule → wrapper carrying an Indicator SDO (never None here).
        assert out is not None
        assert out.stix_main_object is not None


class TestGenerateStixSuricata:
    def test_empty_returns_none(self):
        a = _adapter("malware/signature", is_ioc=True)
        out = a.generate_stix_suricata(
            obj={}, related_objects=[], json_date_obj={}, suricata_is_ioc=True
        )
        assert out is None

    def test_with_rule(self):
        a = _adapter("malware/signature", is_ioc=True)
        # Suricata reads ``obj.get("signature")`` for the rule name.
        out = a.generate_stix_suricata(
            obj={
                "signature": "alert_x",
                "context": 'alert tcp any any -> any 80 (msg:"x";)',
            },
            related_objects=[],
            json_date_obj={
                "date-created": "2024-01-01T00:00:00+00:00",
                "date-modified": "2024-01-15T00:00:00+00:00",
                "ttl": 30,
            },
            suricata_is_ioc=True,
        )
        # Valid rule → wrapper carrying an Indicator SDO (never None here).
        assert out is not None
        assert out.stix_main_object is not None


# --- generate_stix_ungrouped ------------------------------------------------


class TestGenerateStixUngrouped:
    def test_empty(self):
        a = _adapter("apt/threat")
        # Empty obj → early-exit returns None.
        assert (
            a.generate_stix_ungrouped(
                obj={}, related_objects=[], json_date_obj={}, email_is_ioc=False
            )
            is None
        )

    def test_with_email(self):
        a = _adapter("attacks/phishing_kit", is_ioc=True)
        out = a.generate_stix_ungrouped(
            # ``generate_stix_ungrouped`` reads the ``emails`` key.
            obj={"emails": ["drop@example.com"]},
            related_objects=[],
            # email_is_ioc builds an Indicator; supply a real TTL window
            # (date-created/-modified + ttl) so valid_until > valid_from.
            json_date_obj={
                "date-created": "2024-01-01T00:00:00+00:00",
                "date-modified": "2024-02-01T00:00:00+00:00",
                "ttl": 30,
            },
            email_is_ioc=True,
        )
        # One address in → one Email wrapper out.
        assert len(out) == 1
        assert out[0].stix_main_object.type == "email-addr"
        assert out[0].stix_main_object.value == "drop@example.com"


# --- generate_stix_targeted_entities ----------------------------------------


class TestGenerateStixTargetedEntities:
    def test_empty(self):
        a = _adapter("apt/threat")
        out = a.generate_stix_targeted_entities(obj={}, related_objects=[])
        assert isinstance(out, list)

    def test_sectors_companies_partners_regions(self):
        a = _adapter("apt/threat")
        out = a.generate_stix_targeted_entities(
            obj={
                "sectors": ["finance"],
                "targeted_companies": ["ExampleCorp"],
                "targeted_partners": ["PartnerCo"],
                "regions": ["europe:european_union"],
            },
            related_objects=[],
        )
        # Wrappers list — Identity SDOs + Location SDOs.
        assert isinstance(out, list)
        assert len(out) >= 1


# --- generate_locations -----------------------------------------------------


class TestGenerateLocations:
    def test_empty_input(self):
        a = _adapter("apt/threat")
        out = a.generate_locations([])
        assert out == []

    def test_country_code_lookup(self):
        a = _adapter("apt/threat")
        out = a.generate_locations(["US", "GB"])
        # Two Location wrappers.
        assert len(out) == 2
        assert all(w.stix_main_object.type == "location" for w in out)

    def test_invalid_country_skipped_gracefully(self):
        a = _adapter("apt/threat")
        # Unknown code → wrapper still emits with raw name as fallback.
        out = a.generate_locations(["ZZ", None, ""])
        # Only ZZ survives (None/"" filtered).
        assert len(out) == 1


# --- generate_stix_report ---------------------------------------------------


class TestGenerateStixReport:
    def test_empty_returns_none(self):
        a = _adapter("apt/threat")
        out = a.generate_stix_report(
            obj={},
            json_date_obj={},
            report_related_objects_ids=[],
            json_malware_report_obj={},
            json_threat_actor_obj={},
        )
        assert out is None

    def test_minimal_report(self):
        a = _adapter("apt/threat", threat_actor_name="FIN-X")
        out = a.generate_stix_report(
            obj={
                "id": "rep-1",
                "title": "Threat Report",
                "description": "<p>Body</p>",
            },
            json_date_obj={"date-published": "2024-01-01T00:00:00Z"},
            report_related_objects_ids=[
                "indicator--11111111-1111-4111-8111-111111111111"
            ],
            json_malware_report_obj={},
            json_threat_actor_obj={"name": "FIN-X"},
        )
        assert out is not None
        # The wrapper exposes the Report SDO.
        assert out.stix_main_object.type == "report"
        assert out.stix_main_object.name == "Threat Report"
