"""Tests for the imphash and ATT&CK technique pivots.

Result shapes were measured read-only against the live API on 2026-11-10:
``search_by_ioc(imphash=...)`` yields IOC resources whose ``json`` is a
SHA-256 string; ``search_by_metadata(..., include=["artifact.sha256"])`` yields
Metadata resources whose ``json`` is ``{"artifact": {"sha256": ...}}``. Both
raise ``NoResultsException`` when nothing matches (``search_by_ioc(ttp=...)``
did that for every technique tried, which is why the technique pivot uses the
metadata index).
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from conftest import StubHelper
from connectors_sdk import ConfigValidationError
from polyswarm_enrichment.connector import _IOC_NOT_FETCHED, ConnectorTemplate
from polyswarm_enrichment.converter_to_stix import ConverterToStix
from polyswarm_enrichment.pivots import (
    MAX_PIVOT_RESULTS,
    PIVOT_LABEL,
    TTP_METADATA_FIELDS,
    PivotService,
    extract_mitre_id,
    has_pivot_label,
)
from polyswarm_enrichment.polyswarm_client import polyswarm_exceptions
from polyswarm_enrichment.settings import ConnectorSettings
from test_network_observables import _make_client, _raise_no_results

SELF_SHA = "e" * 64
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
IMPHASH = "68f013d7437aa653a8a98a05807afeb1"
FILE_ID = "file--0d6a4c5e-4a2b-5c3d-9e8f-123456789abc"
AP_ID = "attack-pattern--0d6a4c5e-4a2b-5c3d-9e8f-123456789abc"
TLP_AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
TLP_GREEN = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"


def _ioc_results(*hashes):
    return iter([SimpleNamespace(json=h) for h in hashes])


def _meta_results(*hashes):
    return iter([SimpleNamespace(json={"artifact": {"sha256": h}}) for h in hashes])


def _service(client, imphash_max=10, ttp_max=10):
    helper = StubHelper()
    return PivotService(
        helper,
        client,
        ConverterToStix(helper),
        imphash_max=imphash_max,
        ttp_max=ttp_max,
    )


def _by_type(objects, stix_type):
    return [o for o in objects if o.get("type") == stix_type]


# ===========================================================================
# MITRE id extraction
# ===========================================================================
class TestExtractMitreId:
    def test_reads_x_mitre_id(self):
        assert extract_mitre_id({"x_mitre_id": "T1059"}) == "T1059"

    def test_reads_sub_technique_and_normalises_case(self):
        assert extract_mitre_id({"x_mitre_id": " t1059.001 "}) == "T1059.001"

    def test_falls_back_to_mitre_external_reference(self):
        entity = {
            "external_references": [
                {"source_name": "other", "external_id": "X1"},
                {"source_name": "mitre-attack", "external_id": "T1486"},
            ]
        }
        assert extract_mitre_id(entity) == "T1486"

    @pytest.mark.parametrize(
        "entity",
        [
            None,
            {},
            {"x_mitre_id": "TA0001"},
            {"x_mitre_id": 'T1059" OR *:*'},
            {
                "external_references": [
                    {"source_name": "capec", "external_id": "CAPEC-1"}
                ]
            },
            {"external_references": ["not-a-dict"]},
        ],
    )
    def test_rejects_anything_that_is_not_a_technique_id(self, entity):
        assert extract_mitre_id(entity) is None


# ===========================================================================
# Imphash pivot
# ===========================================================================
class TestImphashPivot:
    def test_creates_related_files_relationships_and_note(self):
        client = _make_client(
            search_by_ioc=lambda **kw: _ioc_results(SHA_A, SHA_B, SELF_SHA)
        )
        objects = _service(client).imphash_objects(FILE_ID, SELF_SHA, IMPHASH)

        files = _by_type(objects, "file")
        assert [f["hashes"]["SHA-256"] for f in files] == [SHA_A, SHA_B]
        rels = _by_type(objects, "relationship")
        assert len(rels) == 2
        assert {r["source_ref"] for r in rels} == {FILE_ID}
        assert {r["relationship_type"] for r in rels} == {"related-to"}
        assert all(IMPHASH in r["description"] for r in rels)
        (note,) = _by_type(objects, "note")
        assert IMPHASH in note["content"] and IMPHASH in note["abstract"]
        assert note["object_refs"][0] == FILE_ID
        assert len(note["object_refs"]) == 3

    def test_searches_by_imphash_only(self):
        client = _make_client(search_by_ioc=lambda **kw: _ioc_results(SHA_A))
        _service(client).imphash_objects(FILE_ID, SELF_SHA, IMPHASH)
        client.polyswarm.search_by_ioc.assert_called_once_with(imphash=IMPHASH)
        client.polyswarm.search_by_metadata.assert_not_called()

    def test_never_includes_the_source_file(self):
        client = _make_client(search_by_ioc=lambda **kw: _ioc_results(SELF_SHA))
        assert _service(client).imphash_objects(FILE_ID, SELF_SHA, IMPHASH) == []

    def test_caps_results_at_the_limit(self):
        many = [f"{i:064x}" for i in range(1, 30)]
        client = _make_client(search_by_ioc=lambda **kw: _ioc_results(*many))
        objects = _service(client, imphash_max=3).imphash_objects(
            FILE_ID, SELF_SHA, IMPHASH
        )
        assert len(_by_type(objects, "file")) == 3

    def test_off_when_limit_is_zero_and_makes_no_call(self):
        client = _make_client(search_by_ioc=lambda **kw: _ioc_results(SHA_A))
        assert (
            _service(client, imphash_max=0).imphash_objects(FILE_ID, SELF_SHA, IMPHASH)
            == []
        )
        client.polyswarm.search_by_ioc.assert_not_called()

    @pytest.mark.parametrize("bad", [None, "", "zz" * 16, IMPHASH + "0", "a" * 31])
    def test_ignores_missing_or_malformed_imphash(self, bad):
        client = _make_client(search_by_ioc=lambda **kw: _ioc_results(SHA_A))
        assert _service(client).imphash_objects(FILE_ID, SELF_SHA, bad) == []
        client.polyswarm.search_by_ioc.assert_not_called()

    def test_no_results_gives_nothing(self):
        client = _make_client(search_by_ioc=_raise_no_results)
        assert _service(client).imphash_objects(FILE_ID, SELF_SHA, IMPHASH) == []

    def test_api_error_gives_nothing_and_does_not_raise(self):
        def boom(**kw):
            raise polyswarm_exceptions.RequestException(MagicMock(), "boom")

        client = _make_client(search_by_ioc=boom)
        assert _service(client).imphash_objects(FILE_ID, SELF_SHA, IMPHASH) == []

    def test_markings_are_copied_to_every_object(self):
        client = _make_client(search_by_ioc=lambda **kw: _ioc_results(SHA_A))
        objects = _service(client).imphash_objects(
            FILE_ID, SELF_SHA, IMPHASH, marking_refs=[TLP_AMBER]
        )
        assert len(objects) == 3
        assert all(o["object_marking_refs"] == [TLP_AMBER] for o in objects)
        json.dumps(objects)  # plain JSON, no stix2 objects left

    def test_private_community_also_searches_default(self):
        client = _make_client(
            search_by_ioc=lambda **kw: _ioc_results(SHA_A), community="private"
        )
        client.polyswarm_default = MagicMock()
        client.polyswarm_default.search_by_ioc.side_effect = lambda **kw: (
            _ioc_results(SHA_B)
        )
        client._circuit_breakers["default"] = client._circuit_breakers["private"]
        objects = _service(client).imphash_objects(FILE_ID, SELF_SHA, IMPHASH)
        assert {f["hashes"]["SHA-256"] for f in _by_type(objects, "file")} == {
            SHA_A,
            SHA_B,
        }


# ===========================================================================
# Technique pivot
# ===========================================================================
class TestTechniquePivot:
    def _client(self, results):
        client = _make_client()
        client.polyswarm.search_by_metadata.side_effect = lambda q, **kw: (
            results() if callable(results) else results
        )
        return client

    def test_creates_files_related_to_the_attack_pattern(self):
        client = self._client(lambda: _meta_results(SHA_A, SHA_B))
        objects = _service(client).ttp_objects(AP_ID, "T1486")

        assert [f["hashes"]["SHA-256"] for f in _by_type(objects, "file")] == [
            SHA_A,
            SHA_B,
        ]
        rels = _by_type(objects, "relationship")
        assert {r["target_ref"] for r in rels} == {AP_ID}
        assert {r["relationship_type"] for r in rels} == {"related-to"}
        (note,) = _by_type(objects, "note")
        assert "T1486" in note["content"]
        assert note["object_refs"][0] == AP_ID

    def test_queries_both_sandbox_fields_with_the_quoted_id(self):
        client = self._client(lambda: _meta_results(SHA_A))
        _service(client).ttp_objects(AP_ID, "T1059.001")
        query = client.polyswarm.search_by_metadata.call_args[0][0]
        for field in TTP_METADATA_FIELDS:
            assert f'{field}:"T1059.001"' in query
        assert client.polyswarm.search_by_metadata.call_args[1]["include"] == [
            "artifact.sha256"
        ]
        client.polyswarm.search_by_ioc.assert_not_called()

    def test_caps_results_at_the_limit(self):
        many = [f"{i:064x}" for i in range(1, 30)]
        client = self._client(lambda: _meta_results(*many))
        objects = _service(client, ttp_max=4).ttp_objects(AP_ID, "T1055")
        assert len(_by_type(objects, "file")) == 4

    def test_off_when_limit_is_zero_and_makes_no_call(self):
        client = self._client(lambda: _meta_results(SHA_A))
        assert _service(client, ttp_max=0).ttp_objects(AP_ID, "T1055") == []
        client.polyswarm.search_by_metadata.assert_not_called()

    @pytest.mark.parametrize("bad", [None, "", "TA0001", 'T1059" OR *:*', "T10"])
    def test_never_queries_with_a_malformed_id(self, bad):
        client = self._client(lambda: _meta_results(SHA_A))
        assert _service(client).ttp_objects(AP_ID, bad) == []
        client.polyswarm.search_by_metadata.assert_not_called()

    def test_no_results_gives_nothing(self):
        client = _make_client()
        client.polyswarm.search_by_metadata.side_effect = _raise_no_results
        assert _service(client).ttp_objects(AP_ID, "T1486") == []

    def test_api_error_gives_nothing_and_records_a_failure(self):
        client = _make_client()
        client.polyswarm.search_by_metadata.side_effect = (
            polyswarm_exceptions.RequestException(MagicMock(), "boom")
        )
        assert _service(client).ttp_objects(AP_ID, "T1486") == []
        assert client._circuit_breakers["default"].get_status()["failure_count"] == 1

    def test_skips_items_without_a_valid_sha256(self):
        items = iter(
            [
                SimpleNamespace(json={"artifact": {}}),
                SimpleNamespace(json={"artifact": {"sha256": "short"}}),
                SimpleNamespace(json={"artifact": {"sha256": SHA_C.upper()}}),
            ]
        )
        client = self._client(lambda: items)
        objects = _service(client).ttp_objects(AP_ID, "T1486")
        assert [f["hashes"]["SHA-256"] for f in _by_type(objects, "file")] == [SHA_C]

    def test_markings_are_copied_to_every_object(self):
        client = self._client(lambda: _meta_results(SHA_A))
        objects = _service(client).ttp_objects(AP_ID, "T1486", marking_refs=[TLP_AMBER])
        assert all(o["object_marking_refs"] == [TLP_AMBER] for o in objects)


def test_imported_files_carry_the_pivot_label_and_nothing_else_does():
    client = _make_client(search_by_ioc=lambda **kw: _ioc_results(SHA_A))
    objects = _service(client).imphash_objects(FILE_ID, SELF_SHA, IMPHASH)
    for obj in objects:
        assert has_pivot_label(obj) == (obj["type"] == "file")


def test_has_pivot_label_handles_empty_input():
    assert not has_pivot_label(None, {}, {"x_opencti_labels": ["other"]})


def test_limits_are_clamped():
    service = _service(_make_client(), imphash_max=10_000, ttp_max=-5)
    assert service.imphash_max == MAX_PIVOT_RESULTS
    assert service.ttp_max == 0


# ===========================================================================
# Connector hook
# ===========================================================================
def _connector(client, imphash_max=10, ttp_max=10, scope="stixfile,attack-pattern"):
    connector = object.__new__(ConnectorTemplate)
    connector.helper = StubHelper()
    connector.helper.connect_scope = scope
    connector.stix_objects_list = []
    connector.converter_to_stix = ConverterToStix(connector.helper)
    connector.client = client
    connector.pivots = PivotService(
        connector.helper,
        client,
        connector.converter_to_stix,
        imphash_max=imphash_max,
        ttp_max=ttp_max,
    )
    connector.max_tlp = "TLP:RED"
    connector.replace_with_lower_score = True
    connector._last_ioc_data = _IOC_NOT_FETCHED
    connector._send_bundle = MagicMock(return_value="[CONNECTOR] sent")
    return connector


def _ap_message(entity=None, event_type="enrichment", **opencti):
    entity = {
        "id": AP_ID,
        "type": "attack-pattern",
        "name": "Data Encrypted for Impact",
        "x_mitre_id": "T1486",
        **(entity or {}),
    }
    return {
        "enrichment_entity": {
            "entity_type": "Attack-Pattern",
            "id": "internal-id",
            **opencti,
        },
        "stix_objects": [entity],
        "stix_entity": entity,
        "event_type": event_type,
    }


class TestAttackPatternHook:
    def test_enriches_an_attack_pattern(self):
        client = _make_client()
        client.polyswarm.search_by_metadata.side_effect = lambda q, **kw: (
            _meta_results(SHA_A)
        )
        connector = _connector(client)
        assert connector.process_message(_ap_message()) == "[CONNECTOR] sent"
        sent = connector._send_bundle.call_args[0][0]
        assert AP_ID in {o["id"] for o in sent}
        assert len(_by_type(sent, "file")) == 1
        assert len(_by_type(sent, "note")) == 1

    def test_uses_the_mitre_external_reference_when_no_x_mitre_id(self):
        client = _make_client()
        client.polyswarm.search_by_metadata.side_effect = lambda q, **kw: (
            _meta_results(SHA_A)
        )
        message = _ap_message(
            {
                "x_mitre_id": None,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1055"}
                ],
            }
        )
        _connector(client).process_message(message)
        assert "T1055" in client.polyswarm.search_by_metadata.call_args[0][0]

    def test_auto_enrichment_never_runs_the_technique_pivot(self):
        client = _make_client()
        connector = _connector(client)
        connector.helper.connect_auto = True
        connector.process_message(_ap_message(event_type=None))
        client.polyswarm.search_by_metadata.assert_not_called()

    def test_disabled_pivot_sends_nothing_to_polyswarm(self):
        client = _make_client()
        connector = _connector(client, ttp_max=0)
        connector.process_message(_ap_message(event_type=None))
        client.polyswarm.search_by_metadata.assert_not_called()
        sent = connector._send_bundle.call_args[0][0]
        assert [o["id"] for o in sent] == [AP_ID]

    def test_disabled_pivot_on_playbook_event_is_an_error_not_a_lookup(self):
        client = _make_client()
        connector = _connector(client, ttp_max=0)
        result = connector.process_message(_ap_message())
        assert "not supported" in result
        client.polyswarm.search_by_metadata.assert_not_called()

    def test_explicit_env_scope_without_attack_pattern_still_pivots(self):
        # The helper reads CONNECTOR_SCOPE from the environment first, so an
        # explicit scope hides the type the settings added. The setting decides.
        client = _make_client()
        connector = _connector(
            client, scope="StixFile,Artifact,Url,Domain-Name,IPv4-Addr,IPv6-Addr"
        )
        result = connector.process_message(_ap_message())
        assert "not supported" not in result
        client.polyswarm.search_by_metadata.assert_called()

    def test_no_mitre_id_sends_nothing(self):
        client = _make_client()
        connector = _connector(client)
        result = connector.process_message(_ap_message({"x_mitre_id": None}))
        assert "No MITRE" in result
        client.polyswarm.search_by_metadata.assert_not_called()

    def test_tlp_above_max_is_refused_before_any_lookup(self):
        client = _make_client()
        connector = _connector(client)
        connector.max_tlp = "TLP:GREEN"
        message = _ap_message(entity={"object_marking_refs": [TLP_AMBER]})
        assert "exceeds" in connector.process_message(message)
        client.polyswarm.search_by_metadata.assert_not_called()

    def test_unresolvable_marking_fails_closed(self):
        client = _make_client()
        connector = _connector(client)
        connector.max_tlp = "TLP:GREEN"
        message = _ap_message(
            entity={"object_marking_refs": ["marking-definition--custom"]},
            event_type=None,
        )
        assert "can't be resolved" in connector.process_message(message)
        client.polyswarm.search_by_metadata.assert_not_called()


class TestImphashHook:
    def _file_message(self):
        observable = {"id": FILE_ID, "type": "file", "hashes": {"SHA-256": SELF_SHA}}
        return {
            "enrichment_entity": {"entity_type": "StixFile", "id": "internal-id"},
            "stix_objects": [observable],
            "stix_entity": observable,
            "event_type": "enrichment",
        }

    def _wire(self, connector, ioc_data, found=(SHA_A,)):
        client = connector.client
        client.query_polyswarm = MagicMock(return_value={"data": {"sha256": SELF_SHA}})
        client.fetch_iocs = MagicMock(return_value=ioc_data)
        client.polyswarm.search_by_ioc.side_effect = lambda **kw: _ioc_results(*found)
        connector._collect_intelligence = MagicMock(
            return_value=[{"id": FILE_ID, "type": "file"}]
        )

    def test_adds_pivot_objects_to_the_bundle(self):
        connector = _connector(_make_client())
        self._wire(connector, {"imphash": IMPHASH})
        connector.process_message(self._file_message())
        sent = connector._send_bundle.call_args[0][0]
        assert [
            f["hashes"]["SHA-256"] for f in _by_type(sent, "file") if "hashes" in f
        ] == [SHA_A]
        assert len(_by_type(sent, "relationship")) == 1

    def test_pivot_objects_carry_union_of_stix_and_opencti_markings(self):
        connector = _connector(_make_client())
        self._wire(connector, {"imphash": IMPHASH})
        message = self._file_message()
        message["stix_entity"] = {
            **message["stix_entity"],
            "object_marking_refs": [TLP_AMBER],
        }
        message["enrichment_entity"]["objectMarking"] = [
            {"definition": "TLP:GREEN", "standard_id": TLP_GREEN},
            {"definition": "TLP:AMBER", "standard_id": TLP_AMBER},
        ]
        connector.process_message(message)
        sent = connector._send_bundle.call_args[0][0]
        pivots = [
            o
            for o in sent
            if (o["type"] == "file" and "hashes" in o) or o["type"] == "relationship"
        ]
        assert len(pivots) == 2
        for obj in pivots:
            assert obj["object_marking_refs"] == [TLP_AMBER, TLP_GREEN]

    def test_bundle_gets_the_marking_definitions_it_references(self):
        connector = _connector(_make_client())
        self._wire(connector, None)
        connector._collect_intelligence = MagicMock(
            return_value=[
                {"id": FILE_ID, "type": "file"},
                {"id": "note--1", "type": "note"},
            ]
        )
        message = self._file_message()
        message["enrichment_entity"]["objectMarking"] = [
            {
                "standard_id": TLP_AMBER,
                "definition_type": "TLP",
                "definition": "TLP:AMBER",
            }
        ]
        connector.process_message(message)
        sent = {o["id"]: o for o in connector._send_bundle.call_args[0][0]}
        assert sent["note--1"]["object_marking_refs"] == [TLP_AMBER]
        definition = sent[TLP_AMBER]
        assert definition["type"] == "marking-definition"
        assert definition["definition_type"] == "tlp"
        assert definition["definition"] == {"tlp": "amber"}
        assert definition["x_opencti_definition"] == "TLP:AMBER"

    def test_marking_definition_is_not_duplicated_when_already_present(self):
        connector = _connector(_make_client())
        present = {"id": TLP_AMBER, "type": "marking-definition"}
        objects = [
            present,
            {"id": "note--1", "type": "note", "object_marking_refs": [TLP_AMBER]},
        ]
        assert connector._with_marking_definitions(objects, {}) == objects

    def test_exported_definition_from_the_message_is_used_first(self):
        connector = _connector(_make_client())
        exported = {
            "id": TLP_AMBER,
            "type": "marking-definition",
            "definition_type": "statement",
        }
        connector.stix_objects_list = [exported]
        objects = [
            {"id": "note--1", "type": "note", "object_marking_refs": [TLP_AMBER]}
        ]
        entity = {
            "objectMarking": [
                {
                    "standard_id": TLP_AMBER,
                    "definition_type": "TLP",
                    "definition": "TLP:AMBER",
                }
            ]
        }
        out = connector._with_marking_definitions(objects, entity)
        assert out[-1] is exported

    def test_non_dict_object_marking_entry_is_skipped(self):
        connector = _connector(_make_client())
        objects = [
            {"id": "note--1", "type": "note", "object_marking_refs": [TLP_AMBER]}
        ]
        entity = {
            "objectMarking": [
                "junk",
                None,
                {
                    "standard_id": TLP_AMBER,
                    "definition_type": "TLP",
                    "definition": "TLP:AMBER",
                },
            ]
        }
        out = connector._with_marking_definitions(objects, entity)
        assert out[-1]["id"] == TLP_AMBER

    def test_unresolvable_marking_is_left_alone(self):
        connector = _connector(_make_client())
        objects = [
            {"id": "note--1", "type": "note", "object_marking_refs": [TLP_GREEN]}
        ]
        assert connector._with_marking_definitions(objects, {}) == objects

    @pytest.mark.parametrize("with_definition", [False, True])
    def test_opencti_cleanup_keeps_markings_only_when_defined(self, with_definition):
        """pycti's cleanup removes refs to objects the bundle lacks."""
        from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter

        connector = _connector(_make_client())
        objects = [
            {"id": "note--1", "type": "note", "object_marking_refs": [TLP_AMBER]}
        ]
        if with_definition:
            objects = connector._with_marking_definitions(
                objects,
                {
                    "objectMarking": [
                        {
                            "standard_id": TLP_AMBER,
                            "definition_type": "TLP",
                            "definition": "TLP:AMBER",
                        }
                    ]
                },
            )
        bundle = {"type": "bundle", "id": "bundle--1", "objects": objects}
        _n, _bad, bundles = OpenCTIStix2Splitter().split_bundle_with_expectations(
            bundle, use_json=False, cleanup_inconsistent_bundle=True
        )
        note = next(o for b in bundles for o in b["objects"] if o["id"] == "note--1")
        assert note["object_marking_refs"] == ([TLP_AMBER] if with_definition else [])

    def test_hash_enrichment_objects_carry_the_source_markings(self):
        connector = _connector(_make_client())
        self._wire(connector, None)
        connector._collect_intelligence = MagicMock(
            return_value=[
                {"id": FILE_ID, "type": "file"},
                {"id": "marking-definition--x", "type": "marking-definition"},
                {"id": "indicator--1", "type": "indicator"},
                {"id": "malware--1", "type": "malware"},
                {"id": "note--1", "type": "note"},
                {
                    "id": "relationship--1",
                    "type": "relationship",
                    "source_ref": "indicator--1",
                    "target_ref": "malware--1",
                },
                {
                    "id": "relationship--2",
                    "type": "relationship",
                    "source_ref": FILE_ID,
                    "target_ref": "malware--1",
                    "object_marking_refs": [TLP_GREEN],
                },
                {
                    "id": "relationship--3",
                    "type": "relationship",
                    "source_ref": "malware--1",
                    "target_ref": "attack-pattern--1",
                },
            ]
        )
        message = self._file_message()
        message["stix_entity"] = {
            **message["stix_entity"],
            "object_marking_refs": [TLP_AMBER],
        }
        connector.process_message(message)
        sent = {o["id"]: o for o in connector._send_bundle.call_args[0][0]}
        for obj_id in (
            "indicator--1",
            "note--1",
            "relationship--1",
        ):
            assert sent[obj_id]["object_marking_refs"] == [TLP_AMBER]
        assert sent["relationship--2"]["object_marking_refs"] == [
            TLP_GREEN,
            TLP_AMBER,
        ]
        for obj_id in (
            FILE_ID,
            "marking-definition--x",
            "malware--1",
            "relationship--3",
        ):
            assert "object_marking_refs" not in sent[obj_id]

    def test_reuses_the_imphash_the_ioc_step_already_read(self):
        connector = _connector(_make_client())
        self._wire(connector, None)

        def collect(*_a, **_k):
            connector._last_ioc_data = {"imphash": IMPHASH}
            return [{"id": FILE_ID, "type": "file"}]

        connector._collect_intelligence = MagicMock(side_effect=collect)
        connector.process_message(self._file_message())
        connector.client.fetch_iocs.assert_not_called()
        connector.client.polyswarm.search_by_ioc.assert_called_once_with(
            imphash=IMPHASH
        )

    def test_ioc_step_ran_without_imphash_does_not_refetch(self):
        connector = _connector(_make_client())
        self._wire(connector, None)

        def collect(*_a, **_k):
            connector._last_ioc_data = None  # fetched, nothing found
            return [{"id": FILE_ID, "type": "file"}]

        connector._collect_intelligence = MagicMock(side_effect=collect)
        connector.process_message(self._file_message())
        connector.client.fetch_iocs.assert_not_called()
        connector.client.polyswarm.search_by_ioc.assert_not_called()

    def test_pivot_result_file_never_pivots_again(self):
        connector = _connector(_make_client())
        self._wire(connector, {"imphash": IMPHASH})
        message = self._file_message()
        message["stix_entity"] = {
            **message["stix_entity"],
            "x_opencti_labels": [PIVOT_LABEL],
        }
        connector.process_message(message)
        connector.client.polyswarm.search_by_ioc.assert_not_called()

    def test_pivot_result_label_read_from_opencti_entity(self):
        connector = _connector(_make_client())
        self._wire(connector, {"imphash": IMPHASH})
        message = self._file_message()
        message["enrichment_entity"]["objectLabel"] = [{"value": PIVOT_LABEL}]
        connector.process_message(message)
        connector.client.polyswarm.search_by_ioc.assert_not_called()

    def test_pivot_off_makes_no_extra_call(self):
        connector = _connector(_make_client(), imphash_max=0)
        self._wire(connector, {"imphash": IMPHASH})
        connector.process_message(self._file_message())
        connector.client.fetch_iocs.assert_not_called()
        connector.client.polyswarm.search_by_ioc.assert_not_called()

    def test_no_imphash_means_no_search(self):
        connector = _connector(_make_client())
        self._wire(connector, {"imphash": ""})
        connector.process_message(self._file_message())
        connector.client.polyswarm.search_by_ioc.assert_not_called()

    def test_pivot_failure_does_not_lose_the_enrichment(self):
        connector = _connector(_make_client())
        self._wire(connector, {"imphash": IMPHASH})
        connector.pivots.imphash_objects = MagicMock(side_effect=RuntimeError("x"))
        assert connector.process_message(self._file_message()) == "[CONNECTOR] sent"

    def test_stale_ioc_data_from_a_previous_file_is_not_reused(self):
        connector = _connector(_make_client())
        self._wire(connector, {"imphash": "f" * 32})
        connector._last_ioc_data = {"imphash": IMPHASH}
        connector.process_message(self._file_message())
        connector.client.polyswarm.search_by_ioc.assert_called_once_with(
            imphash="f" * 32
        )


# ===========================================================================
# Settings
# ===========================================================================
def _settings_from(polyswarm=None, connector=None):
    """ConnectorSettings from a fake config dict (no env or file)."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler):
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {"id": "connector-id", **(connector or {})},
                    "polyswarm": {"api_key": "test-key", **(polyswarm or {})},
                }
            )

    return FakeConnectorSettings()


class TestPivotSettings:
    def test_both_pivots_default_to_off(self):
        settings = _settings_from({})
        assert settings.polyswarm.pivot_imphash_max == 0
        assert settings.polyswarm.pivot_ttp_max == 0

    def test_attack_pattern_not_in_default_scope(self):
        assert "Attack-Pattern" not in _settings_from({}).connector.scope

    def test_ttp_pivot_adds_attack_pattern_to_scope(self):
        settings = _settings_from({"pivot_ttp_max": 10})
        assert settings.polyswarm.pivot_ttp_max == 10
        assert settings.connector.scope[-1] == "Attack-Pattern"
        assert settings.connector.scope.count("Attack-Pattern") == 1
        # ...and it reaches the helper config the platform registers
        assert "Attack-Pattern" in settings.to_helper_config()["connector"]["scope"]

    def test_ttp_pivot_does_not_duplicate_an_explicit_scope_entry(self):
        settings = _settings_from(
            {"pivot_ttp_max": 5}, {"scope": "StixFile,attack-pattern"}
        )
        assert [s.lower() for s in settings.connector.scope].count(
            "attack-pattern"
        ) == 1

    def test_imphash_pivot_leaves_scope_alone(self):
        settings = _settings_from({"pivot_imphash_max": 10})
        assert settings.polyswarm.pivot_imphash_max == 10
        assert "Attack-Pattern" not in settings.connector.scope

    @pytest.mark.parametrize("name", ["pivot_imphash_max", "pivot_ttp_max"])
    @pytest.mark.parametrize("value", [-1, 101])
    def test_limits_are_bounded(self, name, value):
        with pytest.raises(ConfigValidationError):
            _settings_from({name: value})


class TestScopeWithPivotsAndYaraHunt:
    """The scope validator serves both features: each type added once."""

    def test_both_features_add_both_types_once(self):
        settings = _settings_from({"pivot_ttp_max": 5, "yara_hunt_enabled": True})
        scope = list(settings.connector.scope)
        assert scope.count("Attack-Pattern") == 1
        assert scope.count("Indicator") == 1
        assert scope[:2] == ["StixFile", "Artifact"]
        helper_scope = settings.to_helper_config()["connector"]["scope"]
        assert "Attack-Pattern" in helper_scope and "Indicator" in helper_scope

    def test_each_feature_adds_only_its_own_type(self):
        pivot_only = _settings_from({"pivot_ttp_max": 5}).connector.scope
        assert "Attack-Pattern" in pivot_only and "Indicator" not in pivot_only
        yara_only = _settings_from({"yara_hunt_enabled": True}).connector.scope
        assert "Indicator" in yara_only and "Attack-Pattern" not in yara_only

    def test_neither_feature_leaves_default_scope(self):
        scope = _settings_from({"pivot_imphash_max": 5}).connector.scope
        assert "Attack-Pattern" not in scope and "Indicator" not in scope

    def test_configured_types_are_not_duplicated(self):
        settings = _settings_from(
            {"pivot_ttp_max": 5, "yara_hunt_enabled": True},
            {"scope": "StixFile,attack-pattern,indicator"},
        )
        lowered = [item.lower() for item in settings.connector.scope]
        assert lowered.count("attack-pattern") == 1
        assert lowered.count("indicator") == 1
