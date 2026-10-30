import json
from unittest.mock import MagicMock

import pytest
from connector.connector import StairwellConnector
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


@pytest.fixture
def env(monkeypatch):
    for key, value in {
        "OPENCTI_URL": "http://opencti:8080",
        "OPENCTI_TOKEN": "token",
        "CONNECTOR_ID": "11111111-1111-4111-8111-111111111111",
        "CONNECTOR_SCOPE": "StixFile,Domain-Name,IPv4-Addr,IPv6-Addr,Autonomous-System",
        "STAIRWELL_API_TOKEN": "sw-token",
    }.items():
        monkeypatch.setenv(key, value)
    return monkeypatch


def _connector():
    helper = MagicMock()
    # The real static check, so a wrong max-TLP format fails as it would live.
    helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp
    helper.stix2_create_bundle.side_effect = lambda objects: json.dumps(
        {"type": "bundle", "id": "bundle--0", "objects": objects}
    )
    connector = StairwellConnector(config=ConnectorSettings(), helper=helper)
    connector.client._session = MagicMock()
    return connector, helper


def _message(*tlps):
    observable = {
        "id": "x",
        "standard_id": "file--1",
        "entity_type": "StixFile",
        "hashes": [{"algorithm": "SHA-256", "hash": "a" * 64}],
        "objectMarking": [
            {"definition_type": "TLP", "definition": tlp} for tlp in tlps
        ],
    }
    # Shape of a manual enrichment message from pycti: the entity is
    # included, and `event_type` is set (a playbook message has none).
    data = {
        "entity_id": "x",
        "event_type": "INTERNAL_ENRICHMENT",
        "stix_entity": {"id": "file--1"},
        "enrichment_entity": observable,
    }
    return data, observable


def test_api_token_is_secret_and_reaches_the_client(env):
    settings = ConnectorSettings()
    assert "sw-token" not in repr(settings) and "sw-token" not in str(
        settings.model_dump()
    )
    fresh = StairwellConnector(config=ConnectorSettings(), helper=MagicMock())
    assert fresh.client._session.headers["Authorization"] == "Bearer sw-token"


def test_defaults_are_amber_max_tlp_and_no_sightings(env):
    settings = ConnectorSettings()
    assert settings.connector.max_tlp.value == "amber"
    assert not hasattr(settings.stairwell, "max_tlp_level")
    assert settings.stairwell.sightings_limit == 0
    connector, _ = _connector()
    assert connector.dispatcher.max_tlp == "TLP:AMBER"
    assert connector.dispatcher.file.sightings_limit == 0


@pytest.mark.parametrize(
    "configured", ["clear", "white", "green", "amber", "amber+strict", "red"]
)
def test_every_configurable_max_tlp_works_with_pycti(env, configured):
    env.setenv("CONNECTOR_MAX_TLP", configured)
    connector, helper = _connector()
    data, _ = _message("TLP:CLEAR")
    connector.dispatcher.file.enrich = MagicMock(return_value="enriched")
    assert connector.process_message(data) == "enriched"


def test_observable_above_max_tlp_is_never_sent_to_stairwell(env):
    connector, helper = _connector()
    data, _ = _message("TLP:GREEN", "TLP:RED")
    with pytest.raises(ValueError, match="max TLP"):
        connector.process_message(data)
    connector.client._session.get.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


@pytest.mark.parametrize(
    "configured, observable_tlp, allowed",
    [
        ("green", "TLP:AMBER", False),
        ("green", "TLP:GREEN", True),
        ("red", "TLP:RED", True),
        ("amber+strict", "TLP:AMBER+STRICT", True),
        ("amber", "TLP:AMBER+STRICT", False),
    ],
)
def test_configured_max_tlp_reaches_the_gate(env, configured, observable_tlp, allowed):
    env.setenv("CONNECTOR_MAX_TLP", configured)
    connector, helper = _connector()
    data, _ = _message(observable_tlp)
    connector.dispatcher.file.enrich = MagicMock(return_value="enriched")
    if allowed:
        assert connector.process_message(data) == "enriched"
    else:
        with pytest.raises(ValueError, match="max TLP"):
            connector.process_message(data)
        connector.dispatcher.file.enrich.assert_not_called()


def test_uses_the_entity_pycti_already_resolved(env):
    connector, helper = _connector()
    data, _ = _message("TLP:GREEN")
    connector.dispatcher.file.enrich = MagicMock(return_value="enriched")
    assert connector.process_message(data) == "enriched"
    connector.dispatcher.file.enrich.assert_called_once_with(data["enrichment_entity"])
    helper.api.stix_cyber_observable.read.assert_not_called()


def _out_of_scope_message(playbook):
    entity = {"id": "x", "entity_type": "Report", "objectMarking": []}
    data = {
        "entity_id": "report--1",
        "stix_entity": {"id": "report--1", "type": "report"},
        "enrichment_entity": entity,
        "stix_objects": [{"id": "report--1", "type": "report"}],
    }
    if not playbook:
        data["event_type"] = "INTERNAL_ENRICHMENT"
    return data


def test_playbook_entity_out_of_scope_gets_its_bundle_back_unchanged(env):
    connector, helper = _connector()
    helper.stix2_create_bundle.side_effect = lambda objs: {"objects": objs}
    connector.process_message(_out_of_scope_message(playbook=True))
    helper.stix2_create_bundle.assert_called_once_with(
        [{"id": "report--1", "type": "report"}]
    )
    helper.send_stix2_bundle.assert_called_once_with(
        {"objects": [{"id": "report--1", "type": "report"}]},
        cleanup_inconsistent_bundle=True,
    )
    connector.client._session.get.assert_not_called()


def test_manual_enrichment_out_of_scope_is_an_error(env):
    connector, helper = _connector()
    with pytest.raises(ValueError, match="not a supported entity type"):
        connector.process_message(_out_of_scope_message(playbook=False))
    helper.send_stix2_bundle.assert_not_called()


ORIGINAL = [
    {"id": "file--1", "type": "file", "hashes": {"SHA-256": "a" * 64}},
    {"id": "report--9", "type": "report", "name": "from an earlier step"},
]


def _playbook_message(entity_type="StixFile", tlp="TLP:GREEN"):
    data, observable = _message(tlp)
    observable["entity_type"] = entity_type
    del data["event_type"]
    data["stix_objects"] = [dict(o) for o in ORIGINAL]
    return data


def _sent_objects(helper, call=-1):
    return json.loads(helper.send_stix2_bundle.call_args_list[call].args[0])["objects"]


def _send_from_enricher(connector, objects):
    """What an enricher does: send through the helper it was built with."""
    connector.dispatcher.file.helper.send_stix2_bundle(
        json.dumps({"type": "bundle", "id": "bundle--x", "objects": objects}),
        cleanup_inconsistent_bundle=True,
    )


def test_playbook_result_keeps_the_objects_of_earlier_steps(env):
    connector, helper = _connector()
    enriched = {"id": "file--1", "type": "file", "x_opencti_score": 75}
    note = {"id": "note--2", "type": "note", "content": "c"}

    def enrich(_):
        _send_from_enricher(connector, [enriched, note])
        return "enriched"

    connector.dispatcher.file.enrich = enrich
    assert connector.process_message(_playbook_message()) == "enriched"
    helper.send_stix2_bundle.assert_called_once()
    sent = {o["id"]: o for o in _sent_objects(helper)}
    assert set(sent) == {"file--1", "note--2", "report--9"}
    assert sent["file--1"]["x_opencti_score"] == 75
    # update=True, or OpenCTI keeps an observable's existing score and
    # description instead of the enrichment's.
    assert helper.send_stix2_bundle.call_args.kwargs == {
        "cleanup_inconsistent_bundle": True,
        "update": True,
    }


def test_manual_enrichment_sends_with_update(env):
    connector, helper = _connector()
    data, _ = _message("TLP:GREEN")

    def enrich(_):
        _send_from_enricher(connector, [{"id": "file--1", "type": "file"}])
        return "enriched"

    connector.dispatcher.file.enrich = enrich
    connector.process_message(data)
    assert helper.send_stix2_bundle.call_args.kwargs["update"] is True


GREEN = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"


def test_playbook_merge_keeps_what_the_partial_update_leaves_out(env):
    connector, helper = _connector()
    data = _playbook_message()
    data["stix_objects"][0] = {
        "id": "file--1",
        "type": "file",
        "name": "invoice.exe",
        "hashes": {"SHA-256": "a" * 64},
        "labels": ["from-earlier-step"],
        "object_marking_refs": [GREEN],
        "external_references": [{"source_name": "earlier"}],
        "x_opencti_score": 40,
    }
    enriched = {
        "id": "file--1",
        "type": "file",
        "hashes": {"SHA-256": "a" * 64, "MD5": "b" * 32},
        "labels": ["stairwell:yara:rule"],
        "object_marking_refs": [AMBER],
        "external_references": [{"source_name": "Stairwell"}],
        "x_opencti_score": 75,
    }

    def enrich(_):
        _send_from_enricher(connector, [enriched])
        return "enriched"

    connector.dispatcher.file.enrich = enrich
    connector.process_message(data)
    merged = {o["id"]: o for o in _sent_objects(helper)}["file--1"]
    assert merged["name"] == "invoice.exe"
    assert merged["hashes"] == {"SHA-256": "a" * 64, "MD5": "b" * 32}
    assert merged["labels"] == ["from-earlier-step", "stairwell:yara:rule"]
    assert merged["object_marking_refs"] == [GREEN, AMBER]
    assert merged["external_references"] == [
        {"source_name": "earlier"},
        {"source_name": "Stairwell"},
    ]
    assert merged["x_opencti_score"] == 75  # the enricher's scalar wins


@pytest.mark.parametrize(
    "outcome",
    [
        MagicMock(return_value="Stairwell: hash not in corpus"),
        MagicMock(side_effect=RuntimeError("Stairwell down")),
    ],
)
def test_playbook_gets_its_bundle_back_on_no_result_or_error(env, outcome):
    connector, helper = _connector()
    connector.dispatcher.file.enrich = outcome
    connector.process_message(_playbook_message())
    helper.send_stix2_bundle.assert_called_once()
    assert _sent_objects(helper) == ORIGINAL


def test_playbook_gets_its_bundle_back_when_tlp_refuses(env):
    connector, helper = _connector()
    connector.dispatcher.file.enrich = MagicMock()
    connector.process_message(_playbook_message(tlp="TLP:RED"))
    connector.dispatcher.file.enrich.assert_not_called()
    connector.client._session.get.assert_not_called()
    assert _sent_objects(helper) == ORIGINAL


def test_manual_enrichment_errors_still_raise(env):
    connector, helper = _connector()
    connector.dispatcher.file.enrich = MagicMock(side_effect=RuntimeError("down"))
    data, _ = _message("TLP:GREEN")
    with pytest.raises(RuntimeError):
        connector.process_message(data)
    helper.send_stix2_bundle.assert_not_called()


def test_scope_defaults_to_every_supported_type(env):
    env.delenv("CONNECTOR_SCOPE")
    assert ConnectorSettings().connector.scope == [
        "StixFile",
        "Domain-Name",
        "IPv4-Addr",
        "IPv6-Addr",
        "Autonomous-System",
    ]


def test_configured_scope_is_enforced(env):
    env.setenv("CONNECTOR_SCOPE", "StixFile")
    connector, helper = _connector()
    connector.dispatcher.domain.enrich = MagicMock()
    connector.process_message(_playbook_message(entity_type="Domain-Name"))
    connector.dispatcher.domain.enrich.assert_not_called()
    assert _sent_objects(helper) == ORIGINAL
    data, observable = _message("TLP:GREEN")
    observable["entity_type"] = "Domain-Name"
    with pytest.raises(ValueError, match="not a supported entity type"):
        connector.process_message(data)
    connector.dispatcher.domain.enrich.assert_not_called()


@pytest.mark.parametrize("drop", ["enrichment_entity", "stix_entity_and_entity_id"])
def test_playbook_early_returns_still_hand_the_bundle_on(env, drop):
    connector, helper = _connector()
    data = _playbook_message()
    if drop == "enrichment_entity":
        del data["enrichment_entity"]
    else:
        del data["stix_entity"], data["entity_id"]
    connector.process_message(data)
    assert _sent_objects(helper) == ORIGINAL


def test_failed_enrichment_send_falls_back_to_the_incoming_bundle(env):
    connector, helper = _connector()
    helper.send_stix2_bundle.side_effect = [RuntimeError("queue down"), None]

    def enrich(_):
        _send_from_enricher(connector, [{"id": "note--2", "type": "note"}])
        return "enriched"

    connector.dispatcher.file.enrich = enrich
    connector.process_message(_playbook_message())
    assert helper.send_stix2_bundle.call_count == 2
    assert _sent_objects(helper) == ORIGINAL


def test_playbook_not_found_merges_the_label_into_the_incoming_bundle(env):
    connector, helper = _connector()
    connector.client.get_object_metadata = MagicMock(return_value=(404, None))
    data = _playbook_message()
    data["stix_objects"][0].update(name="invoice.exe", labels=["from-earlier-step"])
    message = connector.process_message(data)
    assert "not in corpus" in message
    helper.send_stix2_bundle.assert_called_once()
    sent = {o["id"]: o for o in _sent_objects(helper)}
    assert set(sent) >= {"file--1", "report--9"}
    assert sent["file--1"]["name"] == "invoice.exe"
    assert sent["file--1"]["hashes"] == {"SHA-256": "a" * 64}
    assert sent["file--1"]["labels"] == ["from-earlier-step", "stairwell:not-found"]
    assert sent["report--9"] == ORIGINAL[1]


RED = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"


@pytest.mark.parametrize(
    "refs, extra_objects, refused",
    [
        # The playbook input is RED while the stored entity is GREEN.
        ([RED], [], True),
        # A TLP carried as a marking-definition object in the bundle.
        (
            ["marking-definition--custom-red"],
            [
                {
                    "id": "marking-definition--custom-red",
                    "type": "marking-definition",
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:RED",
                }
            ],
            True,
        ),
        (
            ["marking-definition--stix-red"],
            [
                {
                    "id": "marking-definition--stix-red",
                    "type": "marking-definition",
                    "definition_type": "tlp",
                    "definition": {"tlp": "red"},
                }
            ],
            True,
        ),
        # The SDK's AMBER+STRICT form: a STIX statement carrying an OpenCTI TLP.
        (
            ["marking-definition--custom-strict"],
            [
                {
                    "id": "marking-definition--custom-strict",
                    "type": "marking-definition",
                    "definition_type": "statement",
                    "definition": {"statement": "custom"},
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                }
            ],
            True,
        ),
        ([AMBER], [], False),
        # A non-TLP marking OpenCTI knows is not a TLP restriction.
        (["marking-definition--pap"], [], False),
        # Resolved through OpenCTI: a TLP stored under OpenCTI's own ID.
        (["marking-definition--opencti-red"], [], True),
        (["marking-definition--opencti-green"], [], False),
        # Neither standard, nor in the bundle, nor known to OpenCTI: refused.
        (["marking-definition--unknown"], [], True),
        (["marking-definition--lookup-fails"], [], True),
    ],
)
def test_playbook_input_markings_are_gated_too(env, refs, extra_objects, refused):
    connector, helper = _connector()
    known = {
        "marking-definition--pap": {"definition_type": "PAP", "definition": "PAP:RED"},
        "marking-definition--opencti-red": {
            "definition_type": "TLP",
            "definition": "TLP:RED",
        },
        "marking-definition--opencti-green": {
            "definition_type": "TLP",
            "definition": "TLP:GREEN",
        },
    }

    def read(id):
        if id == "marking-definition--lookup-fails":
            raise RuntimeError("OpenCTI unavailable")
        return known.get(id)

    helper.api.marking_definition.read.side_effect = read
    data = _playbook_message(tlp="TLP:GREEN")
    data["stix_entity"]["object_marking_refs"] = refs
    data["stix_objects"].extend(extra_objects)
    connector.dispatcher.file.enrich = MagicMock(return_value="enriched")
    connector.process_message(data)
    if refused:
        connector.dispatcher.file.enrich.assert_not_called()
        assert _sent_objects(helper) == ORIGINAL + extra_objects
    else:
        connector.dispatcher.file.enrich.assert_called_once()


def test_playbook_merge_reads_a_score_held_in_the_opencti_extension(env):
    connector, helper = _connector()
    data = _playbook_message()
    data["stix_objects"][0]["extensions"] = {
        "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {"score": 95}
    }

    def enrich(_):
        _send_from_enricher(connector, [{"id": "file--1", "x_opencti_score": 75}])
        return "enriched"

    connector.dispatcher.file.enrich = enrich
    connector.process_message(data)
    merged = {o["id"]: o for o in _sent_objects(helper)}["file--1"]
    assert merged["x_opencti_score"] == 95


def test_playbook_merge_never_lowers_the_score(env):
    connector, helper = _connector()
    data = _playbook_message()
    data["stix_objects"][0]["x_opencti_score"] = 95

    def enrich(_):
        _send_from_enricher(connector, [{"id": "file--1", "x_opencti_score": 75}])
        return "enriched"

    connector.dispatcher.file.enrich = enrich
    connector.process_message(data)
    merged = {o["id"]: o for o in _sent_objects(helper)}["file--1"]
    assert merged["x_opencti_score"] == 95


def test_manual_not_found_is_sent_with_update(env):
    connector, helper = _connector()
    connector.client.get_object_metadata = MagicMock(return_value=(404, None))
    data, _ = _message("TLP:GREEN")
    assert "not in corpus" in connector.process_message(data)
    helper.send_stix2_bundle.assert_called_once()
    assert helper.send_stix2_bundle.call_args.kwargs["update"] is True
