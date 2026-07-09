import json
from unittest.mock import MagicMock

import pytest
from connector.connector import VulnersConnector
from pydantic import SecretStr


def _tlp_marking(definition: str) -> dict:
    """Build a resolved OpenCTI TLP marking definition, as pycti exposes it."""
    return {"definition_type": "TLP", "definition": definition}


@pytest.fixture
def fake_bundle() -> dict:
    """A minimal, STIX-ish bundle as returned by the Vulners backend."""
    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000001",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": "vulnerability--11111111-1111-1111-1111-111111111111",
                "name": "CVE-2021-44228",
            }
        ],
    }


def _make_helper(*, check_max_tlp_result: bool = True) -> MagicMock:
    """Build a fake `OpenCTIConnectorHelper`."""
    helper = MagicMock()
    helper.work_id = None
    helper.check_max_tlp.return_value = check_max_tlp_result
    helper.send_stix2_bundle.return_value = ["bundle-1"]
    helper.stix2_create_bundle.side_effect = lambda objects: json.dumps(
        {"type": "bundle", "objects": objects}
    )
    # connector_logger is used via .info/.debug/.warning
    helper.connector_logger = MagicMock()
    return helper


def _make_settings() -> MagicMock:
    settings = MagicMock()
    settings.vulners.api_key = SecretStr("test-api-key")
    settings.vulners.api_base_url = "https://vulners.com"
    settings.vulners.max_tlp_level = "TLP:AMBER"
    return settings


def _build_connector(helper, settings, monkeypatch) -> VulnersConnector:
    """Instantiate the connector with the Vulners SDK call patched out."""
    # Patch the client constructor so no real VulnersApi is created.
    monkeypatch.setattr(
        "connector.connector.VulnersClient", lambda api_key, base_url: MagicMock()
    )
    return VulnersConnector(helper=helper, settings=settings)


def _make_message(
    *,
    marking_definition: str | None,
    name: str = "CVE-2021-44228",
    event_type: str | None = None,
) -> dict:
    """
    Build an enrichment message as pycti delivers it to the callback.

    The connector reads the TLP from the resolved ``enrichment_entity``
    (``objectMarking``), not from ``stix_entity``. Messages coming from a
    playbook carry no ``event_type``; manual/internal enrichments do.
    """
    object_marking = [_tlp_marking(marking_definition)] if marking_definition else []
    stix_entity = {
        "id": "vulnerability--11111111-1111-1111-1111-111111111111",
        "name": name,
    }
    message = {
        "stix_entity": stix_entity,
        "stix_entity_id": "vulnerability--11111111-1111-1111-1111-111111111111",
        "stix_objects": [stix_entity],
        "enrichment_entity": {
            "standard_id": "vulnerability--11111111-1111-1111-1111-111111111111",
            "objectMarking": object_marking,
        },
        "work_id": "work-123",
    }
    if event_type is not None:
        message["event_type"] = event_type
    return message


def test_in_scope_vulnerability_sends_bundle(monkeypatch, fake_bundle):
    """A Vulnerability within max TLP triggers send_stix2_bundle with the bundle."""
    helper = _make_helper(check_max_tlp_result=True)
    settings = _make_settings()
    connector = _build_connector(helper, settings, monkeypatch)

    # Patch the bundle fetch to return our fixture.
    monkeypatch.setattr(connector.client, "get_bundle", lambda *a, **k: fake_bundle)

    data = _make_message(marking_definition="TLP:AMBER")

    result = connector.process_message(data)

    assert result == "Done"
    helper.check_max_tlp.assert_called_once_with("TLP:AMBER", "TLP:AMBER")
    helper.send_stix2_bundle.assert_called_once()
    sent_payload = helper.send_stix2_bundle.call_args.args[0]
    assert json.loads(sent_payload) == fake_bundle
    assert helper.send_stix2_bundle.call_args.kwargs["work_id"] == "work-123"
    assert helper.send_stix2_bundle.call_args.kwargs["update"] is True
    helper.api.work.to_processed.assert_called_once_with(
        "work-123", "Enrichment completed"
    )


def test_no_marking_defaults_to_clear_and_enriches(monkeypatch, fake_bundle):
    """An entity with no TLP marking defaults to TLP:CLEAR and is enriched."""
    helper = _make_helper(check_max_tlp_result=True)
    settings = _make_settings()
    connector = _build_connector(helper, settings, monkeypatch)

    monkeypatch.setattr(connector.client, "get_bundle", lambda *a, **k: fake_bundle)

    data = _make_message(marking_definition=None)

    result = connector.process_message(data)

    assert result == "Done"
    helper.check_max_tlp.assert_called_once_with("TLP:CLEAR", "TLP:AMBER")
    helper.send_stix2_bundle.assert_called_once()


def test_tlp_above_max_passes_inbound_bundle_through(monkeypatch, fake_bundle):
    """
    Playbook context (no event_type): an entity above max_tlp is not enriched,
    but the inbound bundle is forwarded unchanged so the playbook can continue.
    """
    helper = _make_helper(check_max_tlp_result=False)
    settings = _make_settings()
    connector = _build_connector(helper, settings, monkeypatch)

    get_bundle = MagicMock(return_value=fake_bundle)
    monkeypatch.setattr(connector.client, "get_bundle", get_bundle)

    data = _make_message(marking_definition="TLP:RED")

    result = connector.process_message(data)

    assert result == "Skipped (TLP too high)"
    helper.check_max_tlp.assert_called_once_with("TLP:RED", "TLP:AMBER")
    # No Vulners data must be fetched when the TLP gate blocks the entity.
    get_bundle.assert_not_called()
    # The inbound bundle is passed through unchanged.
    helper.send_stix2_bundle.assert_called_once()
    sent_payload = helper.send_stix2_bundle.call_args.args[0]
    assert json.loads(sent_payload)["objects"] == data["stix_objects"]
    assert (
        helper.send_stix2_bundle.call_args.kwargs["cleanup_inconsistent_bundle"] is True
    )
    # The work must be closed so it does not stay stuck in progress.
    helper.api.work.to_processed.assert_called_once_with(
        "work-123", "Skipped: TLP of the entity exceeds the max TLP"
    )


def test_tlp_above_max_manual_enrichment_sends_nothing(monkeypatch, fake_bundle):
    """Manual/internal enrichment (event_type present): skip without sending."""
    helper = _make_helper(check_max_tlp_result=False)
    settings = _make_settings()
    connector = _build_connector(helper, settings, monkeypatch)

    get_bundle = MagicMock(return_value=fake_bundle)
    monkeypatch.setattr(connector.client, "get_bundle", get_bundle)

    data = _make_message(marking_definition="TLP:RED", event_type="create")

    result = connector.process_message(data)

    assert result == "Skipped (TLP too high)"
    get_bundle.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_non_cve_name_is_skipped_with_passthrough(monkeypatch, fake_bundle):
    """A Vulnerability whose name is not a CVE id is skipped, bundle forwarded."""
    helper = _make_helper(check_max_tlp_result=True)
    settings = _make_settings()
    connector = _build_connector(helper, settings, monkeypatch)

    get_bundle = MagicMock(return_value=fake_bundle)
    monkeypatch.setattr(connector.client, "get_bundle", get_bundle)

    data = _make_message(marking_definition="TLP:AMBER", name="Log4Shell")

    result = connector.process_message(data)

    assert result == "Skipped (not a CVE identifier)"
    # The Vulners API must not be called with a non-CVE identifier.
    get_bundle.assert_not_called()
    helper.send_stix2_bundle.assert_called_once()
    helper.api.work.to_processed.assert_called_once_with(
        "work-123", "Skipped: entity name is not a CVE identifier"
    )


def test_empty_bundle_is_skipped_with_passthrough(monkeypatch):
    """An empty bundle from Vulners forwards the inbound bundle and closes work."""
    helper = _make_helper(check_max_tlp_result=True)
    settings = _make_settings()
    connector = _build_connector(helper, settings, monkeypatch)

    monkeypatch.setattr(connector.client, "get_bundle", lambda *a, **k: {})

    data = _make_message(marking_definition="TLP:AMBER")

    result = connector.process_message(data)

    assert result == "No data"
    helper.send_stix2_bundle.assert_called_once()
    sent_payload = helper.send_stix2_bundle.call_args.args[0]
    assert json.loads(sent_payload)["objects"] == data["stix_objects"]
    helper.api.work.to_processed.assert_called_once_with(
        "work-123", "No data from Vulners for this CVE"
    )


def test_missing_stix_entity_raises(monkeypatch):
    """A message without stix_entity raises ValueError."""
    helper = _make_helper()
    settings = _make_settings()
    connector = _build_connector(helper, settings, monkeypatch)

    with pytest.raises(ValueError, match="No stix_entity in message"):
        connector.process_message({})
