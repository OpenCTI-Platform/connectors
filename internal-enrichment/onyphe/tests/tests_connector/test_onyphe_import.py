import json
from typing import Any
from unittest.mock import MagicMock, call

import pytest
import stix2
from internal_enrichment_connector.settings import ConnectorSettings
from onyphe_import import ONYPHEConnector
from pycti import Identity

CLEAR_ENTITY = {
    "id": "internal-id",
    "objectMarking": [{"definition_type": "TLP", "definition": "TLP:CLEAR"}],
}

IPV4_ENTITY = json.loads(stix2.IPv4Address(value="203.0.113.10").serialize())

INDICATOR_ENTITY = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--4d0b8f1e-0000-4000-8000-000000000001",
    "pattern": "ip.asn:AS64500",
    "pattern_type": "onyphe-oql",
    "x_opencti_score": 60,
}


def build_settings(**onyphe_overrides) -> ConnectorSettings:
    """Build `ConnectorSettings` from a dict instead of env vars or `config.yml`."""
    onyphe = {
        "api_key": "test-api-key",
        "time_since": "2w",
        "default_score": 42,
        "pivot_threshold": 5,
        "indicator_max_results": 3,
        "pattern_type": "onyphe-oql",
        **onyphe_overrides,
    }

    class StubConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "token"},
                    "connector": {"id": "connector-id", "name": "ONYPHE"},
                    "onyphe": onyphe,
                }
            )

    return StubConnectorSettings()


def build_helper() -> MagicMock:
    """Mock the OpenCTI helper: bundles are captured in `helper.sent` instead of sent."""
    helper = MagicMock()
    helper.get_name.return_value = "ONYPHE"
    helper.api.identity.create.return_value = {
        "standard_id": Identity.generate_id("ONYPHE", "organization")
    }
    helper.api.stix_core_relationship.list.return_value = []
    helper.sent = []
    helper.stix2_create_bundle.side_effect = lambda objects: [
        json.loads(o.serialize()) if hasattr(o, "serialize") else dict(o)
        for o in objects
    ]

    def send(bundle, **_):
        helper.sent.append(bundle)
        return ["bundle"]

    helper.send_stix2_bundle.side_effect = send
    return helper


@pytest.fixture
def onyphe_client(monkeypatch):
    """Mock the ONYPHE API client so no request leaves the test."""
    client_class = MagicMock()
    monkeypatch.setattr("onyphe_import.Onyphe", client_class)
    return client_class.return_value


def build_connector(**onyphe_overrides) -> ONYPHEConnector:
    return ONYPHEConnector(
        config=build_settings(**onyphe_overrides), helper=build_helper()
    )


def ctiscan_result(port: int, banner: str = "SSH-2.0-OpenSSH_9.2p1") -> dict:
    """A minimal ctiscan document, with the fields read by the description."""
    return {
        "@timestamp": "2026-11-20T08:12:45.000Z",
        "ip": {
            "dest": "203.0.113.10",
            "version": 4,
            "asn": "AS64500",
            "organization": "Example Hosting SAS",
            "country": "FR",
            "lcountry": "FR",
        },
        "tcp": {"dest": port},
        "app": {
            "transport": "tcp",
            "protocol": "ssh",
            "tls": "false",
            "data": {"text": banner},
        },
        "scanner": {"country": "NL"},
        "tag": ["datacenter"],
    }


def enrichment_message(entity: dict) -> dict:
    return {
        "stix_objects": [entity],
        "stix_entity": entity,
        "enrichment_entity": CLEAR_ENTITY,
    }


def sent_objects(connector: ONYPHEConnector) -> list[dict]:
    assert len(connector.helper.sent) == 1
    return connector.helper.sent[0]


def upserted_entity(connector: ONYPHEConnector, entity: dict) -> dict:
    return next(o for o in sent_objects(connector) if o["id"] == entity["id"])


@pytest.mark.parametrize("create_note", [False, True])
def test_observable_enrichment_should_use_settings(onyphe_client, create_note):
    """An observable under the threshold is searched and upserted with the settings."""
    connector = build_connector(create_note=create_note)
    onyphe_client.search_oql_paginated.return_value = {
        "total": 1,
        "results": [ctiscan_result(22)],
    }

    result = connector._process_message(enrichment_message(IPV4_ENTITY))

    assert result == "Sent 1 STIX bundle(s) for import"
    onyphe_client.search_oql_paginated.assert_called_once_with(
        "category:ctiscan ip.dest:203.0.113.10 -since:2w", limit=5
    )
    observable = upserted_entity(connector, IPV4_ENTITY)
    assert observable["x_opencti_score"] == 42
    notes = [o for o in sent_objects(connector) if o["type"] == "note"]
    if create_note:
        assert "x_opencti_description" not in observable
        assert len(notes) == 1
        assert notes[0]["object_refs"] == [IPV4_ENTITY["id"]]
    else:
        assert "SSH-2.0-OpenSSH_9.2p1" in observable["x_opencti_description"]
        assert notes == []


@pytest.mark.parametrize(
    "import_full_data, expected_length", [(False, 2048), (True, 3000)]
)
def test_observable_enrichment_should_truncate_banners_unless_import_full_data(
    onyphe_client, import_full_data, expected_length
):
    """`import_full_data` keeps the whole banner, otherwise it is cut at 2048 chars."""
    connector = build_connector(import_full_data=import_full_data)
    onyphe_client.search_oql_paginated.return_value = {
        "total": 1,
        "results": [ctiscan_result(22, banner="A" * 3000)],
    }

    connector._process_message(enrichment_message(IPV4_ENTITY))

    description = upserted_entity(connector, IPV4_ENTITY)["x_opencti_description"]
    assert "A" * expected_length in description
    assert "A" * (expected_length + 1) not in description


def test_observable_enrichment_should_skip_results_over_pivot_threshold(
    onyphe_client,
):
    """Above `pivot_threshold`, only the original objects are sent back."""
    connector = build_connector(pivot_threshold=5)
    onyphe_client.search_oql_paginated.return_value = {
        "total": 6,
        "results": [ctiscan_result(port) for port in range(5)],
    }

    result = connector._process_message(enrichment_message(IPV4_ENTITY))

    assert result == "Sent 0 bundles for import. Results over pivot threshold."
    assert sent_objects(connector) == [IPV4_ENTITY]


def test_indicator_enrichment_should_skip_results_over_indicator_max_results(
    onyphe_client,
):
    """Above `indicator_max_results`, the query is not paginated and nothing is imported."""
    connector = build_connector(indicator_max_results=3)
    onyphe_client.search_oql.return_value = {
        "total": 4,
        "results": [ctiscan_result(port) for port in range(3)],
    }

    result = connector._process_message(enrichment_message(INDICATOR_ENTITY))

    assert result == (
        "Sent 0 bundles for import. Indicator query returned 4 results, "
        "over the 3 limit."
    )
    onyphe_client.search_oql.assert_called_once_with(
        "category:ctiscan ip.asn:AS64500 -since:2w"
    )
    assert sent_objects(connector) == [INDICATOR_ENTITY]


def test_indicator_enrichment_should_paginate_and_import_search_results(
    onyphe_client,
):
    """Under `indicator_max_results`, every page is fetched and results are imported."""
    connector = build_connector(indicator_max_results=3, import_search_results=True)
    oql = "category:ctiscan ip.asn:AS64500 -since:2w"
    onyphe_client.search_oql.side_effect = [
        {"total": 3, "results": [ctiscan_result(22), ctiscan_result(80)]},
        {"total": 3, "results": [ctiscan_result(443)]},
    ]

    result = connector._process_message(enrichment_message(INDICATOR_ENTITY))

    assert result == "Sent 1 STIX bundle(s) for import"
    assert onyphe_client.search_oql.call_args_list == [call(oql), call(oql, page=2)]
    objects = sent_objects(connector)
    note = next(o for o in objects if o["type"] == "note")
    assert "| Total Results |3 |" in note["content"]
    assert any(o["type"] == "ipv4-addr" for o in objects)


def test_indicator_enrichment_should_only_summarize_without_import_search_results(
    onyphe_client,
):
    """Without `import_search_results`, only the summary fields are queried and noted."""
    connector = build_connector(import_search_results=False)
    onyphe_client.search_oql.return_value = {
        "total": 1,
        "results": [ctiscan_result(22)],
    }

    connector._process_message(enrichment_message(INDICATOR_ENTITY))

    oql = onyphe_client.search_oql.call_args.args[0]
    assert oql.startswith("category:ctiscan ip.asn:AS64500 -since:2w -fields:")
    types = {o["type"] for o in sent_objects(connector)}
    assert types == {"indicator", "note"}


def test_indicator_enrichment_should_keep_user_time_filter(onyphe_client):
    """A pattern with its own time filter does not get the `time_since` one."""
    connector = build_connector()
    onyphe_client.search_oql.return_value = {"total": 0, "results": []}

    connector._process_message(
        enrichment_message({**INDICATOR_ENTITY, "pattern": "ip.asn:AS64500 -dayago:3"})
    )

    onyphe_client.search_oql.assert_called_once_with(
        "category:ctiscan ip.asn:AS64500 -dayago:3"
    )


def test_indicator_enrichment_should_reject_other_pattern_types(onyphe_client):
    """An indicator whose pattern type is not `pattern_type` is not supported."""
    connector = build_connector(pattern_type="onyphe-oql")

    with pytest.raises(ValueError, match="Unsupported pattern type: stix"):
        connector._process_message(
            enrichment_message({**INDICATOR_ENTITY, "pattern_type": "stix"})
        )

    onyphe_client.search_oql.assert_not_called()
