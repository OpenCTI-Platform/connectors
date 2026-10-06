import json
import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"

INDICATOR_ID = "indicator--5a5b4c3d-2e1f-4a0b-9c8d-7e6f5a4b3c2d"
RFC_QUERY = "(name:*daily* OR name:*news*) AND (name:*armenia*)"

# Hosting used for the RFC query fixture, with real IP2ASN answers for armeniadaily.am
DNS_ANSWERS = {
    "armeniadaily.am": ["45.84.204.99", "2a02:4780:9:1582:0:26f7:e9b3:2"],
    # Same IP as armeniadaily.am: must not trigger a second IP2ASN call
    "armenianews.example": ["45.84.204.99"],
    "newsarmenia.example": ["203.0.113.10"],
    # Active but does not resolve
    "armenia-daily.example": [],
}


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def fake_resolve(domain: str) -> list[str]:
    return DNS_ANSWERS.get(domain, [])


class FakeResponse:
    def __init__(self, status_code: int, body: Any):
        self.status_code = status_code
        self._body = body
        self.ok = 200 <= status_code < 400
        self.reason = {
            403: "Forbidden",
            429: "Too Many Requests",
            503: "Service Unavailable",
        }.get(status_code, "OK")

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class FakeSession:
    """
    Stand-in for `requests.Session` that answers from fixtures and records every call.
    `routes` maps a URL suffix to a response, or a list of responses returned in turn.
    """

    def __init__(self, routes: dict[str, Any]):
        self.routes = routes
        self.calls: list[tuple[str, dict | None]] = []

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, params))
        for suffix, answer in self.routes.items():
            if url.endswith(suffix):
                if isinstance(answer, list):
                    answer = answer.pop(0) if len(answer) > 1 else answer[0]
                if isinstance(answer, Exception):
                    raise answer
                if isinstance(answer, FakeResponse):
                    return answer
                return FakeResponse(200, answer)
        return FakeResponse(404, {"status": "error", "data": f"no route for {url}"})

    def calls_to(self, suffix: str) -> list:
        return [call for call in self.calls if call[0].endswith(suffix)]


def default_routes(dataset: dict | None = None) -> dict:
    return {
        "/v2/dataset/domains": dataset
        or load_fixture("dataset_domains_rfc_query.json"),
        "/v1/ip2asn/45.84.204.99": load_fixture("ip2asn_45.84.204.99.json"),
        "/v1/ip2asn/2a02:4780:9:1582:0:26f7:e9b3:2": load_fixture(
            "ip2asn_2a02-4780-9-1582-0-26f7-e9b3-2.json"
        ),
        "/v1/ip2asn/203.0.113.10": {
            "ip": "203.0.113.10",
            "announced": True,
            "cidr": "203.0.113.0/24",
            "asn": 64500,
            "shortname": "  Example Hosting Ltd  ",
            "country": "NL",
        },
        "/v1/accountinfo": load_fixture("accountinfo.json"),
    }


def make_settings(**dnslytics: Any) -> ConnectorSettings:
    config = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {
            "id": "connector-id",
            "name": "DNSlytics",
            "scope": "Indicator",
            "log_level": "error",
        },
        "dnslytics": {"api_key": "test-api-key", **dnslytics},
    }

    class StubConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(config)

    return StubConnectorSettings()


def make_helper() -> MagicMock:
    helper = MagicMock()
    helper.check_max_tlp.side_effect = _check_max_tlp
    helper.stix2_create_bundle.side_effect = lambda objects: {"objects": list(objects)}
    helper.api.vocabulary.read.return_value = {"id": "vocab-id", "name": "dnslytics"}
    return helper


def _check_max_tlp(tlp: str, max_tlp: str) -> bool:
    from pycti import OpenCTIConnectorHelper

    return OpenCTIConnectorHelper.check_max_tlp(tlp, max_tlp)


def indicator_event(
    pattern: str = RFC_QUERY,
    pattern_type: str = "dnslytics",
    markings: list[dict] | None = None,
    event_type: str | None = "enrichment",
) -> dict:
    stix_indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": INDICATOR_ID,
        "name": "Storm-1516 Armenian news lookalikes",
        "pattern": pattern,
        "pattern_type": pattern_type,
        "valid_from": "2026-09-24T00:00:00.000Z",
    }
    event = {
        "entity_id": INDICATOR_ID,
        "entity_type": "Indicator",
        "enrichment_entity": {
            "entity_type": "Indicator",
            "standard_id": INDICATOR_ID,
            "objectMarking": markings or [],
        },
        "stix_entity": stix_indicator,
        "stix_objects": [stix_indicator],
    }
    if event_type:
        event["event_type"] = event_type
    return event


@pytest.fixture
def fake_dns(monkeypatch):
    monkeypatch.setattr("connector.hosting.resolve_domain", fake_resolve)


@pytest.fixture
def no_sleep(monkeypatch):
    monkeypatch.setattr("dnslytics_client.api_client.time.sleep", lambda _: None)
