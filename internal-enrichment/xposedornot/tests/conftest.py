import json
import os
import sys
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

from src.xposedornot.settings import ConnectorSettings  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
PYCTI_LOGGER_METHODS = ["debug", "info", "warning", "error"]
OBSERVABLE_ID = "email-addr--11111111-1111-4111-8111-111111111111"
EMAIL = "victim@example.com"

BREACHED = {
    "breaches": [
        {
            "name": "Sysco",
            "date": "2024-05-01",
            "records": 2699339,
            "domain": "sysco.com",
            "industry": "Food",
            "password_risk": "plaintext",
            "verified": "Yes",
            "data_classes": ["Email addresses", "Names"],
            "details": "Sysco was breached.",
        }
    ],
    "risk_label": "Critical",
    "risk_score": 100,
}


def fixture(name: str) -> Any:
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return json.load(handle)


def make_helper() -> MagicMock:
    helper = MagicMock()
    helper.connector_logger = Mock(spec=PYCTI_LOGGER_METHODS)
    helper.stix2_create_bundle.return_value = "BUNDLE"
    helper.check_max_tlp.side_effect = _check_max_tlp
    return helper


def _check_max_tlp(tlp: str | None, max_tlp: str | None) -> bool:
    order = [
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ]
    if tlp is None or max_tlp is None:
        return True
    if tlp not in order:
        return False
    return order.index(tlp) <= max(order.index(max_tlp), 1)


def make_settings(**overrides: Any) -> ConnectorSettings:
    xon: dict[str, Any] = {
        "api_base_url": "https://api.xposedornot.com",
        "max_tlp": "TLP:AMBER",
        "tlp_level": "amber",
        "max_note_breaches": 50,
        "update_score": True,
    }
    connector: dict[str, Any] = {
        "id": "connector-id",
        "name": "XposedOrNot",
        "scope": "Email-Addr",
        "log_level": "error",
        "auto": False,
    }
    for key, value in overrides.items():
        (connector if key in connector else xon)[key] = value

    class StubSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler):
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": connector,
                    "xposedornot": xon,
                }
            )

    return StubSettings()


def make_data(
    email: str = EMAIL,
    playbook: bool = False,
    markings: tuple[str, ...] = ("TLP:AMBER",),
    entity_type: str = "Email-Addr",
    entity: dict[str, Any] | None = None,
    object_marking_refs: list[str] | None = None,
) -> dict[str, Any]:
    stix_entity = {
        "type": "email-addr",
        "id": OBSERVABLE_ID,
        "spec_version": "2.1",
        "value": email,
        **(entity or {}),
    }
    if object_marking_refs is not None:
        stix_entity["object_marking_refs"] = object_marking_refs
    data = {
        "enrichment_entity": {
            "entity_type": entity_type,
            "observable_value": email,
            "created_at": "2024-05-01T10:00:00.000Z",
            "objectMarking": [
                {"definition_type": "TLP", "definition": marking}
                for marking in markings
            ],
        },
        "stix_entity": stix_entity,
        "stix_objects": [stix_entity],
    }
    if not playbook:
        data["event_type"] = "INTERNAL_ENRICHMENT"
    return data


def sent_objects(helper: MagicMock) -> list[dict[str, Any]]:
    return helper.stix2_create_bundle.call_args[0][0]


def by_type(helper: MagicMock) -> dict[str, dict[str, Any]]:
    return {obj["type"]: obj for obj in sent_objects(helper)}


@pytest.fixture(name="mocked_helper")
def fixture_mocked_helper() -> MagicMock:
    return make_helper()
