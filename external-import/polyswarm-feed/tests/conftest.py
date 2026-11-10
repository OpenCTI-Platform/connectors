"""Shared pytest fixtures and builders for the PolySwarm feed tests.

The sample builders below are small hand-written inputs shaped like the
PolySwarm TAXII responses (one STIX bundle per sample inside a page's
`objects` list). They are not recorded data.
"""

import os
import sys
from typing import Any

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402


class FakeLogger:
    """Stand-in for the connector logger, recording calls by level."""

    def __init__(self) -> None:
        self.records: list[tuple[str, str, Any]] = []

    def _log(self, level: str, message: str, meta: Any = None) -> None:
        self.records.append((level, message, meta))

    def info(self, message: str, meta: Any = None) -> None:
        self._log("info", message, meta)

    def debug(self, message: str, meta: Any = None) -> None:
        self._log("debug", message, meta)

    def warning(self, message: str, meta: Any = None) -> None:
        self._log("warning", message, meta)

    def error(self, message: str, meta: Any = None) -> None:
        self._log("error", message, meta)

    def exception(self, message: str, meta: Any = None) -> None:
        self._log("exception", message, meta)

    def messages(self, level: str) -> list[str]:
        return [message for lvl, message, _ in self.records if lvl == level]


@pytest.fixture
def fake_logger() -> FakeLogger:
    return FakeLogger()


BASE_SETTINGS: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {
        "id": "connector-id",
        "name": "PolySwarm Feed",
        "log_level": "error",
        "duration_period": "PT1H",
    },
    "polyswarm": {
        "api_key": "test-api-key",
        "account_number": "000000000000",
    },
}


def make_settings(**polyswarm_overrides: Any) -> ConnectorSettings:
    """Build valid settings from a fixed dict, without reading env/config files."""
    config = {
        **BASE_SETTINGS,
        "polyswarm": {**BASE_SETTINGS["polyswarm"], **polyswarm_overrides},
    }

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
            return handler(config)

    return FakeConnectorSettings()


@pytest.fixture
def connector_settings() -> ConnectorSettings:
    return make_settings()


def _uuid(suffix: int) -> str:
    return f"00000000-0000-4000-a000-{suffix:012x}"


def make_sample_bundle(
    n: int,
    family: str = "Socks",
    engines: tuple[str, ...] = ("clamav", "ikarus"),
    with_attack_pattern: bool = False,
    with_dynamic_analysis: bool = False,
    created: str = "2026-10-27T14:53:00.063063Z",
) -> dict[str, Any]:
    """One per-sample bundle, shaped like a PolySwarm TAXII page item."""
    family_id = _uuid(1000 + n)
    sample_id = _uuid(2000 + n)
    md5 = f"{n:032x}"
    sha1 = f"{n:040x}"
    sha256 = f"{n:064x}"
    variant = f"malware--{sample_id}"
    family_ref = f"malware--{family_id}"
    indicator_id = f"indicator--{sample_id}"

    objects: list[dict[str, Any]] = [
        {
            "type": "malware",
            "spec_version": "2.1",
            "id": family_ref,
            "created": created,
            "modified": "2026-11-10T14:53:39.115427Z",
            "name": family,
            "is_family": True,
            "aliases": [sha256],
        },
        {
            "type": "file",
            "spec_version": "2.1",
            "id": f"file--{sample_id}",
            "hashes": {"MD5": md5, "SHA-1": sha1, "SHA-256": sha256},
            "size": 1024,
            "name": sha256,
        },
        {
            "type": "malware",
            "spec_version": "2.1",
            "id": variant,
            "created": created,
            "modified": "2026-11-10T14:53:39.126220Z",
            "name": family,
            "is_family": False,
            "malware_types": ["trojan"],
            "sample_refs": [f"file--{sample_id}"],
            "confidence": 99,
        },
    ]
    for algo, value in (("MD5", md5), ("'SHA-1'", sha1), ("'SHA-256'", sha256)):
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": created,
                "modified": "2026-11-10T14:53:39.128052Z",
                "pattern": f"[file:hashes.{algo} = '{value}']",
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": created,
                "confidence": 99,
            }
        )
    objects.append(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{_uuid(3000 + n * 100)}",
            "relationship_type": "variant-of",
            "source_ref": variant,
            "target_ref": family_ref,
        }
    )
    for i in range(3):
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{_uuid(3000 + n * 100 + 1 + i)}",
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": variant,
            }
        )
    for i, engine in enumerate(engines):
        analysis_id = f"malware-analysis--{_uuid(4000 + n * 100 + i)}"
        objects.append(
            {
                "type": "malware-analysis",
                "spec_version": "2.1",
                "id": analysis_id,
                "product": engine,
                "result": "malicious",
            }
        )
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{_uuid(5000 + n * 100 + i)}",
                "relationship_type": "av-analysis-of",
                "source_ref": analysis_id,
                "target_ref": variant,
            }
        )
    if with_dynamic_analysis:
        objects.append(
            {
                "type": "malware-analysis",
                "spec_version": "2.1",
                "id": f"malware-analysis--{_uuid(6000 + n)}",
                "product": "cape",
                "analysis_sco_refs": [
                    "ipv4-addr--a5c97d84-64d1-512b-9be8-3c30d74926ad",
                    f"file--{sample_id}",
                ],
            }
        )
    if with_attack_pattern:
        attack_pattern = "attack-pattern--4f9fc466-c8f0-5d6c-85f3-095820a41b7b"
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": attack_pattern,
                "name": "System Location Discovery: System Language Discovery",
                "external_references": [
                    {"source_name": "ATT&CK", "external_id": "T1614.001"}
                ],
            }
        )
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{_uuid(7000 + n)}",
                "relationship_type": "uses",
                "source_ref": family_ref,
                "target_ref": attack_pattern,
            }
        )
    return {"type": "bundle", "id": f"bundle--{family_id}", "objects": objects}


def make_page(
    *samples: dict[str, Any],
    more: bool = False,
    next_token: str | None = None,
) -> dict[str, Any]:
    """A TAXII `objects` envelope as served by PolySwarm."""
    page: dict[str, Any] = {"objects": list(samples), "more": more}
    if next_token:
        page["next"] = next_token
    return page
