"""Shared pytest fixtures + helpers for the whisper-opencti test suite.

pytest auto-discovers ``conftest.py`` and makes its fixtures available to
every test module in the same directory tree without per-file imports.
Layout matches the upstream OpenCTI-Platform/connectors template — see
the [`tests/conftest.py`](https://github.com/OpenCTI-Platform/connectors/blob/master/templates/internal-enrichment/tests/conftest.py)
in the canonical internal-enrichment skeleton.

Fixtures:

- ``helper`` — a v7 ``OpenCTIConnectorHelper`` mock with an identity-ish
  ``stix2_create_bundle`` side_effect, so tests can ``json.loads`` the
  serialized bundle out of ``send_stix2_bundle.call_args``.
- ``client`` — a ``WhisperClient`` mock spec'd against the real class.
- ``make_config`` — factory returning real ``ConnectorSettings`` (connectors-sdk
  ``BaseConnectorSettings``) instances with sane test defaults. Override
  ``whisper:`` fields via keyword arguments. The SDK loads config from env /
  ``config.yml`` and ignores constructor kwargs, so the factory injects test
  values through a stub subclass that overrides ``_load_config_dict`` — the
  same pattern the upstream domaintools tests use.
- ``config`` — convenience: a ``ConnectorSettings`` built via ``make_config()``
  with no overrides.
- ``connector`` — a ``WhisperConnector`` wired up with the above three.

Module-level helpers (not fixtures):

- ``_v7_payload(observable, *, event_type, stix_objects)`` — builds the v7
  internal-enrichment callback dict. Tests use this rather than crafting
  the dict by hand so the shape stays consistent across the suite.
"""

import json
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector.connector import WhisperConnector  # noqa: E402
from connector.settings import ConnectorSettings  # noqa: E402
from connector.whisper_client import WhisperClient  # noqa: E402


def build_settings(**whisper_overrides) -> ConnectorSettings:
    """Construct a ``ConnectorSettings`` from a fixed in-memory config dict.

    The connectors-sdk ``BaseConnectorSettings`` loads config from env vars and
    ``config.yml`` and ignores constructor kwargs, so tests can't just pass
    values in. Instead we subclass and override ``_load_config_dict`` (the
    SDK's wrap-validator that does the load) to return our test dict — the
    upstream domaintools tests use exactly this stub pattern.

    ``whisper_overrides`` are merged into the ``whisper:`` block so a test can
    do ``build_settings(max_tlp="TLP:AMBER")``.
    """
    cfg = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {
            "id": "11111111-1111-1111-1111-111111111111",
            "name": "Whisper",
            "scope": "IPv4-Addr,IPv6-Addr,Domain-Name,Autonomous-System",
            "log_level": "error",
            "auto": False,
        },
        "whisper": {
            "api_url": "https://api.whisper.test",
            "api_key": "test-key",
            "max_tlp": "TLP:RED",
            **whisper_overrides,
        },
    }

    class _StubSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, data, handler):
            return handler(cfg)

    return _StubSettings()


@pytest.fixture
def helper():
    """v7 helper: ``stix2_create_bundle`` is the only helper API we use
    on the send path; we mock it as identity-ish so test bodies can read
    the serialized bundle from ``send_stix2_bundle.call_args``.
    """
    h = MagicMock()

    # Identity-ish: pass through a serialized JSON form of the objects
    # list so tests can json.loads the call_args and inspect the bundle.
    # Handle both stix2 objects (which have .serialize()) and raw dicts
    # (e.g. the playbook-passthrough path forwards the worker-supplied
    # stix_objects list verbatim).
    def _create_bundle(objects):
        return json.dumps(
            {
                "objects": [
                    json.loads(o.serialize()) if hasattr(o, "serialize") else o
                    for o in objects
                ]
            }
        )

    h.stix2_create_bundle.side_effect = _create_bundle
    return h


@pytest.fixture
def client():
    return MagicMock(spec=WhisperClient)


@pytest.fixture
def make_config():
    """Factory for ``ConnectorSettings`` instances. Default ``max_tlp=TLP:RED``
    keeps every test observable below the ceiling unless a test overrides.
    Override ``whisper:`` fields via ``make_config(max_tlp="TLP:AMBER")`` etc.
    """

    def _factory(**overrides) -> ConnectorSettings:
        return build_settings(**overrides)

    return _factory


@pytest.fixture
def config(make_config):
    return make_config()


@pytest.fixture
def connector(helper, config, client):
    return WhisperConnector(helper=helper, config=config, client=client)


def _v7_payload(
    observable: dict,
    *,
    event_type: str = "create",
    stix_objects: list | None = None,
) -> dict:
    """Build a v7 ``_process_message`` data dict.

    The v7 internal-enrichment callback receives the observable directly
    (no ``helper.api.stix_cyber_observable.read`` round-trip), plus a
    STIX-form view and the bundle's ``stix_objects`` for playbook
    pass-through. Default ``event_type="create"`` simulates a real-time
    enrichment request; pass ``event_type=None`` to simulate a playbook
    chain.
    """
    payload = {
        "enrichment_entity": observable,
        "stix_entity": observable,
        "stix_objects": stix_objects or [],
    }
    if event_type is not None:
        payload["event_type"] = event_type
    return payload
