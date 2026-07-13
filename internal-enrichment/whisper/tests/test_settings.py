"""Tests for ``connector.settings``.

The connector's config is built on the connectors-sdk
``BaseConnectorSettings`` (per the upstream PR review,
OpenCTI-Platform/connectors#6708). These tests pin down the guarantees the
``whisper:`` block and the top-level ``ConnectorSettings`` have to provide:

1. ``WhisperConfig`` requires ``api_url`` / ``api_key`` and raises
   ``ValidationError`` when either is missing.
2. ``api_key`` is a ``SecretStr`` — masked in ``repr``, readable via
   ``get_secret_value()``.
3. ``max_tlp`` defaults to ``TLP:AMBER+STRICT``.
4. ``ConnectorSettings`` exposes the ``whisper:`` block and produces a valid
   helper-config dict (``opencti`` / ``connector`` keys) for pycti.
"""

import pytest
from connector.settings import ConnectorSettings, WhisperConfig
from pydantic import SecretStr, ValidationError

# --- WhisperConfig field validation ----------------------------------------


def test_whisper_config_construction_succeeds_with_required_fields():
    w = WhisperConfig(api_url="https://api.whisper.test", api_key="k")
    assert w.api_url == "https://api.whisper.test"
    assert w.api_key.get_secret_value() == "k"
    # Default TLP ceiling: AMBER+STRICT — strict-by-default keeps customer
    # intel out of the Whisper API unless the operator opts in.
    assert w.max_tlp == "TLP:AMBER+STRICT"


def test_whisper_config_api_key_is_secret():
    # SecretStr keeps the key out of logs / reprs; the connector reads it
    # explicitly via get_secret_value() when building the HTTP client.
    w = WhisperConfig(api_url="https://x", api_key="super-secret")
    assert isinstance(w.api_key, SecretStr)
    assert "super-secret" not in repr(w)
    assert w.api_key.get_secret_value() == "super-secret"


def test_whisper_config_fails_when_api_url_missing():
    with pytest.raises(ValidationError) as exc:
        WhisperConfig(api_key="k")
    assert "api_url" in str(exc.value)


def test_whisper_config_fails_when_api_key_missing():
    with pytest.raises(ValidationError) as exc:
        WhisperConfig(api_url="https://x")
    assert "api_key" in str(exc.value)


@pytest.mark.parametrize(
    "tlp",
    [
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ],
)
def test_whisper_config_accepts_every_canonical_tlp(tlp):
    w = WhisperConfig(api_url="https://x", api_key="k", max_tlp=tlp)
    assert w.max_tlp == tlp


# --- ConnectorSettings (top-level, via the make_config stub) ----------------


def test_connector_settings_exposes_whisper_block(make_config):
    settings = make_config()
    assert isinstance(settings, ConnectorSettings)
    assert settings.whisper.api_url == "https://api.whisper.test"
    assert settings.whisper.api_key.get_secret_value() == "test-key"
    assert settings.whisper.max_tlp == "TLP:RED"


def test_connector_settings_default_connector_scope_and_name(make_config):
    settings = make_config()
    assert settings.connector.name == "Whisper"
    assert set(settings.connector.scope) >= {
        "IPv4-Addr",
        "IPv6-Addr",
        "Domain-Name",
        "Autonomous-System",
    }
    # BaseInternalEnrichmentConnectorConfig pins the connector type.
    assert settings.connector.type == "INTERNAL_ENRICHMENT"


def test_connector_settings_whisper_override(make_config):
    settings = make_config(max_tlp="TLP:AMBER")
    assert settings.whisper.max_tlp == "TLP:AMBER"


def test_to_helper_config_carries_opencti_and_connector_blocks(make_config):
    helper_config = make_config().to_helper_config()
    assert "opencti" in helper_config
    assert "connector" in helper_config
    # The SDK normalises the URL (it may append a trailing slash).
    assert helper_config["opencti"]["url"].rstrip("/") == "http://localhost:8080"
