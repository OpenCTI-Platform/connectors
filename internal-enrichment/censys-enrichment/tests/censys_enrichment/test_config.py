import pytest
from censys_enrichment.settings import ConfigLoader
from connectors_sdk import ConfigValidationError
from pydantic import HttpUrl


@pytest.mark.usefixtures("mock_config")
def test_config() -> None:
    config = ConfigLoader()

    # Test config from env
    assert config.opencti.url == HttpUrl("http://test")
    assert config.opencti.token == "opencti-token"

    assert (
        config.censys_enrichment.organisation_id.get_secret_value()
        == "censys-organisation_id"
    )
    assert config.censys_enrichment.token.get_secret_value() == "censys-token"

    # Test defaults
    assert (
        config.connector.id == "censys-enrichment--674403d0-4723-40cd-b03c-42fb959d5469"
    )
    assert config.connector.type == "INTERNAL_ENRICHMENT"
    assert config.connector.name == "Censys Enrichment"
    assert config.connector.scope == [
        "IPv4-Addr",
        "IPv6-Addr",
        "X509-Certificate",
        "Domain-Name",
    ]
    assert config.connector.log_level == "error"
    assert config.connector.auto is False

    assert config.censys_enrichment.max_tlp == "TLP:AMBER"


@pytest.mark.usefixtures("mock_config")
def test_missing_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENCTI_URL")
    with pytest.raises(ConfigValidationError) as exc_info:
        ConfigLoader()
    assert exc_info.value.args == ("Error validating configuration.",)


# ---------------------------------------------------------------------------
# Scope field validator
# ---------------------------------------------------------------------------
#
# Without ``@field_validator("scope")``, a misconfigured
# ``CONNECTOR_SCOPE`` (e.g. a typo like ``Domain-name`` or an entity
# type the connector does not implement, like ``Url``) silently
# falls through ``Connector._is_entity_in_scope`` and only blows up
# at dispatch time inside ``_generate_octi_objects`` with
# ``EntityTypeNotSupportedError`` — after a work has already been
# accepted off the queue. These tests pin the new fail-at-startup
# contract so a future contributor cannot regress the validator
# back to a no-op.


@pytest.mark.usefixtures("mock_config")
def test_scope_accepts_subset_of_supported_types(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONNECTOR_SCOPE", "IPv4-Addr,Domain-Name")
    config = ConfigLoader()
    assert config.connector.scope == ["IPv4-Addr", "Domain-Name"]


@pytest.mark.usefixtures("mock_config")
def test_scope_rejects_unsupported_entity_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ``Url`` is a legal OpenCTI entity_type but the Censys
    # connector does not implement a converter for it. The
    # validator must surface this at startup rather than letting it
    # slip through to dispatch time.
    monkeypatch.setenv("CONNECTOR_SCOPE", "IPv4-Addr,Url")
    with pytest.raises(ConfigValidationError):
        ConfigLoader()


@pytest.mark.usefixtures("mock_config")
def test_scope_rejects_case_typo(monkeypatch: pytest.MonkeyPatch) -> None:
    # OpenCTI uses ``Domain-Name`` (capitalised D, capitalised N).
    # A typo like ``Domain-name`` would match no converter at
    # dispatch time and produce a confusing
    # ``EntityTypeNotSupportedError`` after the fact — the
    # validator must reject it now instead.
    monkeypatch.setenv("CONNECTOR_SCOPE", "Domain-name")
    with pytest.raises(ConfigValidationError):
        ConfigLoader()
