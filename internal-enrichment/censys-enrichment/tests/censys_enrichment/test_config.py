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
    assert config.connector.scope == ["IPv4-Addr", "IPv6-Addr", "X509-Certificate"]
    assert config.connector.log_level == "error"
    assert config.connector.auto is False

    assert config.censys_enrichment.max_tlp == "TLP:AMBER"


@pytest.mark.usefixtures("mock_config")
def test_missing_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENCTI_URL")
    with pytest.raises(ConfigValidationError) as exc_info:
        ConfigLoader()
    assert exc_info.value.args == ("Error validating configuration.",)
