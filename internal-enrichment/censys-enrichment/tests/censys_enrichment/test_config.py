import pytest
from censys_enrichment.config import Config
from connectors_sdk.exceptions.error import ConfigError
from pydantic import HttpUrl


@pytest.mark.usefixtures("mock_config")
def test_config() -> None:
    config = Config()

    assert config.opencti.url == HttpUrl("http://test")
    assert config.opencti.token == "test"

    assert (
        config.connector.id == "censys-enrichment--674403d0-4723-40cd-b03c-42fb959d5469"
    )
    assert config.connector.type == "INTERNAL_ENRICHMENT"
    assert config.connector.name == "Censys Enrichment"
    assert config.connector.scope == ["IPv4-Addr"]
    assert config.connector.log_level == "error"
    assert config.connector.auto == True

    assert config.censys_enrichment.max_tlp == "TLP:AMBER"


@pytest.mark.usefixtures("mock_config")
def test_missing_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENCTI_URL")
    with pytest.raises(ConfigError) as exc_info:
        Config()
    errors = exc_info.value.args[1].errors()
    assert errors[0]["msg"] == "Field required"
    assert errors[0]["type"] == "missing"
    assert errors[0]["loc"] == ("opencti", "url")
