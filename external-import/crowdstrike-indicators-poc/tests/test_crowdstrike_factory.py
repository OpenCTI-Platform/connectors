"""Tests for the CrowdStrike settings and connector factory."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import falconpy
import pytest
from conftest import FIXTURES_DIR, FakeIndicatorsAPI, make_indicator
from crowdstrike_indicators.factory import (
    DEFAULT_BASE_URL,
    CrowdStrikeConnectorFactory,
    CrowdStrikeSettings,
)
from crowdstrike_indicators.transform.attack import CrowdStrikeAddAttackPatterns
from crowdstrike_indicators.transform.bundle import MakeStixBundle
from crowdstrike_indicators.transform.malware import CrowdStrikeAddMalware
from crowdstrike_indicators.transform.transformer import CrowdStrikeIndicatorTransformer

from shared.connector import Connector
from shared.factory import ConnectorConfigurationError
from shared.record_to_file import RecordToFile

SECRET = "the-client-secret-value"
CREDENTIALS = {"client_id": "an-id", "client_secret": SECRET}
ATTACK_DATA = FIXTURES_DIR / "attack_extract.json"
VARIABLES = (
    "CROWDSTRIKE_CLIENT_ID",
    "CROWDSTRIKE_CLIENT_SECRET",
    "CROWDSTRIKE_BASE_URL",
    "CROWDSTRIKE_ATTACK_DATA",
)


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Run each test in an empty directory, without ``CROWDSTRIKE_*`` variables."""
    monkeypatch.chdir(tmp_path)
    for key in VARIABLES:
        monkeypatch.delenv(key, raising=False)
    return tmp_path


class ClientFactory:
    """Stands in for ``_create_client``; counts the clients it builds."""

    def __init__(self, client: Any) -> None:
        self.client = client
        self.count = 0

    def __call__(self) -> Any:
        self.count += 1
        return self.client


@pytest.fixture
def api(monkeypatch) -> tuple[FakeIndicatorsAPI, ClientFactory]:
    fake = FakeIndicatorsAPI([make_indicator(1), make_indicator(2)])
    creator = ClientFactory(fake)
    monkeypatch.setattr(
        CrowdStrikeConnectorFactory, "_create_client", lambda self: creator()
    )
    return fake, creator


@pytest.fixture
def no_client(monkeypatch):
    def forbidden(factory):
        raise AssertionError("the API client must not be built")

    monkeypatch.setattr(CrowdStrikeConnectorFactory, "_create_client", forbidden)


# Settings


def test_defaults():
    factory = CrowdStrikeConnectorFactory(**CREDENTIALS)

    assert isinstance(factory.settings, CrowdStrikeSettings)
    assert factory.settings.base_url == "https://api.crowdstrike.com"
    assert factory.settings.attack_data is None
    assert factory.attack_pattern_catalog is None


def test_settings_come_from_the_env_file(isolated):
    (isolated / ".env").write_text(
        "CROWDSTRIKE_CLIENT_ID=file-id\n"
        f"CROWDSTRIKE_CLIENT_SECRET={SECRET}\n"
        "CROWDSTRIKE_BASE_URL=https://api.eu-1.crowdstrike.com\n"
    )

    settings = CrowdStrikeConnectorFactory().settings

    assert settings.client_id.get_secret_value() == "file-id"
    assert settings.client_secret.get_secret_value() == SECRET
    assert settings.base_url == "https://api.eu-1.crowdstrike.com"


def test_unknown_keys_are_ignored(isolated):
    (isolated / ".env").write_text(
        "OPENCTI_URL=http://localhost:8080\n"
        "CROWDSTRIKE_UNKNOWN=1\n"
        "CROWDSTRIKE_CLIENT_ID=file-id\n"
        f"CROWDSTRIKE_CLIENT_SECRET={SECRET}\n"
    )

    factory = CrowdStrikeConnectorFactory()

    assert factory.settings.client_id.get_secret_value() == "file-id"


def _credentials(settings: CrowdStrikeSettings) -> tuple[str, str, str]:
    return (
        settings.client_id.get_secret_value(),
        settings.client_secret.get_secret_value(),
        settings.base_url,
    )


def test_env_file_syntax(isolated):
    (isolated / ".env").write_text(
        "# comment\n"
        "\n"
        "export CROWDSTRIKE_CLIENT_ID=exported-id\n"
        'CROWDSTRIKE_CLIENT_SECRET="a=b#c"\n'
        "UNRELATED_KEY=ignored\n"
    )

    settings = CrowdStrikeConnectorFactory().settings

    assert _credentials(settings) == ("exported-id", "a=b#c", DEFAULT_BASE_URL)


def test_env_file_replaces_references(isolated):
    (isolated / ".env").write_text(
        "REGION=eu-1\n"
        "CROWDSTRIKE_CLIENT_ID=id-${REGION}\n"
        "CROWDSTRIKE_CLIENT_SECRET='a${UNDEFINED}c'\n"
        'CROWDSTRIKE_BASE_URL="https://api.${REGION}.crowdstrike.com"\n'
    )

    settings = CrowdStrikeConnectorFactory().settings

    assert _credentials(settings) == (
        "id-eu-1",
        "ac",
        "https://api.eu-1.crowdstrike.com",
    )


def test_environment_values_are_kept_literally(monkeypatch, isolated):
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "env-id")
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_SECRET", "a${B}c")

    settings = CrowdStrikeConnectorFactory().settings

    assert _credentials(settings) == ("env-id", "a${B}c", DEFAULT_BASE_URL)


def test_both_credentials_missing_are_named_together():
    with pytest.raises(ConnectorConfigurationError) as caught:
        CrowdStrikeConnectorFactory()

    assert caught.value.problems == [
        ("CROWDSTRIKE_CLIENT_ID", "missing"),
        ("CROWDSTRIKE_CLIENT_SECRET", "missing"),
    ]


def test_empty_values_count_as_unset(isolated):
    (isolated / ".env").write_text(
        "CROWDSTRIKE_CLIENT_ID=\n"
        "CROWDSTRIKE_CLIENT_SECRET=\n"
        "CROWDSTRIKE_BASE_URL=\n"
        "CROWDSTRIKE_ATTACK_DATA=\n"
    )

    with pytest.raises(ConnectorConfigurationError) as caught:
        CrowdStrikeConnectorFactory()

    assert [name for name, _ in caught.value.problems] == [
        "CROWDSTRIKE_CLIENT_ID",
        "CROWDSTRIKE_CLIENT_SECRET",
    ]


def test_placeholder_credentials_are_accepted_without_any_request(no_client):
    factory = CrowdStrikeConnectorFactory(
        client_id="FAKE_CLIENT_ID", client_secret="FAKE_CLIENT_SECRET"
    )

    factory.create_extractor()
    factory.create_transformers()

    assert factory.settings.client_id.get_secret_value() == "FAKE_CLIENT_ID"


def test_dataset_path_that_does_not_exist_is_named(isolated):
    with pytest.raises(ConnectorConfigurationError) as caught:
        CrowdStrikeConnectorFactory(
            **CREDENTIALS, attack_data=isolated / "missing.json"
        )

    ((name, _),) = caught.value.problems
    assert name == "CROWDSTRIKE_ATTACK_DATA"


def test_secret_is_not_in_the_settings_text():
    settings = CrowdStrikeConnectorFactory(**CREDENTIALS).settings

    assert SECRET not in repr(settings)
    assert SECRET not in str(settings)


def test_secret_is_not_in_the_error_for_another_parameter(isolated):
    with pytest.raises(ConnectorConfigurationError) as caught:
        CrowdStrikeConnectorFactory(
            **CREDENTIALS, attack_data=isolated / "missing.json"
        )

    assert SECRET not in str(caught.value)
    assert caught.value.__cause__ is None


# ATT&CK dataset


def test_dataset_that_is_not_a_bundle_fails_naming_the_file(isolated):
    path = isolated / "array.json"
    path.write_text("[]")

    with pytest.raises(ConnectorConfigurationError) as caught:
        CrowdStrikeConnectorFactory(**CREDENTIALS, attack_data=path)

    ((name, reason),) = caught.value.problems
    assert name == "CROWDSTRIKE_ATTACK_DATA"
    assert str(path) in reason


def test_valid_dataset_is_read_at_construction(no_client):
    factory = CrowdStrikeConnectorFactory(**CREDENTIALS, attack_data=ATTACK_DATA)

    assert factory.settings.attack_data == ATTACK_DATA
    assert factory.attack_pattern_catalog is not None
    assert len(factory.attack_pattern_catalog) > 0


def test_dataset_from_the_environment(monkeypatch, no_client):
    monkeypatch.setenv("CROWDSTRIKE_ATTACK_DATA", str(ATTACK_DATA))

    factory = CrowdStrikeConnectorFactory(**CREDENTIALS)

    assert factory.attack_pattern_catalog is not None


# Extractor


def test_extractor_and_enricher_share_the_client(api):
    extractor = CrowdStrikeConnectorFactory(**CREDENTIALS).create_extractor()

    assert extractor.client is extractor.actor_enricher.client


def test_creating_the_extractor_sends_no_request(api):
    fake, creator = api

    CrowdStrikeConnectorFactory(**CREDENTIALS).create_extractor()

    assert creator.count == 0
    assert fake.calls == []


def test_the_client_is_built_once_on_the_first_call(api):
    fake, creator = api
    factory = CrowdStrikeConnectorFactory(**CREDENTIALS)
    from_date = datetime(2023, 1, 1, tzinfo=UTC)

    first = factory.create_extractor().extract(from_date, 10)
    second = factory.create_extractor().extract(from_date, 10)

    assert [i.id for _, i in first] == [i.id for _, i in second] == ["ioc-1", "ioc-2"]
    assert creator.count == 1


def test_each_extractor_has_its_own_enricher(api):
    factory = CrowdStrikeConnectorFactory(**CREDENTIALS)

    first, second = factory.create_extractor(), factory.create_extractor()

    assert first is not second
    assert first.actor_enricher is not second.actor_enricher
    assert first.client is second.client


def test_configured_settings_reach_the_falconpy_client(monkeypatch):
    built: list[dict[str, Any]] = []

    class RecordingIntel(FakeIndicatorsAPI):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__([])
            built.append(kwargs)

    monkeypatch.setattr(falconpy, "Intel", RecordingIntel)
    factory = CrowdStrikeConnectorFactory(
        **CREDENTIALS, base_url="https://api.eu-1.crowdstrike.com"
    )

    extractor = factory.create_extractor()
    assert built == []
    extractor.extract(datetime(2023, 1, 1, tzinfo=UTC), 1)

    assert built == [
        {
            "client_id": "an-id",
            "client_secret": SECRET,
            "base_url": "https://api.eu-1.crowdstrike.com",
        }
    ]


# Transformers


def _types(transformers: list[Any]) -> list[type]:
    return [type(transformer) for transformer in transformers]


def test_transformers_without_a_dataset():
    transformers = CrowdStrikeConnectorFactory(**CREDENTIALS).create_transformers()

    assert _types(transformers) == [
        CrowdStrikeIndicatorTransformer,
        CrowdStrikeAddMalware,
        MakeStixBundle,
    ]


def test_transformers_with_a_dataset():
    factory = CrowdStrikeConnectorFactory(**CREDENTIALS, attack_data=ATTACK_DATA)

    transformers = factory.create_transformers()

    assert _types(transformers) == [
        CrowdStrikeIndicatorTransformer,
        CrowdStrikeAddMalware,
        CrowdStrikeAddAttackPatterns,
        MakeStixBundle,
    ]
    assert transformers[2].catalog is factory.attack_pattern_catalog


def test_each_call_returns_new_transformers():
    factory = CrowdStrikeConnectorFactory(**CREDENTIALS, attack_data=ATTACK_DATA)

    first, second = factory.create_transformers(), factory.create_transformers()

    assert all(a is not b for a, b in zip(first, second, strict=True))


@pytest.mark.parametrize("attack_data", [None, ATTACK_DATA])
def test_chain_fits_a_connector(api, tmp_path: Path, attack_data):
    factory = CrowdStrikeConnectorFactory(**CREDENTIALS, attack_data=attack_data)
    loader = RecordToFile(tmp_path / "bundles")

    connector = Connector(
        factory.create_extractor(), factory.create_transformers(), loader
    )
    result = connector.run_once(datetime(2023, 1, 1, tzinfo=UTC), 10)

    assert result.loaded == 2
    assert len(list((tmp_path / "bundles").glob("*.json"))) == 2
