from unittest.mock import MagicMock

import pytest
import requests
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.settings._settings_loader import _SettingsLoader
from external_import_connector import ConnectorSettings
from external_import_connector.client_api import ConnectorClient
from external_import_connector.connector import ConnectorState, ConnectorURLhaus
from external_import_connector.settings import UrlhausConfig

AUTH_KEY = "s3cr3t-auth-key"
LEGACY_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def test_export_url_is_built_from_auth_key():
    config = UrlhausConfig(auth_key=AUTH_KEY)

    assert config.export_url == (
        f"https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv"
    )


def test_export_url_encodes_auth_key():
    config = UrlhausConfig(auth_key="a/b?c#d%e")

    assert config.export_url == (
        "https://urlhaus-api.abuse.ch/v2/files/exports/a%2Fb%3Fc%23d%25e/recent.csv"
    )


def test_csv_url_takes_precedence_over_auth_key():
    config = UrlhausConfig(
        auth_key=AUTH_KEY, csv_url="https://mirror.example/recent.csv"
    )

    assert config.export_url == "https://mirror.example/recent.csv"


def test_legacy_csv_url_is_ignored_when_auth_key_is_set():
    config = UrlhausConfig(auth_key=AUTH_KEY, csv_url=LEGACY_URL)

    assert config.has_legacy_csv_url is True
    assert config.export_url.startswith("https://urlhaus-api.abuse.ch/v2/")


@pytest.mark.parametrize(
    "values, expected_message",
    [
        pytest.param({}, "abuse.ch requires an Auth-Key", id="nothing_set"),
        pytest.param(
            {"csv_url": LEGACY_URL}, "retired public download", id="legacy_csv_url"
        ),
    ],
)
def test_missing_auth_key_is_rejected(values, expected_message):
    with pytest.raises(ValueError, match=expected_message):
        UrlhausConfig(**values)


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_auth_key_is_rejected(blank):
    with pytest.raises(ValueError, match="abuse.ch requires an Auth-Key"):
        UrlhausConfig(auth_key=blank)


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_csv_url_falls_back_to_auth_key(blank):
    config = UrlhausConfig(auth_key=AUTH_KEY, csv_url=blank)

    assert config.csv_url is None
    assert config.export_url == (
        f"https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv"
    )


def test_blank_settings_from_env_are_treated_as_unset(monkeypatch):
    """End to end through the SDK loader, as an empty `${VAR}` in compose."""
    monkeypatch.setattr(
        "connectors_sdk.settings._settings_loader._SettingsLoader."
        "_get_config_yml_file_path",
        classmethod(lambda cls: None),
    )
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("URLHAUS_AUTH_KEY", AUTH_KEY)
    monkeypatch.setenv("URLHAUS_CSV_URL", "")

    settings = ConnectorSettings()

    assert settings.urlhaus.export_url.endswith(f"/{AUTH_KEY}/recent.csv")


@pytest.mark.parametrize(
    "csv_url, expected_legacy",
    [
        pytest.param("https://mirror.example/key/recent.csv", False, id="override"),
        pytest.param(LEGACY_URL, True, id="legacy"),
    ],
)
def test_untyped_settings_loader_accepts_raw_csv_url(csv_url, expected_legacy):
    """The SDK loader validates raw values with an untyped copy of the model
    that inherits its validators: they must accept a plain string."""
    loader = _SettingsLoader.build_loader_from_model(ConnectorSettings)
    untyped_config = loader.model_fields["urlhaus"].annotation

    config = untyped_config(
        auth_key="raw-key",
        csv_url=csv_url,
        default_x_opencti_score="80",
        import_offline="true",
        interval="3",
        threats_from_labels="true",
    )

    assert config.has_legacy_csv_url is expected_legacy


def test_untyped_settings_loader_accepts_raw_csv_url_without_auth_key():
    loader = _SettingsLoader.build_loader_from_model(ConnectorSettings)
    untyped_config = loader.model_fields["urlhaus"].annotation

    config = untyped_config(
        auth_key=None,
        csv_url="https://mirror.example/key/recent.csv",
        default_x_opencti_score="80",
        import_offline="true",
        interval="3",
        threats_from_labels="true",
    )

    assert config.has_legacy_csv_url is False


def test_auth_key_and_csv_url_are_masked():
    config = UrlhausConfig(
        auth_key=AUTH_KEY, csv_url=f"https://mirror.example/{AUTH_KEY}/recent.csv"
    )

    assert AUTH_KEY not in repr(config)
    assert AUTH_KEY not in str(config.model_dump())


def test_connector_warns_when_legacy_csv_url_is_set():
    settings = MagicMock()
    settings.urlhaus = UrlhausConfig(auth_key=AUTH_KEY, csv_url=LEGACY_URL)
    helper = MagicMock()

    ConnectorURLhaus(config=settings, helper=helper)

    helper.connector_logger.warning.assert_called_once()


def _client_with_response(response=None, side_effect=None):
    config = MagicMock()
    config.urlhaus = UrlhausConfig(auth_key=AUTH_KEY)
    client = ConnectorClient(MagicMock(), config, ConnectorState())
    client.session = MagicMock()
    client.session.get.return_value = response
    client.session.get.side_effect = side_effect
    return client


def _http_error_response(status, reason):
    """Build a response whose raise_for_status() fails like requests does,
    with the URL (and so the key) in the error message."""
    response = MagicMock()
    response.status_code = status
    response.reason = reason
    response.raise_for_status.side_effect = requests.HTTPError(
        f"{status} Client Error: {reason} for url: "
        f"https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv",
        response=response,
    )
    return response


def _logged_text(helper):
    return str(helper.mock_calls)


def test_download_requests_the_export_url():
    response = MagicMock()
    response.text = ""
    client = _client_with_response(response=response)

    list(client.get_entities())

    url = client.session.get.call_args.args[0]
    assert url == client.config.urlhaus.export_url
    assert AUTH_KEY not in _logged_text(client.helper)


def test_unauthorized_download_raises_without_leaking_the_key():
    client = _client_with_response(response=_http_error_response(401, "Unauthorized"))

    with pytest.raises(DataRetrievalError) as exc_info:
        list(client.get_entities())

    message = str(exc_info.value)
    assert "HTTP 401 Unauthorized" in message
    assert "URLHAUS_AUTH_KEY" in message
    assert AUTH_KEY not in message
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__suppress_context__ is True
    assert AUTH_KEY not in _logged_text(client.helper)


@pytest.mark.parametrize(
    "status, expected",
    [
        pytest.param(403, "HTTP 403 Forbidden: check URLHAUS_AUTH_KEY", id="known"),
        pytest.param(599, "HTTP 599", id="unknown"),
    ],
)
def test_server_reason_phrase_is_not_reported(status, expected):
    """A proxy can echo the request URL, and so the key, in its reason phrase."""
    reason = (
        "Denied for "
        f"https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv"
    )
    client = _client_with_response(response=_http_error_response(status, reason))

    with pytest.raises(DataRetrievalError) as exc_info:
        list(client.get_entities())

    message = str(exc_info.value)
    assert message.startswith(f"URLhaus export download failed: {expected}")
    assert "Denied" not in message
    assert AUTH_KEY not in message


def test_connection_error_raises_without_leaking_the_key():
    client = _client_with_response(
        side_effect=requests.ConnectionError(
            f"Max retries exceeded with url: /v2/files/exports/{AUTH_KEY}/recent.csv"
        )
    )

    with pytest.raises(DataRetrievalError) as exc_info:
        list(client.get_entities())

    assert "ConnectionError" in str(exc_info.value)
    assert AUTH_KEY not in str(exc_info.value)


def test_failed_run_reports_no_key_to_opencti():
    """The work message and the logs of a failed run never contain the key."""
    connector = ConnectorURLhaus.__new__(ConnectorURLhaus)
    connector.helper = MagicMock()
    connector.helper.get_state.return_value = {}
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.state = ConnectorState()
    connector.client = _client_with_response(
        response=_http_error_response(401, "Unauthorized")
    )
    connector.converter_to_stix = MagicMock()

    connector.process_message()

    args, kwargs = connector.helper.api.work.to_processed.call_args
    assert kwargs.get("in_error") is True
    assert "HTTP 401" in args[1]
    assert AUTH_KEY not in _logged_text(connector.helper)
