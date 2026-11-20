"""Source selection (community / Spamhaus commercial), fallback and sample download."""

import hashlib
import io
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
import pyzipper
from connector import ConnectorSettings, URLHausRecentPayloads
from connectors_sdk import (
    ApiNotFoundError,
    SpamhausAuthenticationError,
    SpamhausUnavailableError,
)
from helpers import (
    AUTH_KEY,
    BOTH,
    COMMERCIAL,
    COMMUNITY,
    PASSWORD,
    USERNAME,
    make_settings,
)

SPAMHAUS_SHA = "a" * 64


class FakeSpamhausClient:
    """Stands in for `connectors_sdk.SpamhausClient`; records how it is used."""

    instances: list["FakeSpamhausClient"] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.pages: list[list[dict]] = []
        self.paginate_error: Exception | None = None
        self.paginate_calls: list[tuple[str, dict]] = []
        self.sample: bytes | Exception = b""
        self.get_bytes_calls: list[str] = []
        FakeSpamhausClient.instances.append(self)

    def paginate(self, path, *, params=None, page_size=100):
        self.paginate_calls.append((path, dict(params or {})))
        if self.paginate_error:
            raise self.paginate_error
        yield from self.pages

    def get_bytes(self, path, *, params=None):
        self.get_bytes_calls.append(path)
        if isinstance(self.sample, Exception):
            raise self.sample
        return self.sample


@pytest.fixture
def fake_client(monkeypatch) -> type[FakeSpamhausClient]:
    FakeSpamhausClient.instances = []
    monkeypatch.setattr("connector.connector.SpamhausClient", FakeSpamhausClient)
    return FakeSpamhausClient


@pytest.fixture
def community_get(monkeypatch) -> MagicMock:
    """Replace `requests.get` used for the community API."""
    get = MagicMock(name="requests.get")
    monkeypatch.setattr("connector.connector.requests.get", get)
    return get


def build(settings: ConnectorSettings) -> URLHausRecentPayloads:
    return URLHausRecentPayloads(config=settings, helper=MagicMock())


def spamhaus_item(sha256: str = SPAMHAUS_SHA, first_seen="2026-11-19T10:00:00Z"):
    return {
        "file_size": 10,
        "file_type": "exe",
        "first_seen": first_seen,
        "last_seen": first_seen,
        "md5_hash": "b" * 32,
        "sha256_hash": sha256,
        "signature": "Adwind",
        "urlhaus_download": f"https://api.spamhaus.com/urlhaus/v1/files/samples/{sha256}",
    }


def encrypted_zip(content: bytes) -> bytes:
    buffer = io.BytesIO()
    with pyzipper.AESZipFile(
        buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as archive:
        archive.setpassword(b"infected")
        archive.writestr("sample.bin", content)
    return buffer.getvalue()


def all_log_text(connector: URLHausRecentPayloads) -> str:
    logger = connector.helper.connector_logger
    return " ".join(str(call) for call in logger.mock_calls)


# --- community mode (unchanged) ---------------------------------------------


def test_community_mode_calls_the_community_host_with_the_auth_key(
    fake_client, community_get
):
    community_get.return_value.json.return_value = {"payloads": [{"sha256_hash": "x"}]}
    connector = build(make_settings(**COMMUNITY))

    payloads = connector.get_recent_payloads(since=None)

    assert payloads == [{"sha256_hash": "x"}]
    community_get.assert_called_once_with(
        "https://urlhaus-api.abuse.ch/v1/payloads/recent/",
        headers={"Auth-Key": AUTH_KEY},
    )
    assert fake_client.instances == []  # no Spamhaus client, no login


# --- commercial mode -----------------------------------------------------------


def test_commercial_mode_builds_the_spamhaus_client_with_an_explicit_user_agent(
    fake_client,
):
    build(make_settings(**COMMERCIAL))

    (client,) = fake_client.instances
    assert client.kwargs["username"].get_secret_value() == USERNAME
    assert client.kwargs["password"].get_secret_value() == PASSWORD
    assert client.kwargs["connector_name"] == "urlhaus-recent-payloads"
    assert client.kwargs["connector_version"]


def test_commercial_mode_requests_payloads_since_the_checkpoint(
    fake_client, community_get
):
    connector = build(make_settings(**COMMERCIAL))
    (client,) = fake_client.instances
    client.pages = [[spamhaus_item()]]

    connector.get_recent_payloads(since=datetime(2026, 11, 18, 8, 30, 15))

    assert client.paginate_calls == [
        ("/urlhaus/v1/payloads", {"since": "2026-11-18T08:30:15Z"})
    ]
    community_get.assert_not_called()


def test_commercial_mode_follows_every_page_and_maps_the_items(fake_client):
    connector = build(make_settings(**COMMERCIAL))
    (client,) = fake_client.instances
    client.pages = [
        [spamhaus_item("1" * 64, "2026-11-19T10:00:00Z")],
        [spamhaus_item("2" * 64, "2026-11-19T11:00:00+00:00")],
    ]

    payloads = connector.get_recent_payloads(since=None)

    assert [p["sha256_hash"] for p in payloads] == ["1" * 64, "2" * 64]
    assert payloads[0] == {
        "sha256_hash": "1" * 64,
        "firstseen": "2026-11-19 10:00:00",
        "file_type": "exe",
        "signature": "Adwind",
        "urlhaus_download": f"https://api.spamhaus.com/urlhaus/v1/files/samples/{'1' * 64}",
    }


def test_commercial_mode_without_checkpoint_starts_at_import_start_date(fake_client):
    connector = build(
        make_settings(**COMMERCIAL, import_start_date="2026-11-01T00:00:00Z")
    )
    (client,) = fake_client.instances

    connector.get_recent_payloads(since=None)

    assert client.paginate_calls[0][1]["since"] == "2026-11-01T00:00:00Z"


def test_commercial_mode_skips_an_item_that_cannot_be_mapped(fake_client):
    connector = build(make_settings(**COMMERCIAL))
    (client,) = fake_client.instances
    broken = spamhaus_item()
    del broken["sha256_hash"]
    client.pages = [[broken, spamhaus_item("2" * 64)]]

    payloads = connector.get_recent_payloads(since=None)

    assert [p["sha256_hash"] for p in payloads] == ["2" * 64]
    connector.helper.connector_logger.warning.assert_called_once()


# --- fallback ------------------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(SpamhausUnavailableError("api down"), id="unavailable"),
        pytest.param(SpamhausAuthenticationError("rejected"), id="rejected"),
    ],
)
def test_commercial_failure_falls_back_to_the_community_auth_key(
    fake_client, community_get, error
):
    community_get.return_value.json.return_value = {"payloads": [{"sha256_hash": "c"}]}
    connector = build(make_settings(**BOTH))
    (client,) = fake_client.instances
    client.paginate_error = error

    payloads = connector.get_recent_payloads(since=None)

    assert payloads == [{"sha256_hash": "c"}]
    community_get.assert_called_once()
    connector.helper.connector_logger.warning.assert_called()
    text = all_log_text(connector)
    assert PASSWORD not in text and AUTH_KEY not in text and USERNAME not in text


def test_commercial_only_failure_is_not_swallowed(fake_client, community_get):
    connector = build(make_settings(**COMMERCIAL))
    (client,) = fake_client.instances
    client.paginate_error = SpamhausUnavailableError("api down")

    with pytest.raises(SpamhausUnavailableError):
        connector.get_recent_payloads(since=None)

    community_get.assert_not_called()


def test_process_asks_to_check_the_credentials_when_they_are_rejected(fake_client):
    connector = build(make_settings(**COMMERCIAL))
    (client,) = fake_client.instances
    client.paginate_error = SpamhausAuthenticationError("rejected")
    connector.helper.get_state.return_value = None

    connector.process()

    errors = [c.args[0] for c in connector.helper.connector_logger.error.call_args_list]
    assert any("check the Spamhaus credentials" in message for message in errors)
    text = all_log_text(connector)
    assert PASSWORD not in text and USERNAME not in text


# --- sample download ----------------------------------------------------------


def test_commercial_download_fetches_the_sample_with_the_jwt_and_unzips_it(
    fake_client, community_get
):
    content = b"MZ synthetic sample"
    sha256 = hashlib.sha256(content).hexdigest()
    connector = build(make_settings(**COMMERCIAL))
    (client,) = fake_client.instances
    client.sample = encrypted_zip(content)

    result = connector.download_payload(
        "exe", f"https://evil.example/{sha256}", sha256=sha256
    )

    assert result == content
    # The path is built from the hash: the JWT is never sent to a URL taken from the API.
    assert client.get_bytes_calls == [f"/urlhaus/v1/files/samples/{sha256}"]
    community_get.assert_not_called()


def test_community_download_is_unchanged(fake_client, community_get):
    community_get.return_value.content = b"raw"
    connector = build(make_settings(**COMMUNITY))

    result = connector.download_payload(
        "exe", "https://urlhaus-api.abuse.ch/v1/download/abc/", sha256="abc"
    )

    assert result == b"raw"
    community_get.assert_called_once_with(
        "https://urlhaus-api.abuse.ch/v1/download/abc/", headers={"Auth-Key": AUTH_KEY}
    )


def test_commercial_download_failure_falls_back_to_the_community_download(
    fake_client, community_get
):
    community_get.return_value.content = b"raw"
    connector = build(make_settings(**BOTH))
    (client,) = fake_client.instances
    client.sample = SpamhausUnavailableError("api down")

    result = connector.download_payload("exe", "ignored", sha256="abc")

    assert result == b"raw"
    community_get.assert_called_once_with(
        "https://urlhaus-api.abuse.ch/v1/download/abc/", headers={"Auth-Key": AUTH_KEY}
    )


# --- checkpoint -----------------------------------------------------------------


def test_checkpoint_never_moves_backwards(fake_client):
    content = b"MZ synthetic sample"
    sha256 = hashlib.sha256(content).hexdigest()
    connector = build(make_settings(**COMMERCIAL))
    helper = connector.helper
    helper.get_state.return_value = {"last_first_seen": "2026-11-19 09:00:00"}
    helper.api.stix_cyber_observable.read.return_value = None  # not in OpenCTI yet
    (client,) = fake_client.instances
    client.sample = encrypted_zip(content)
    # Newest first: processing the second item must not lower the checkpoint.
    client.pages = [
        [
            spamhaus_item(sha256, "2026-11-19T12:00:00Z"),
            spamhaus_item(sha256, "2026-11-19T10:00:00Z"),
        ]
    ]

    connector.process()

    saved = [call.args[0] for call in helper.set_state.call_args_list]
    assert saved == [{"last_first_seen": "2026-11-19 12:00:00"}]
    assert client.paginate_calls[0][1]["since"] == "2026-11-19T09:00:00Z"


def test_a_corrupt_sample_is_skipped_without_failing_the_run(fake_client):
    content = b"MZ synthetic sample"
    good_sha = hashlib.sha256(content).hexdigest()
    connector = build(make_settings(**COMMERCIAL))
    helper = connector.helper
    helper.get_state.return_value = None
    helper.api.stix_cyber_observable.read.return_value = None
    (client,) = fake_client.instances
    client.sample = encrypted_zip(content)
    # The first item advertises a hash the archive does not match.
    client.pages = [
        [
            spamhaus_item("f" * 64, "2026-11-19T12:00:00Z"),
            spamhaus_item(good_sha, "2026-11-19T11:00:00Z"),
        ]
    ]

    connector.process()

    uploads = helper.api.stix_cyber_observable.upload_artifact.call_args_list
    assert [call.kwargs["file_name"] for call in uploads] == [good_sha]
    helper.connector_logger.warning.assert_called()
    helper.log_error.assert_not_called()


def test_a_sample_that_is_gone_from_spamhaus_is_skipped_without_fallback(
    fake_client, community_get
):
    """Samples are kept about a month: a 404 is a missing file, not an outage."""
    connector = build(make_settings(**BOTH))
    (client,) = fake_client.instances
    client.sample = ApiNotFoundError("not found", status_code=404)

    result = connector.download_payload("exe", "ignored", sha256="abc")

    assert result is None
    community_get.assert_not_called()
    assert connector.commercial_active is True
    connector.helper.connector_logger.warning.assert_called_once()
