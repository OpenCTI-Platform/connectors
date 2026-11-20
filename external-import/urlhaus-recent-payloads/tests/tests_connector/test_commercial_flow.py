"""End to end run in commercial mode on the real `SpamhausClient`, HTTP transport faked."""

import hashlib
import io
import json
import time
from typing import Any
from unittest.mock import MagicMock

import pyzipper
import requests
from connector import URLHausRecentPayloads
from helpers import COMMERCIAL, PASSWORD, USERNAME, make_settings

JWT = "synthetic-jwt-do-not-leak"
CONTENT = b"MZ synthetic sample"
SHA256 = hashlib.sha256(CONTENT).hexdigest()


def _response(status: int, body: Any = None, content: bytes | None = None):
    response = requests.Response()
    response.status_code = status
    response._content = content if content is not None else json.dumps(body).encode()
    response.headers["Content-Type"] = "application/json"
    return response


def _item(sha256: str, first_seen: str) -> dict[str, Any]:
    return {
        "file_size": len(CONTENT),
        "file_type": "exe",
        "first_seen": first_seen,
        "last_seen": first_seen,
        "md5_hash": "b" * 32,
        "sha256_hash": sha256,
        "signature": "Adwind",
        "urlhaus_download": f"https://api.spamhaus.com/urlhaus/v1/files/samples/{sha256}",
    }


def _archive() -> bytes:
    buffer = io.BytesIO()
    with pyzipper.AESZipFile(
        buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as archive:
        archive.setpassword(b"infected")
        archive.writestr("sample.bin", CONTENT)
    return buffer.getvalue()


class FakeSpamhaus:
    """Replays Spamhaus: login, two pages of payloads, one sample."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def __call__(self, session, method, url, **kwargs):
        self.requests.append(
            {
                "method": method,
                "url": url,
                "params": kwargs.get("params"),
                "headers": {**session.headers, **(kwargs.get("headers") or {})},
            }
        )
        if url.endswith("/v1/login"):
            return _response(
                200, {"code": 200, "token": JWT, "expires": time.time() + 86400}
            )
        if url.endswith("/urlhaus/v1/payloads"):
            if (kwargs.get("params") or {}).get("after") == "cursor-2":
                return _response(
                    200,
                    {
                        "items": [_item(SHA256, "2026-11-19T11:00:00Z")],
                        "meta": {"page_size": 1},
                    },
                )
            return _response(
                200,
                {
                    "items": [_item(SHA256, "2026-11-19T12:00:00Z")],
                    "meta": {
                        "page_size": 1,
                        "next_cursor": "cursor-2",
                        "next_page": "/urlhaus/v1/payloads?after=cursor-2",
                    },
                },
            )
        if url.endswith(f"/urlhaus/v1/files/samples/{SHA256}"):
            return _response(200, content=_archive())
        raise AssertionError(f"unexpected request {method} {url}")


def test_commercial_run_imports_the_payloads_with_one_login(monkeypatch):
    fake = FakeSpamhaus()
    monkeypatch.setattr(
        requests.Session,
        "request",
        lambda session, method, url, **kw: fake(session, method, url, **kw),
    )
    connector = URLHausRecentPayloads(
        config=make_settings(**COMMERCIAL), helper=MagicMock()
    )
    helper = connector.helper
    helper.get_state.return_value = {"last_first_seen": "2026-11-19 09:00:00"}
    helper.api.stix_cyber_observable.read.return_value = None

    connector.process()

    logins = [r for r in fake.requests if r["url"].endswith("/v1/login")]
    assert len(logins) == 1, "the JWT must be reused, not renewed per request"

    authenticated = [r for r in fake.requests if not r["url"].endswith("/v1/login")]
    assert all(r["headers"]["Authorization"] == f"Bearer {JWT}" for r in authenticated)
    assert all(
        r["headers"]["User-Agent"].startswith("OpenCTI-urlhaus-recent-payloads/")
        for r in fake.requests
    )
    assert all(r["url"].startswith("https://api.spamhaus.com/") for r in fake.requests)

    pages = [r for r in authenticated if r["url"].endswith("/urlhaus/v1/payloads")]
    assert [p["params"].get("after") for p in pages] == [None, "cursor-2"]
    assert all(p["params"]["since"] == "2026-11-19T09:00:00Z" for p in pages)

    # Both pages carry the same sample: the second one is already imported by then.
    uploads = helper.api.stix_cyber_observable.upload_artifact.call_args_list
    assert uploads and uploads[0].kwargs["file_name"] == SHA256
    assert uploads[0].kwargs["data"] == CONTENT
    assert helper.set_state.call_args_list[0].args[0] == {
        "last_first_seen": "2026-11-19 12:00:00"
    }

    logged = " ".join(str(c) for c in helper.mock_calls)
    assert PASSWORD not in logged and JWT not in logged and USERNAME not in logged


def test_rejected_credentials_fail_the_run_with_a_hint(monkeypatch):
    def reject(session, method, url, **kwargs):
        return _response(401, {"status": 401, "message": "nope"})

    monkeypatch.setattr(requests.Session, "request", reject)
    connector = URLHausRecentPayloads(
        config=make_settings(**COMMERCIAL), helper=MagicMock()
    )
    connector.helper.get_state.return_value = None

    connector.process()

    errors = [c.args[0] for c in connector.helper.connector_logger.error.call_args_list]
    assert any("check the Spamhaus credentials" in message for message in errors)
    logged = " ".join(str(c) for c in connector.helper.mock_calls)
    assert PASSWORD not in logged and USERNAME not in logged
    connector.helper.api.stix_cyber_observable.upload_artifact.assert_not_called()
