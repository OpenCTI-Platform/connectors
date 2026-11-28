"""HTTPS startup checks of the feed distributor: the certificate and key must exist and be
readable by the container user, so a wrong file or permission is named at startup instead of
failing later inside uvicorn."""

import os
import tempfile

import pytest
from common import config


def _https_env(cert: str, key: str) -> None:
    os.environ.update(
        {
            "FEED_DISTRIBUTOR_HTTP_ENABLED": "true",
            "FEED_DISTRIBUTOR_HTTP_PORT": "8080",
            "FEED_DISTRIBUTOR_HTTPS_ENABLED": "true",
            "FEED_DISTRIBUTOR_HTTPS_PORT": "8443",
            "FEED_DISTRIBUTOR_TLS_CERT_FILE": cert,
            "FEED_DISTRIBUTOR_TLS_KEY_FILE": key,
            "FEED_DISTRIBUTOR_AUTH_MODE": "none",
        }
    )


def _file(folder: str, name: str) -> str:
    path = os.path.join(folder, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("-----BEGIN TEST-----\n")
    return path


def test_readable_files_pass():
    with tempfile.TemporaryDirectory() as folder:
        _https_env(_file(folder, "server.crt"), _file(folder, "server.key"))
        settings = config.feed_distributor_settings()
        assert settings.https_enabled


def test_missing_key_stops_startup():
    with tempfile.TemporaryDirectory() as folder:
        _https_env(_file(folder, "server.crt"), os.path.join(folder, "server.key"))
        with pytest.raises(SystemExit, match="TLS_KEY_FILE is missing"):
            config.feed_distributor_settings()


@pytest.mark.skipif(
    not hasattr(os, "getuid") or os.getuid() == 0,
    reason="root reads any file, so a permission error can't be produced",
)
def test_unreadable_key_stops_startup():
    with tempfile.TemporaryDirectory() as folder:
        key = _file(folder, "server.key")
        os.chmod(key, 0)
        _https_env(_file(folder, "server.crt"), key)
        with pytest.raises(SystemExit, match="TLS_KEY_FILE can't be read"):
            config.feed_distributor_settings()
