from unittest.mock import MagicMock

import pytest
from dxltieclient.constants import HashType, TrustLevel
from trellix_tie_client import (
    TrellixTieAPIError,
    TrellixTieClient,
    extract_hashes,
)


def test_extract_hashes_multiple():
    pattern = "[file:hashes.'SHA-256' = 'AABBCC' AND file:hashes.MD5 = 'D41D8CD9']"
    hashes = extract_hashes(pattern)
    assert hashes[HashType.SHA256] == "aabbcc"
    assert hashes[HashType.MD5] == "d41d8cd9"


def test_extract_hashes_sha1_variants():
    assert extract_hashes("[file:hashes.'SHA-1' = 'ABCD']")[HashType.SHA1] == "abcd"
    assert extract_hashes("[file:hashes.SHA1 = 'ABCD']")[HashType.SHA1] == "abcd"


def test_extract_hashes_none():
    assert extract_hashes("[ipv4-addr:value = '1.2.3.4']") == {}
    assert extract_hashes("") == {}


def _patch_dxl(monkeypatch, fake_dxl, fake_tie):
    monkeypatch.setattr("trellix_tie_client.api_client.DxlClientConfig", MagicMock())
    monkeypatch.setattr(
        "trellix_tie_client.api_client.DxlClient", MagicMock(return_value=fake_dxl)
    )
    monkeypatch.setattr(
        "trellix_tie_client.api_client.TieClient", MagicMock(return_value=fake_tie)
    )


def test_set_file_reputation_connects_and_sets(monkeypatch):
    fake_dxl = MagicMock()
    fake_dxl.connected = False
    fake_tie = MagicMock()
    _patch_dxl(monkeypatch, fake_dxl, fake_tie)

    client = TrellixTieClient(MagicMock(), "/opt/dxl/dxlclient.config")
    hashes = {HashType.SHA256: "abc"}
    client.set_file_reputation("KNOWN_MALICIOUS", hashes, filename="x", comment="c")

    fake_dxl.connect.assert_called_once()
    args, kwargs = fake_tie.set_file_reputation.call_args
    assert args[0] == TrustLevel.KNOWN_MALICIOUS
    assert args[1] == hashes
    assert kwargs["filename"] == "x"
    assert kwargs["comment"] == "c"


def test_set_file_reputation_empty_noop(monkeypatch):
    fake_dxl = MagicMock()
    fake_tie = MagicMock()
    _patch_dxl(monkeypatch, fake_dxl, fake_tie)

    client = TrellixTieClient(MagicMock(), "/opt/dxl/dxlclient.config")
    client.set_file_reputation("KNOWN_MALICIOUS", {})

    fake_dxl.connect.assert_not_called()
    fake_tie.set_file_reputation.assert_not_called()


def test_set_file_reputation_unknown_trust_defaults(monkeypatch):
    fake_dxl = MagicMock()
    fake_dxl.connected = True
    fake_tie = MagicMock()
    _patch_dxl(monkeypatch, fake_dxl, fake_tie)

    client = TrellixTieClient(MagicMock(), "/opt/dxl/dxlclient.config")
    client.set_file_reputation("NOT_A_LEVEL", {HashType.MD5: "abc"})
    assert fake_tie.set_file_reputation.call_args[0][0] == TrustLevel.KNOWN_MALICIOUS


def test_set_file_reputation_wraps_error(monkeypatch):
    fake_dxl = MagicMock()
    fake_dxl.connected = True
    fake_tie = MagicMock()
    fake_tie.set_file_reputation.side_effect = RuntimeError("boom")
    _patch_dxl(monkeypatch, fake_dxl, fake_tie)

    client = TrellixTieClient(MagicMock(), "/opt/dxl/dxlclient.config")
    with pytest.raises(TrellixTieAPIError):
        client.set_file_reputation("KNOWN_MALICIOUS", {HashType.MD5: "abc"})


def test_config_load_error_wrapped(monkeypatch):
    monkeypatch.setattr(
        "trellix_tie_client.api_client.DxlClientConfig",
        MagicMock(
            create_dxl_config_from_file=MagicMock(side_effect=OSError("missing"))
        ),
    )
    client = TrellixTieClient(MagicMock(), "/missing/dxlclient.config")
    with pytest.raises(TrellixTieAPIError):
        client.set_file_reputation("KNOWN_MALICIOUS", {HashType.MD5: "abc"})


def test_close_noop_when_not_initialized():
    client = TrellixTieClient(MagicMock(), "/opt/dxl/dxlclient.config")
    client.close()  # must not raise
