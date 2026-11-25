import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from requests import RequestException
from rst_threat_feed_client.mitre_ttp_downloader import (
    MitreTtpDownloader,
    _safe_path_within,
)


@pytest.fixture
def mapping_file(tmp_path):
    return tmp_path / "mitre_ttp_mapping.json"


@pytest.fixture
def downloader(mapping_file):
    dl = MitreTtpDownloader()
    dl._mapping_path = lambda: str(mapping_file)
    return dl


def test_safe_path_within_rejects_traversal(tmp_path):
    with pytest.raises(ValueError, match="Invalid file path"):
        _safe_path_within(str(tmp_path), "../secret.json")
    with pytest.raises(ValueError, match="Invalid file path"):
        _safe_path_within(str(tmp_path), "")


def test_safe_path_within_allows_basename(tmp_path):
    target = _safe_path_within(str(tmp_path), "mitre_ttp_mapping.json")
    assert target.endswith("mitre_ttp_mapping.json")


def test_load_ttp_mapping_missing_file(downloader):
    assert downloader.load_ttp_mapping() == {}


def test_load_ttp_mapping_reads_json(downloader, mapping_file):
    mapping_file.write_text(json.dumps({"T1059": "Command and Scripting Interpreter"}))
    assert downloader.load_ttp_mapping() == {
        "T1059": "Command and Scripting Interpreter"
    }


def test_load_ttp_mapping_bad_json(downloader, mapping_file):
    mapping_file.write_text("{not-json")
    assert downloader.load_ttp_mapping() == {}


def test_download_skips_when_cache_fresh(downloader, mapping_file):
    mapping_file.write_text(json.dumps({"T1001": "Data Obfuscation"}))
    with patch(
        "rst_threat_feed_client.mitre_ttp_downloader.requests.get"
    ) as mock_get:
        result = downloader.download_mitre_ttps()
    assert result == str(mapping_file)
    mock_get.assert_not_called()


def test_download_fetches_and_writes_mapping(downloader, mapping_file):
    payload = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Command and Scripting Interpreter",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059"}
                ],
            },
            {"type": "malware", "name": "ignored"},
            {
                "type": "attack-pattern",
                "name": "No external id",
                "external_references": [{"source_name": "other"}],
            },
        ]
    }
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = payload

    with patch(
        "rst_threat_feed_client.mitre_ttp_downloader.requests.get",
        return_value=response,
    ) as mock_get:
        result = downloader.download_mitre_ttps()

    assert result == str(mapping_file)
    mock_get.assert_called_once()
    written = json.loads(mapping_file.read_text(encoding="utf-8"))
    assert written == {"T1059": "Command and Scripting Interpreter"}


def test_download_merges_existing_stale_mapping(downloader, mapping_file):
    mapping_file.write_text(json.dumps({"T1001": "Data Obfuscation"}))
    stale = datetime.now() - timedelta(days=4)
    import os

    os.utime(mapping_file, (stale.timestamp(), stale.timestamp()))

    payload = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Command and Scripting Interpreter",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059"}
                ],
            }
        ]
    }
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = payload

    with patch(
        "rst_threat_feed_client.mitre_ttp_downloader.requests.get",
        return_value=response,
    ):
        downloader.download_mitre_ttps()

    written = json.loads(mapping_file.read_text(encoding="utf-8"))
    assert written == {
        "T1001": "Data Obfuscation",
        "T1059": "Command and Scripting Interpreter",
    }


def test_download_raises_on_request_error(downloader):
    with patch(
        "rst_threat_feed_client.mitre_ttp_downloader.requests.get",
        side_effect=RequestException("network down"),
    ):
        with pytest.raises(RequestException):
            downloader.download_mitre_ttps()


def test_download_raises_on_invalid_json(downloader):
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.side_effect = json.JSONDecodeError("bad", "doc", 0)

    with patch(
        "rst_threat_feed_client.mitre_ttp_downloader.requests.get",
        return_value=response,
    ):
        with pytest.raises(json.JSONDecodeError):
            downloader.download_mitre_ttps()
