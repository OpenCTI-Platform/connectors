# isort:skip_file
# pragma: no cover
from tenable_security_center.adapters.tsc_api.v5_13_from_asset import (
    _FindingAPI,
    _ScanResultsAPI,
)

from unittest.mock import Mock


def test_scan_results_api_get_scanned_assets_info_should_return_tuple_of_string():
    """Test that the method returns a tuple of strings.

    This is important because the results is then used in AssetAPI._fetch_data_chunks and can raise error if not properly formated.
    See https://github.com/OpenCTI-Platform/connectors/issues/3564

    """

    # Given
    # A Mocked Client with a get method returning bad formatted data
    tsc_api_client = Mock()
    tsc_api_client.get.return_value.json.return_value = {
        "response": {
            "progress": {"scannedIPs": "0.0.0.0"},
            "repository": {"id": 1},
        }
    }
    api = _ScanResultsAPI(
        tsc_client=tsc_api_client, logger=Mock(), since_datetime=Mock()
    )

    # When
    # We call the method
    result = api.get_scanned_assets_info(scan_id="scan_id")

    # Then
    # The method should return a tuple of strings
    assert result[0] == "0.0.0.0"  # noqa: S101 # we use assert in unit test context
    assert result[1] == "1"  # noqa: S101


def _make_raw_finding_response(asset_exposure_score="750"):
    """Build a minimal raw API response for a finding."""
    return {
        "pluginName": "Test Plugin",
        "pluginID": "12345",
        "ip": "192.168.1.1",
        "protocol": "TCP",
        "port": "443",
        "severity": {"name": "high"},
        "hasBeenMitigated": "0",
        "acceptRisk": "0",
        "recastRisk": "0",
        "firstSeen": "1700000000",
        "lastSeen": "1700000000",
        "exploitAvailable": "No",
        "hostUniqueness": "ip",
        "vulnUniqueness": "pluginID",
        "uniqueness": "ip,pluginID",
        "assetExposureScore": asset_exposure_score,
        "seolDate": "1700000000",
    }


def test_parse_response_with_empty_asset_exposure_score():
    """Regression test for #6372: empty string asset_exposure_score should not crash."""

    # Given a raw response with an empty string for assetExposureScore
    raw_response = _make_raw_finding_response(asset_exposure_score="")

    # When we parse it
    result = _FindingAPI.parse_response(raw_response)

    # Then asset_exposure_score should be None (not raise)
    assert result["asset_exposure_score"] is None  # noqa: S101


def test_parse_response_with_valid_asset_exposure_score():
    """asset_exposure_score should be correctly parsed as a float when present."""

    # Given a raw response with a valid numeric string
    raw_response = _make_raw_finding_response(asset_exposure_score="750")

    # When we parse it
    result = _FindingAPI.parse_response(raw_response)

    # Then asset_exposure_score should be the float value
    assert result["asset_exposure_score"] == 750.0  # noqa: S101


def test_parse_response_with_zero_asset_exposure_score():
    """asset_exposure_score of '0' should be parsed as 0.0, not None."""

    # Given a raw response with "0" as score
    raw_response = _make_raw_finding_response(asset_exposure_score="0")

    # When we parse it
    result = _FindingAPI.parse_response(raw_response)

    # Then asset_exposure_score should be 0.0
    assert result["asset_exposure_score"] == 0.0  # noqa: S101
