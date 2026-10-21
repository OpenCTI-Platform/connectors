# isort:skip_file
# pragma: no cover
from tenable_security_center.adapters.tsc_api.v5_13_from_asset import (
    _CVEAPI,
    _CVEsAPI,
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


def test_cve_api_from_id_only_should_build_a_degraded_cve():
    """from_id_only should build a CVE with only its id set, everything else None.

    Used when Tenable Security Center has no details for a CVE id (e.g. an
    empty response from the CVE endpoint) so the relationship to the
    system/software can still be created.
    """
    # Given a CVE id with no available details
    cve_id = "CVE-2021-9999"

    # When building a degraded CVE from it
    cve = _CVEAPI.from_id_only(cve_id)

    # Then only the name is set, everything else is None
    assert cve.name == cve_id  # noqa: S101
    assert cve.description is None  # noqa: S101
    assert cve.publication_datetime is None  # noqa: S101
    assert cve.last_modified_datetime is None  # noqa: S101
    assert cve.cpes is None  # noqa: S101
    assert cve.cvss_v3_score is None  # noqa: S101
    assert cve.cvss_v3_vector is None  # noqa: S101
    assert cve.epss_score is None  # noqa: S101
    assert cve.epss_percentile is None  # noqa: S101


def test_cves_api_fetch_cves_should_yield_id_only_cve_on_empty_response():
    """Regression test: Tenable Security Center returning an empty body for a
    CVE id (HTTP 200, no content) must not be skipped nor crash the run; the
    relationship to the CVE should still be created using its id only.
    """
    # Given a mocked Tenable Security Center client whose CVE endpoint
    # returns an empty body (no error raised, just an empty response)
    tsc_client = Mock()
    tsc_client._url = "https://sc.example.com"
    empty_response = Mock()
    empty_response.content = b""
    empty_response.raise_for_status = Mock()
    tsc_client._session.get.return_value = empty_response

    api = _CVEsAPI(tsc_client=tsc_client, logger=Mock(), num_threads=1)

    # When fetching a CVE whose details are unavailable
    cves = list(api.fetch_cves(["CVE-2021-9999"]))

    # Then a degraded CVE (id only) is returned, not skipped
    assert len(cves) == 1  # noqa: S101
    assert cves[0].name == "CVE-2021-9999"  # noqa: S101
    assert cves[0].description is None  # noqa: S101


def test_cves_api_fetch_cves_should_return_full_cve_on_valid_response():
    """A normal, non-empty response should still be parsed into a full CVE."""
    # Given a mocked Tenable Security Center client returning a valid CVE payload
    tsc_client = Mock()
    tsc_client._url = "https://sc.example.com"
    valid_response = Mock()
    valid_response.content = b'{"primary_vuln_id": "CVE-2021-1234"}'
    valid_response.raise_for_status = Mock()
    valid_response.json.return_value = {
        "primary_vuln_id": "CVE-2021-1234",
        "descriptions": [
            {
                "description_text": "A test vulnerability.",
                "publication_date": "2021-01-01T00:00:00Z",
            },
            {
                "description_text": "A test vulnerability.",
                "publication_date": "2021-01-02T00:00:00Z",
            },
        ],
        "cpe_metrics": [],
        "cvss_metrics": [{}],
        "epss_metrics": [{}],
    }
    tsc_client._session.get.return_value = valid_response

    api = _CVEsAPI(tsc_client=tsc_client, logger=Mock(), num_threads=1)

    # When fetching that CVE
    cves = list(api.fetch_cves(["CVE-2021-1234"]))

    # Then the full CVE details are returned
    assert len(cves) == 1  # noqa: S101
    assert cves[0].name == "CVE-2021-1234"  # noqa: S101
    assert cves[0].description == "A test vulnerability."  # noqa: S101
