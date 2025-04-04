# isort:skip_file
# pragma: no cover
from tenable_security_center.adapters.tsc_api.v5_13_from_asset import _ScanResultsAPI

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
