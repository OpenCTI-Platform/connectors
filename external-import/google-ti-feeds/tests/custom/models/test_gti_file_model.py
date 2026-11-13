"""Tests for the GTI file response models."""

import pytest
from connector.src.custom.models.gti.gti_file_model import (
    GTIFileData,
    LastAnalysisResult,
)


@pytest.mark.parametrize(
    "engine_update, expected",
    [
        pytest.param("20251015", "20251015", id="string-unchanged"),
        pytest.param(1760519377, "1760519377", id="int-timestamp-coerced"),
        pytest.param(None, None, id="none-unchanged"),
    ],
)
def test_last_analysis_result_engine_update(engine_update, expected):
    """`engine_update` is exposed as `str | None` whatever type the API sends."""
    result = LastAnalysisResult.model_validate(
        {"engine_name": "google_safebrowsing", "engine_update": engine_update}
    )

    assert result.engine_update == expected  # noqa: S101


def test_gti_file_data_accepts_int_engine_update():
    """A numeric `engine_update` on one engine must not fail the whole file."""
    payload = {
        "id": "a" * 64,
        "type": "file",
        "attributes": {
            "sha256": "a" * 64,
            "last_analysis_results": {
                "google_safebrowsing": {
                    "category": "harmless",
                    "engine_name": "Google Safebrowsing",
                    "engine_update": 1760519377,
                    "method": "blacklist",
                    "result": "clean",
                }
            },
        },
    }

    data = GTIFileData.model_validate(payload)

    results = data.attributes.last_analysis_results
    assert results["google_safebrowsing"].engine_update == "1760519377"  # noqa: S101
