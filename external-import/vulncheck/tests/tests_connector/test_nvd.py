"""Tests for NVD2 helpers: query param precedence and SSVC mapping."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from connector.sources import names
from connector.util.nvd import (
    build_nvd2_query_params,
    get_nvd_ssvc_properties,
    get_vulncheck_ssvc_properties,
)
from vulncheck_sdk.models.api_nvd20_metric import ApiNVD20Metric
from vulncheck_sdk.models.api_nvd20_metric_extended import ApiNVD20MetricExtended

SRC = names.NIST_NVD2

# Fixed "now" so first-run window assertions can't flake on a midnight rollover
# between the test's datetime.now() and the one inside build_nvd2_query_params.
FROZEN_NOW = datetime(2026, 6, 27, 12, 0, 0)


def _config(**nvd2):
    # Mirrors post-validation types: max_date_range is a timedelta and the
    # last-mod overrides are datetimes (SimpleNamespace bypasses pydantic).
    base = dict(
        nvd2_last_mod_start_date=None,
        nvd2_last_mod_end_date=None,
        nvd2_pull_history=False,
        nvd2_max_date_range=timedelta(days=120),
    )
    base.update(nvd2)
    return SimpleNamespace(vulncheck=SimpleNamespace(**base))


def _params(config, state):
    return build_nvd2_query_params(config, state, SRC, MagicMock())


def test_explicit_override_wins_over_state():
    params = _params(
        _config(nvd2_last_mod_start_date=datetime(2024, 1, 1)),
        {SRC: "2026-06-20 10:00:00"},
    )
    assert params == {"last_mod_start_date": "2024-01-01"}


def test_state_drives_incremental():
    assert _params(_config(), {SRC: "2026-06-20 10:00:00"}) == {
        "last_mod_start_date": "2026-06-20"
    }


def test_first_run_bounded_by_max_date_range():
    with patch("connector.util.nvd.datetime") as mock_dt:
        mock_dt.now.return_value = FROZEN_NOW
        params = _params(_config(), None)
    expected = (FROZEN_NOW - timedelta(days=120)).strftime("%Y-%m-%d")
    assert params == {"last_mod_start_date": expected}


def test_first_run_custom_max_date_range():
    with patch("connector.util.nvd.datetime") as mock_dt:
        mock_dt.now.return_value = FROZEN_NOW
        params = _params(_config(nvd2_max_date_range=timedelta(days=7)), {})
    expected = (FROZEN_NOW - timedelta(days=7)).strftime("%Y-%m-%d")
    assert params == {"last_mod_start_date": expected}


def test_pull_history_means_no_filter():
    assert _params(_config(nvd2_pull_history=True), None) == {}


def test_end_date_added():
    params = _params(
        _config(nvd2_pull_history=True, nvd2_last_mod_end_date=datetime(2026, 6, 27)),
        None,
    )
    assert params == {"last_mod_end_date": "2026-06-27"}


SSVC_ACTIVE = {
    "x_opencti_ssvc_exploitation": "active",
    "x_opencti_ssvc_automatable": "yes",
    "x_opencti_ssvc_technical_impact": "total",
}


def _vc_ssvc(*entries):
    return ApiNVD20MetricExtended.from_dict({"ssvc": list(entries)}).ssvc


def test_vulncheck_ssvc_prefers_vulncheck_source():
    ssvc = _vc_ssvc(
        {
            "source": "CISA-ADP",
            "exploitation": "POC",
            "automatable": "NO",
            "technicalImpact": "PARTIAL",
        },
        {
            "source": "VulnCheck",
            "exploitation": "ACTIVE",
            "automatable": "YES",
            "technicalImpact": "TOTAL",
        },
    )
    assert get_vulncheck_ssvc_properties(ssvc) == SSVC_ACTIVE


def test_vulncheck_ssvc_falls_back_to_cisa_only():
    cisa = {"source": "CISA-ADP", "exploitation": "POC"}
    other = {"source": "Other", "exploitation": "NONE"}
    assert get_vulncheck_ssvc_properties(_vc_ssvc(other, cisa)) == {
        "x_opencti_ssvc_exploitation": "proof_of_concept"
    }
    assert get_vulncheck_ssvc_properties(_vc_ssvc(other)) == {}


def test_vulncheck_ssvc_drops_unknown_values():
    ssvc = _vc_ssvc(
        {"source": "VulnCheck", "exploitation": "SOMETIMES", "automatable": "YES"}
    )
    assert get_vulncheck_ssvc_properties(ssvc) == {"x_opencti_ssvc_automatable": "yes"}


def test_vulncheck_ssvc_missing():
    assert get_vulncheck_ssvc_properties(None) == {}
    assert get_vulncheck_ssvc_properties([]) == {}


def _nvd_ssvc(exploitation, automatable, technical_impact):
    return ApiNVD20Metric.from_dict(
        {
            "ssvcV203": [
                {
                    "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                    "ssvcData": {
                        "options": [
                            {"exploitation": exploitation},
                            {"automatable": automatable},
                            {"technicalImpact": technical_impact},
                        ],
                        "role": "CISA Coordinator",
                        "version": "2.0.3",
                    },
                }
            ]
        }
    ).ssvc_v203


def test_nvd_ssvc_maps_options():
    assert get_nvd_ssvc_properties(_nvd_ssvc("active", "yes", "total")) == SSVC_ACTIVE


def test_nvd_ssvc_translates_poc():
    assert get_nvd_ssvc_properties(_nvd_ssvc("poc", "no", "partial")) == {
        "x_opencti_ssvc_exploitation": "proof_of_concept",
        "x_opencti_ssvc_automatable": "no",
        "x_opencti_ssvc_technical_impact": "partial",
    }


def test_nvd_ssvc_missing():
    assert get_nvd_ssvc_properties(None) == {}
    assert get_nvd_ssvc_properties([]) == {}
