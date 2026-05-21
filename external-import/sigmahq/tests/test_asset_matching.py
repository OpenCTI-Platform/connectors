"""Regression tests for the rule-package asset selector.

SigmaHQ release assets are named ``<rule_package>_<date>.zip`` and the
three ``sigma_core`` variants overlap by prefix:

    sigma_core_<date>.zip
    sigma_core+_<date>.zip
    sigma_core++_<date>.zip

A naive ``rule_package in asset["name"]`` substring match would let
``sigma_core`` also match the ``+`` / ``++`` variants (and, without
``break``, would have overwritten the result with the last matching
asset). The selector MUST disambiguate the three variants and pick a
single asset deterministically regardless of the order in which
GitHub returns them.

These tests exercise the selector directly via ``_collect_intelligence``
with a stubbed-out ``SigmaHQClient`` so the selection logic is pinned
without an HTTP round-trip.
"""

from unittest.mock import MagicMock

import pytest
from connector.connector import SigmaHQConnector


def _make_connector(monkeypatch=None) -> SigmaHQConnector:
    """Build a ``SigmaHQConnector`` with all heavy collaborators mocked."""
    connector = SigmaHQConnector.__new__(SigmaHQConnector)
    connector.config = MagicMock()
    connector.helper = MagicMock()
    connector.client = MagicMock()
    connector.converter_to_stix = MagicMock()
    # ``_collect_intelligence`` defers to the converter; for the
    # asset-selection contract we only care WHICH download_url was
    # passed to the client, so ``convert_sigma_rule`` returning ``[]``
    # is fine (the helper logs "nothing to do").
    connector.converter_to_stix.convert_sigma_rule.return_value = []
    return connector


def _release(*asset_names: str) -> dict:
    """Build a fake GitHub release-metadata payload."""
    return {
        "tag": "v20251119",
        "assets": [
            {
                "name": name,
                "browser_download_url": f"https://example.invalid/{name}",
            }
            for name in asset_names
        ],
    }


@pytest.mark.parametrize(
    ("rule_package", "expected_asset"),
    [
        ("sigma_core", "sigma_core_20251119.zip"),
        ("sigma_core+", "sigma_core+_20251119.zip"),
        ("sigma_core++", "sigma_core++_20251119.zip"),
        ("sigma_all_rules", "sigma_all_rules_20251119.zip"),
        (
            "sigma_emerging_threats_addon",
            "sigma_emerging_threats_addon_20251119.zip",
        ),
    ],
)
def test_overlapping_rule_packages_disambiguate(rule_package, expected_asset):
    connector = _make_connector()
    release_metadata = _release(
        "sigma_all_rules_20251119.zip",
        "sigma_core_20251119.zip",
        "sigma_core+_20251119.zip",
        "sigma_core++_20251119.zip",
        "sigma_emerging_threats_addon_20251119.zip",
    )
    connector._collect_intelligence(release_metadata, rule_package)
    # The client is called exactly once with the disambiguated asset.
    assert connector.client.download_and_convert_package.call_count == 1
    expected_url = f"https://example.invalid/{expected_asset}"
    connector.client.download_and_convert_package.assert_called_once_with(expected_url)


def test_first_matching_asset_wins_regardless_of_order():
    """``break`` after the first match makes the selection deterministic.

    GitHub does not guarantee a stable asset ordering across releases,
    so the selector must not rely on it. This test rearranges the
    ``sigma_core`` variants so the wrong one appears first / last and
    confirms the selector still picks the exact-match one.
    """
    connector = _make_connector()
    release_metadata = _release(
        # ``sigma_core++`` first — a naive selector that uses
        # ``rule_package in asset['name']`` without ``break`` would
        # have overwritten the result on every later iteration.
        "sigma_core++_20251119.zip",
        "sigma_core+_20251119.zip",
        "sigma_core_20251119.zip",
    )
    connector._collect_intelligence(release_metadata, "sigma_core")
    connector.client.download_and_convert_package.assert_called_once_with(
        "https://example.invalid/sigma_core_20251119.zip"
    )


def test_no_match_does_not_call_client():
    connector = _make_connector()
    release_metadata = _release("some_other_package_20251119.zip")
    connector._collect_intelligence(release_metadata, "sigma_core")
    connector.client.download_and_convert_package.assert_not_called()
