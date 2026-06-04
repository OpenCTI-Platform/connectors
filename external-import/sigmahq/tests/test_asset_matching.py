"""Regression tests for the rule-package asset selector.

SigmaHQ release assets are named ``<rule_package>.zip`` and the
three ``sigma_core`` variants overlap by prefix:

    sigma_core.zip
    sigma_core+.zip
    sigma_core++.zip

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
        "tag": "r2026-04-01",
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
        ("sigma_core", "sigma_core.zip"),
        ("sigma_core+", "sigma_core+.zip"),
        ("sigma_core++", "sigma_core++.zip"),
        ("sigma_all_rules", "sigma_all_rules.zip"),
        (
            "sigma_emerging_threats_addon",
            "sigma_emerging_threats_addon.zip",
        ),
    ],
)
def test_overlapping_rule_packages_disambiguate(rule_package, expected_asset):
    connector = _make_connector()
    release_metadata = _release(
        "sigma_all_rules.zip",
        "sigma_core.zip",
        "sigma_core+.zip",
        "sigma_core++.zip",
        "sigma_emerging_threats_addon.zip",
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
        "sigma_core++.zip",
        "sigma_core+.zip",
        "sigma_core.zip",
    )
    connector._collect_intelligence(release_metadata, "sigma_core")
    connector.client.download_and_convert_package.assert_called_once_with(
        "https://example.invalid/sigma_core.zip"
    )


def test_no_match_does_not_call_client():
    connector = _make_connector()
    release_metadata = _release("some_other_package.zip")
    connector._collect_intelligence(release_metadata, "sigma_core")
    connector.client.download_and_convert_package.assert_not_called()


def test_collect_intelligence_resets_converter_dedup_state():
    """Per-bundle dedup contract is enforced at the connector layer.

    ``SigmaHQConnector`` keeps a single ``ConverterToStix`` instance
    for its lifetime, so the converter's per-bundle dedup state must
    be reset at the start of every scheduled run — otherwise the
    second bundle would emit ``Relationship`` SDOs whose AttackPattern
    / Vulnerability targets were already "seen" in the first run.
    Pin the wiring at this layer so a future refactor that moves the
    reset out of ``_collect_intelligence`` (e.g. into the converter
    itself) is caught here, not as an integration regression.
    """
    connector = _make_connector()
    release_metadata = _release("sigma_core.zip")
    connector._collect_intelligence(release_metadata, "sigma_core")
    connector.converter_to_stix.reset_dedup_state.assert_called_once()


def test_tlp_level_setting_threads_through_to_converter(monkeypatch):
    """Connector instantiates ``ConverterToStix`` with the configured TLP.

    Pins the wiring from ``ConnectorSettings.sigmahq.tlp_level`` to the
    ``ConverterToStix(tlp_level=…)`` argument so a future refactor
    cannot silently re-introduce the previous hardcoded ``"clear"``.
    Building the real ``ConverterToStix`` (as opposed to a mock) keeps
    the test honest: a regression on the wiring would produce a
    ``MarkingDefinition`` whose id does not match the configured
    level.

    The OpenCTI / connector env vars are required by
    ``BaseConnectorSettings`` (``url`` / ``token`` / ``id`` are
    declared without defaults). They are wired here as
    ``monkeypatch`` env vars so the ``ConnectorSettings`` constructor
    runs end-to-end against the real Pydantic validation path —
    short-circuiting it via ``model_construct`` would skip the very
    field-validation behaviour that ensures ``tlp_level`` is one of
    the allowed labels.
    """
    import stix2
    from connector.settings import ConnectorSettings

    monkeypatch.setenv("OPENCTI_URL", "http://opencti.test")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("CONNECTOR_ID", "00000000-0000-0000-0000-000000000000")
    monkeypatch.setenv("CONNECTOR_SCOPE", "Indicator")
    monkeypatch.setenv("SIGMAHQ_TLP_LEVEL", "amber")

    settings = ConnectorSettings()
    assert settings.sigmahq.tlp_level == "amber"

    helper = MagicMock()
    connector = SigmaHQConnector(config=settings, helper=helper)
    # The converter materialised the TLP marking from the configured
    # level. ``stix2.TLP_AMBER`` carries the canonical id, so an
    # ``"amber"`` setting must produce that exact id — re-running with
    # the default ``"clear"`` would produce a different (custom)
    # marking id, so this assertion fails on regression.
    assert connector.converter_to_stix.tlp_marking.id == stix2.TLP_AMBER.id
