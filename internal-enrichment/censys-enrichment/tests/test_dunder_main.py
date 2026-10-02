"""Tests for the censys_enrichment.__main__ entry point wiring."""

from unittest.mock import MagicMock, patch

import pytest
from censys_enrichment.__main__ import main

# =====================
# Test Cases
# =====================


# Scenario: main() wires config, helper, client, converter and connector together
def test_main_happy_path() -> None:
    """Test that main() builds all collaborators and runs the connector."""
    fake_config = MagicMock()
    fake_config.censys_enrichment.organisation_id.get_secret_value.return_value = (
        "org-id"
    )
    fake_config.censys_enrichment.token.get_secret_value.return_value = "token"
    fake_config.censys_enrichment.nvd_api_key = None
    fake_helper = MagicMock()
    fake_client = MagicMock()
    fake_converter = MagicMock()
    fake_connector = MagicMock()

    with patch(
        "censys_enrichment.settings.ConfigLoader", return_value=fake_config
    ), patch(
        "pycti.OpenCTIConnectorHelper", return_value=fake_helper
    ) as m_helper, patch(
        "censys_enrichment.client.Client", return_value=fake_client
    ) as m_client, patch(
        "censys_enrichment.converter.Converter", return_value=fake_converter
    ), patch(
        "censys_enrichment.connector.Connector", return_value=fake_connector
    ) as m_connector:
        main()

    m_helper.assert_called_once_with(
        config=fake_config.to_helper_config(), playbook_compatible=True
    )
    m_client.assert_called_once_with(
        organisation_id="org-id", token="token", nvd_api_key=None
    )
    m_connector.assert_called_once_with(
        config=fake_config,
        helper=fake_helper,
        client=fake_client,
        converter=fake_converter,
    )
    fake_connector.run.assert_called_once()


# Scenario: main() passes the NVD API key through when configured
def test_main_passes_nvd_api_key_when_set() -> None:
    """Test that main() unwraps a configured NVD API key SecretStr."""
    fake_config = MagicMock()
    fake_config.censys_enrichment.organisation_id.get_secret_value.return_value = (
        "org-id"
    )
    fake_config.censys_enrichment.token.get_secret_value.return_value = "token"
    fake_config.censys_enrichment.nvd_api_key.get_secret_value.return_value = "nvd-key"

    with patch(
        "censys_enrichment.settings.ConfigLoader", return_value=fake_config
    ), patch("pycti.OpenCTIConnectorHelper"), patch(
        "censys_enrichment.client.Client"
    ) as m_client, patch(
        "censys_enrichment.converter.Converter"
    ), patch(
        "censys_enrichment.connector.Connector"
    ):
        main()

    m_client.assert_called_once_with(
        organisation_id="org-id", token="token", nvd_api_key="nvd-key"
    )


# Scenario: main() exits with an error code on unexpected startup failures
def test_main_unexpected_error_exits() -> None:
    """Test that main() prints a traceback and exits(1) on unexpected errors."""
    with patch(
        "censys_enrichment.settings.ConfigLoader", side_effect=RuntimeError("boom")
    ):
        with pytest.raises(SystemExit) as exc_info:
            main()
    assert exc_info.value.code == 1  # noqa: S101
