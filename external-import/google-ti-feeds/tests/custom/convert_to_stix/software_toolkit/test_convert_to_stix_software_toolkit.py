"""Tests for ConvertToSTIXSoftwareToolkit: convert_software_toolkit_to_stix."""

import logging
from unittest.mock import MagicMock

import pytest
from connector.src.custom.convert_to_stix.software_toolkit.convert_to_stix_software_toolkit import (
    ConvertToSTIXSoftwareToolkit,
)

# =====================
# Fixtures
# =====================


@pytest.fixture
def converter():
    """Create a ConvertToSTIXSoftwareToolkit with mocked factory and config."""
    config = MagicMock()
    config.api_url.unicode_string.return_value = "https://fake-gti.api"
    logger = logging.getLogger("test_convert_to_stix_software_toolkit")

    converter_instance = ConvertToSTIXSoftwareToolkit(
        config=config, logger=logger, tlp_level="white"
    )
    # Replace the real factory with a mock so tests can control converter behavior
    converter_instance.converter_factory = MagicMock()
    return converter_instance


# =====================
# convert_software_toolkit_to_stix tests
# =====================


class TestConvertSoftwareToolkitToStix:
    """Tests for ConvertToSTIXSoftwareToolkit.convert_software_toolkit_to_stix."""

    def test_given_valid_toolkit_data_when_convert_then_returns_list_of_entities(
        self, converter
    ):
        """When converter returns a list, it is passed through as-is."""
        fake_entity = MagicMock()
        fake_entity.type = "tool"

        mock_inner_converter = MagicMock()
        mock_inner_converter.convert_single.return_value = [fake_entity]
        converter.converter_factory.create_converter_by_name.return_value = (
            mock_inner_converter
        )

        software_toolkit_data = MagicMock()
        result = converter.convert_software_toolkit_to_stix(software_toolkit_data)

        assert result == [fake_entity]
        converter.converter_factory.create_converter_by_name.assert_called_once_with(
            "software_toolkit"
        )
        mock_inner_converter.convert_single.assert_called_once_with(
            software_toolkit_data
        )

    def test_given_converter_returns_single_entity_when_convert_then_wraps_in_list(
        self, converter
    ):
        """When converter returns a non-list, it is wrapped in a list."""
        fake_entity = MagicMock()
        fake_entity.type = "tool"

        mock_inner_converter = MagicMock()
        mock_inner_converter.convert_single.return_value = fake_entity  # not a list
        converter.converter_factory.create_converter_by_name.return_value = (
            mock_inner_converter
        )

        software_toolkit_data = MagicMock()
        result = converter.convert_software_toolkit_to_stix(software_toolkit_data)

        assert isinstance(result, list)
        assert result == [fake_entity]

    def test_given_converter_raises_when_convert_then_returns_empty_list(
        self, converter
    ):
        """When converter raises an exception, returns empty list and logs warning."""
        mock_inner_converter = MagicMock()
        mock_inner_converter.convert_single.side_effect = RuntimeError(
            "conversion failed"
        )
        converter.converter_factory.create_converter_by_name.return_value = (
            mock_inner_converter
        )

        software_toolkit_data = MagicMock()
        result = converter.convert_software_toolkit_to_stix(software_toolkit_data)

        assert result == []

    def test_given_factory_raises_when_convert_then_returns_empty_list(self, converter):
        """When factory.create_converter_by_name raises, returns empty list."""
        converter.converter_factory.create_converter_by_name.side_effect = KeyError(
            "software_toolkit"
        )

        software_toolkit_data = MagicMock()
        result = converter.convert_software_toolkit_to_stix(software_toolkit_data)

        assert result == []

    def test_given_valid_data_when_convert_then_returns_non_empty_list(self, converter):
        """Successful conversion returns a non-empty list."""
        fake_entities = [MagicMock(), MagicMock()]
        mock_inner_converter = MagicMock()
        mock_inner_converter.convert_single.return_value = fake_entities
        converter.converter_factory.create_converter_by_name.return_value = (
            mock_inner_converter
        )

        result = converter.convert_software_toolkit_to_stix(MagicMock())

        assert len(result) == 2
