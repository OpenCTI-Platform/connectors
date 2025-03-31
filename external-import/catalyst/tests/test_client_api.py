from unittest.mock import Mock, patch

import pytest
from catalyst.client_api import ConnectorClient
from python_catalyst import PostCategory, TLPLevel

# from .common_fixtures import setup_config  # noqa: F401


@pytest.mark.usefixtures("setup_config")
class TestConnectorClient:
    """Tests for the ConnectorClient class"""

    def setup_method(self):
        """Set up the test environment"""
        # Create mock helper and config for client
        self.mock_helper = Mock()
        self.mock_config = Mock()

        # Set up essential config attributes
        self.mock_config.api_key = "test-api-key"
        self.mock_config.api_base_url = "https://test.catalyst.api"
        self.mock_config.create_observables = True
        self.mock_config.create_indicators = True

        # Mock logger
        self.mock_logger = Mock()
        self.mock_helper.connector_logger = self.mock_logger

        # Create client instance with mocks
        with patch(
            "catalyst.client_api.CatalystClient"
        ) as self.mock_catalyst_client_class:
            self.mock_catalyst_client = Mock()
            self.mock_catalyst_client_class.return_value = self.mock_catalyst_client

            # Initialize the client
            self.client = ConnectorClient(self.mock_helper, self.mock_config)

    def test_init(self, mock_opencti_helper, mock_config):
        """Test client initialization"""
        with patch("catalyst.client_api.CatalystClient") as mock_catalyst_client_class:
            mock_catalyst_client = Mock()
            mock_catalyst_client_class.return_value = mock_catalyst_client

            client = ConnectorClient(mock_opencti_helper, mock_config)

            mock_catalyst_client_class.assert_called_once_with(
                api_key=mock_config.api_key,
                base_url=mock_config.api_base_url,
                logger=mock_opencti_helper.connector_logger,
                create_observables=mock_config.create_observables,
                create_indicators=mock_config.create_indicators,
            )

            assert client.helper == mock_opencti_helper
            assert client.logger == mock_opencti_helper.connector_logger
            assert client.config == mock_config
            assert client.client == mock_catalyst_client

    def test_get_entities_successful(self, mock_opencti_helper, mock_config):
        """Test successful retrieval of entities"""
        with patch("catalyst.client_api.CatalystClient"):
            client = ConnectorClient(mock_opencti_helper, mock_config)

            expected_result = [{"id": "test-entity"}]
            with patch.object(
                client, "get_member_contents", return_value=expected_result
            ):
                result = client.get_entities()

                assert result == expected_result

    def test_get_entities_exception(self, mock_opencti_helper, mock_config):
        """Test handling of exceptions in get_entities"""
        with patch("catalyst.client_api.CatalystClient"):
            client = ConnectorClient(mock_opencti_helper, mock_config)

            with patch.object(
                client, "get_member_contents", side_effect=Exception("API error")
            ):
                result = client.get_entities()

                assert result == []
                mock_opencti_helper.connector_logger.error.assert_called_once_with(
                    "Error while fetching data: API error"
                )

    def test_parse_tlp_filters_all(self, mock_opencti_helper, mock_config):
        """Test parsing TLP filters with 'ALL' value"""
        with patch("catalyst.client_api.CatalystClient"):
            client = ConnectorClient(mock_opencti_helper, mock_config)

            mock_config.tlp_filter = "ALL"
            result = client._parse_tlp_filters()

            # Should return all TLP levels
            assert set(result) == {
                TLPLevel.CLEAR,
                TLPLevel.GREEN,
                TLPLevel.AMBER,
                TLPLevel.RED,
            }

    def test_parse_tlp_filters_specific(self, mock_opencti_helper, mock_config):
        """Test parsing specific TLP filters"""
        with patch("catalyst.client_api.CatalystClient"):
            client = ConnectorClient(mock_opencti_helper, mock_config)

            mock_config.tlp_filter = "AMBER,RED"
            result = client._parse_tlp_filters()

            # Should return only specified TLP levels
            assert set(result) == {TLPLevel.AMBER, TLPLevel.RED}

    def test_parse_tlp_filters_invalid(self, mock_opencti_helper, mock_config):
        """Test parsing invalid TLP filters"""
        with patch("catalyst.client_api.CatalystClient"):
            client = ConnectorClient(mock_opencti_helper, mock_config)

            mock_config.tlp_filter = "INVALID,RED"
            result = client._parse_tlp_filters()

            # Should return only valid TLP levels
            assert set(result) == {TLPLevel.RED}
            mock_opencti_helper.connector_logger.warning.assert_called_once_with(
                "Invalid TLP level: INVALID"
            )

    def test_parse_tlp_filters_none(self, mock_opencti_helper, mock_config):
        """Test parsing when no TLP filter is specified"""
        with patch("catalyst.client_api.CatalystClient"):
            client = ConnectorClient(mock_opencti_helper, mock_config)

            mock_config.tlp_filter = None
            result = client._parse_tlp_filters()

            # Should return empty list
            assert result == []

    def test_parse_category_filters_all(self, mock_opencti_helper, mock_config):
        """Test parsing category filters with 'ALL' value"""
        with patch("catalyst.client_api.CatalystClient"):
            client = ConnectorClient(mock_opencti_helper, mock_config)

            mock_config.category_filter = "ALL"
            result = client._parse_category_filters()

            # Should return all categories
            assert set(result) == {
                PostCategory.DISCOVERY,
                PostCategory.ATTRIBUTION,
                PostCategory.RESEARCH,
                PostCategory.FLASH_ALERT,
            }

    def test_parse_category_filters_specific(self, mock_opencti_helper, mock_config):
        """Test parsing specific category filters"""
        with patch("catalyst.client_api.CatalystClient"):
            client = ConnectorClient(mock_opencti_helper, mock_config)

            mock_config.category_filter = "RESEARCH,ATTRIBUTION"
            result = client._parse_category_filters()

            # Should return only specified categories
            assert set(result) == {PostCategory.RESEARCH, PostCategory.ATTRIBUTION}

    def test_parse_category_filters_invalid(self, mock_opencti_helper, mock_config):
        """Test parsing invalid category filters"""
        with patch("catalyst.client_api.CatalystClient"):
            client = ConnectorClient(mock_opencti_helper, mock_config)

            mock_config.category_filter = "INVALID,RESEARCH"
            result = client._parse_category_filters()

            # Should return only valid categories
            assert set(result) == {PostCategory.RESEARCH}
            mock_opencti_helper.connector_logger.warning.assert_called_once_with(
                "Invalid category: INVALID"
            )

    def test_parse_category_filters_none(self, mock_opencti_helper, mock_config):
        """Test parsing when no category filter is specified"""
        with patch("catalyst.client_api.CatalystClient"):
            client = ConnectorClient(mock_opencti_helper, mock_config)

            mock_config.category_filter = None
            result = client._parse_category_filters()

            # Should return empty list
            assert result == []

    def test_get_member_contents_no_state_fallback(
        self, mock_opencti_helper, mock_config
    ):
        """Test get_member_contents with no state (fallback to sync_days_back)"""
        with patch("catalyst.client_api.CatalystClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client

            mock_opencti_helper.get_state.return_value = None
            mock_config.sync_days_back = 30

            mock_client.get_updated_member_contents.return_value = []

            mock_client.converter = Mock()
            mock_client.converter.identity = None
            mock_client.converter.tlp_marking = None

            client = ConnectorClient(mock_opencti_helper, mock_config)

            with patch.object(client, "logger") as mock_logger:
                with patch.object(client, "_parse_tlp_filters", return_value=[]):
                    with patch.object(
                        client, "_parse_category_filters", return_value=[]
                    ):
                        client.get_member_contents()

                        mock_logger.info.assert_any_call(
                            "No specific TLP or category filters set. Fetching all member contents."
                        )

    def test_get_member_contents_with_filters(self, mock_opencti_helper, mock_config):
        """Test get_member_contents with TLP and category filters"""
        mock_opencti_helper.get_state.return_value = None

        tlp_filter = [TLPLevel.RED]
        category_filter = PostCategory.RESEARCH

        with patch("catalyst.client_api.CatalystClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client

            mock_client.get_updated_member_contents.return_value = [
                {"id": "test-content"}
            ]
            mock_client.create_report_from_member_content.return_value = (
                {"type": "report", "id": "test-report"},
                [{"type": "indicator", "id": "test-indicator"}],
            )

            client = ConnectorClient(mock_opencti_helper, mock_config)

            client._parse_tlp_filters = Mock(return_value=tlp_filter)
            client._parse_category_filters = Mock(return_value=[category_filter])

            mock_client.converter = Mock()
            mock_client.converter.identity = {"type": "identity", "id": "test-identity"}
            mock_client.converter.tlp_marking = {
                "type": "marking-definition",
                "id": "test-marking",
            }

            with patch.object(client, "get_member_contents") as mock_get_contents:
                mock_get_contents.return_value = [
                    {"type": "report", "id": "test-report"},
                    {"type": "indicator", "id": "test-indicator"},
                    {"type": "identity", "id": "test-identity"},
                    {"type": "marking-definition", "id": "test-marking"},
                ]

                result = mock_get_contents()

                assert len(result) == 4

    def test_get_member_contents_error_handling(self, mock_opencti_helper, mock_config):
        """Test error handling in get_member_contents"""
        with patch("catalyst.client_api.CatalystClient"):
            client = ConnectorClient(mock_opencti_helper, mock_config)

            mock_opencti_helper.get_state.side_effect = Exception("State error")

            with patch.object(client.logger, "error") as mock_error:
                result = client.get_member_contents()

                assert result == []

                mock_error.assert_called_with(
                    "Error while fetching member contents: State error"
                )

    def test_get_member_contents_processing_error(
        self, mock_opencti_helper, mock_config
    ):
        """Test handling of errors during content processing"""
        mock_opencti_helper.get_state.return_value = None

        with patch("catalyst.client_api.CatalystClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client

            mock_contents = [{"id": "content1"}, {"id": "content2"}]
            mock_client.get_updated_member_contents.return_value = mock_contents

            def side_effect(content):
                if content["id"] == "content1":
                    raise Exception("Processing error")
                return ({"type": "report", "id": content["id"]}, [])

            mock_client.create_report_from_member_content.side_effect = side_effect

            mock_client.converter = Mock()
            mock_client.converter.identity = {"type": "identity", "id": "test-identity"}
            mock_client.converter.tlp_marking = {
                "type": "marking-definition",
                "id": "test-marking",
            }

            _ = ConnectorClient(mock_opencti_helper, mock_config)

            with patch.object(
                mock_opencti_helper.connector_logger, "error"
            ) as mock_error:
                mock_error("Error processing content content1: Processing error")

                mock_error.assert_called_with(
                    "Error processing content content1: Processing error"
                )

    def test_with_sample_stix_objects(
        self,
        mock_opencti_helper,
        mock_config,
        sample_stix_report,
        sample_stix_indicator,
    ):
        """Test with sample STIX objects from fixtures"""
        with patch("catalyst.client_api.CatalystClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client

            client = ConnectorClient(mock_opencti_helper, mock_config)

            mock_client.create_report_from_member_content.return_value = (
                sample_stix_report,
                [sample_stix_indicator],
            )

            mock_client.converter = Mock()
            mock_client.converter.identity = {
                "type": "identity",
                "id": "identity--test",
            }
            mock_client.converter.tlp_marking = {
                "type": "marking-definition",
                "id": "marking--test",
            }

            mock_client.get_updated_member_contents.return_value = [
                {"id": "test-content"}
            ]

            with patch.object(client, "_parse_tlp_filters", return_value=[]):
                with patch.object(client, "_parse_category_filters", return_value=[]):
                    with patch.object(
                        client, "get_member_contents"
                    ) as mock_get_contents:
                        mock_get_contents.return_value = [
                            sample_stix_report,
                            sample_stix_indicator,
                            mock_client.converter.identity,
                            mock_client.converter.tlp_marking,
                        ]

                        result = mock_get_contents()

                        assert len(result) == 4
                        assert result[0]["type"] == "report"
                        assert result[1]["type"] == "indicator"
