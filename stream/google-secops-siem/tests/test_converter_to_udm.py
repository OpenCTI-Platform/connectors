import pytest

from .common_fixtures import (  # noqa: F401 pylint:disable=unused-import
    event_data_samples,
    setup_config,
)


@pytest.mark.usefixtures("setup_config", "event_data_samples")
class TestCTIConverterChronicle(object):

    fake_opencti_ioc_id = "52dfd627-a875-4c05-bb21-12302ed66220"
    fake_opencti_ioc_no_id = None

    def test_correct_udm_entity_generation_for_file_md5(self) -> None:
        """
        Check if UDM entity is generated correctly for md5
        :return:
        """
        # Arrange
        entity = self.CTIConverter.generate_entity_details(
            self.fake_observable_values["md5_sample"], self.fake_metadata
        )

        entity_expected_result = {"file": {"md5": "946d53360ef6e553b90d826a018bc546"}}

        assert entity == entity_expected_result

    def test_correct_udm_entity_generation_for_file_sha1(self) -> None:
        """
        Check if UDM entity is generated correctly for sha1
        :return:
        """
        # Arrange
        entity = self.CTIConverter.generate_entity_details(
            self.fake_observable_values["sha1_sample"], self.fake_metadata
        )

        entity_expected_result = {
            "file": {"sha1": "ef1faa3a55cca05d84187c8cd15ceed9066c0f19"}
        }

        assert entity == entity_expected_result

    def test_correct_udm_entity_generation_for_file_sha256(self) -> None:
        """
        Check if UDM entity is generated correctly for 256
        :return:
        """
        # Arrange
        entity = self.CTIConverter.generate_entity_details(
            self.fake_observable_values["sha256_sample"], self.fake_metadata
        )

        entity_expected_result = {
            "file": {
                "sha256": "e67538748476070016be140e73625dcb4f9b953f5c1806ac8e08a49b45e7d1cd"
            }
        }

        assert entity == entity_expected_result

    def test_correct_udm_entity_generation_for_domain(self) -> None:
        """
        Check if UDM entity is generated correctly for domain
        :return:
        """
        # Arrange
        entity = self.CTIConverter.generate_entity_details(
            self.fake_observable_values["domain_sample"], self.fake_metadata
        )

        entity_expected_result = {"hostname": "thesecure.biz"}

        assert entity == entity_expected_result

    def test_correct_udm_entity_generation_for_ipv4(self) -> None:
        """
        Check if UDM entity is generated correctly for ipv4
        :return:
        """
        # Arrange
        entity = self.CTIConverter.generate_entity_details(
            self.fake_observable_values["ipv4_sample"], self.fake_metadata
        )

        entity_expected_result = {"ip": "23.95.75.114"}

        assert entity == entity_expected_result

    def test_correct_udm_entity_generation_for_url(self) -> None:
        """
        Check if UDM entity is generated correctly for url
        :return:
        """
        # Arrange
        entity = self.CTIConverter.generate_entity_details(
            self.fake_observable_values["url_sample"], self.fake_metadata
        )

        entity_expected_result = {"url": "https://rechnung-senden.net/download/"}

        assert entity == entity_expected_result

    def test_correct_udm_entity_generation_for_ipv6(self) -> None:
        """
        Check if UDM entity is generated correctly for ipv6
        :return:
        """
        # Arrange
        entity = self.CTIConverter.generate_entity_details(
            self.fake_observable_values["ipv6_sample"], self.fake_metadata
        )

        entity_expected_result = {"ip": "2604:a880:400:d1::3c0:f001"}

        assert entity == entity_expected_result

    def test_correct_udm_entity_generation_for_hostname(self) -> None:
        """
        Check if UDM entity is generated correctly for hostname
        :return:
        """
        # Arrange
        entity = self.CTIConverter.generate_entity_details(
            self.fake_observable_values["hostname_sample"], self.fake_metadata
        )

        entity_expected_result = {"hostname": "ebay.ebayshoo.com"}

        assert entity == entity_expected_result

    def test_correct_metadata_generation(self) -> None:
        """
        Check if metadata for UDM entity is generated correctly
        :return: None
        """
        # Arrange

        # Mock get_attribute_in_extension method to return a specific value for score
        self.mock_helper.get_attribute_in_extension.side_effect = [
            35,
            self.fake_opencti_ioc_id,
        ]

        # Mock helper method to return a specific value for opencti_url
        self.mock_helper.opencti_url = "http://localhost:8080"

        metadata = self.CTIConverter.generate_entity_metadata(self.fake_ioc_data)
        metadata["collected_timestamp"] = "2024-12-17T14:35:42.009890Z"

        expected_metadata_result = {
            "vendor_name": "FILIGRAN",
            "product_name": "OPENCTI",
            "collected_timestamp": "2024-12-17T14:35:42.009890Z",
            "product_entity_id": "indicator--f2a0f638-a65b-5283-9c34-4e6140f51e15",
            "description": "Fake description",
            "interval": {
                "start_time": "2024-12-10T09:19:46.528Z",
                "end_time": "2025-07-13T09:14:20.754Z",
            },
            "threat": {
                "confidence_details": "100",
                "confidence_score": 100,
                "risk_score": 35,
                "category_details": ["chronicle"],
                "url_back_to_product": "http://localhost:8080/dashboard/observations/indicators/52dfd627-a875-4c05-bb21-12302ed66220",
            },
        }

        # Assert
        assert metadata == expected_metadata_result

    def test_correct_metadata_generation_missing_opencti_url(self) -> None:
        """
        Check if metadata for UDM entity is generated correctly
        :return: None
        """
        # Arrange

        # Mock get_attribute_in_extension method to return a specific value for score
        self.mock_helper.get_attribute_in_extension.side_effect = [
            35,
            self.fake_opencti_ioc_no_id,
        ]

        # Mock helper method to return a specific value for opencti_url
        self.mock_helper.opencti_url = "http://localhost:8080"

        metadata = self.CTIConverter.generate_entity_metadata(self.fake_ioc_data_no_id)
        metadata["collected_timestamp"] = "2024-12-17T14:35:42.009890Z"

        expected_metadata_result = {
            "vendor_name": "FILIGRAN",
            "product_name": "OPENCTI",
            "collected_timestamp": "2024-12-17T14:35:42.009890Z",
            "product_entity_id": "indicator--f2a0f638-a65b-5283-9c34-4e6140f51e15",
            "description": "Fake description",
            "interval": {
                "start_time": "2024-12-10T09:19:46.528Z",
                "end_time": "2025-07-13T09:14:20.754Z",
            },
            "threat": {
                "confidence_details": "100",
                "confidence_score": 100,
                "risk_score": 35,
                "category_details": ["chronicle"],
                "url_back_to_product": None,
            },
        }

        # Assert
        assert metadata == expected_metadata_result
