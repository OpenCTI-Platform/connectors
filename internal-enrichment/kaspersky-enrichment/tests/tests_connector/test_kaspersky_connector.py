from unittest import mock

import pytest
from connectors_sdk.models.enums import TLPLevel


@pytest.mark.usefixtures("setup_config")
class TestKasperskyConnector(object):

    def test_entity_is_none(self):
        with pytest.raises(
            Exception,
            match=r"\[Kaspersky Enrichment\] Unexpected Error occurred: 'NoneType' object is not subscriptable",
        ):
            self.connector.process_message(None)

    @pytest.mark.usefixtures("fixture_data")
    def test_entity_is_out_of_scope(self, fixture_data):
        self.connector.helper.send_stix2_bundle.reset_mock()
        fixture_data["enrichment_entity"][
            "entity_id"
        ] = "identity--ae798684-7b0a-4229-928b-4b9480e782d0"
        fixture_data["enrichment_entity"]["entity_type"] = "Identity"

        with mock.patch.object(self.mock_helper, "connect_scope", "Hostname"):
            with pytest.raises(
                Exception,
                match=r"\[Kaspersky Enrichment\] Unexpected Error occurred: Failed to process observable, Identity is not a supported entity type.",
            ):
                self.connector.process_message(fixture_data)
                self.connector.helper.send_stix2_bundle.assert_not_called()

    @pytest.mark.usefixtures("fixture_data")
    def test_skip_entity_with_lower_tlp(self, fixture_data):
        with mock.patch.object(self.mock_config.connector, "max_tlp", TLPLevel.GREEN):
            assert (
                self.connector.process_message(fixture_data)
                == """Do not send any data, TLP of the entity is (TLP:RED), which
                  is greater than MAX TLP: (green)"""
            )

    @pytest.mark.usefixtures("fixture_data")
    def test_skip_entity_with_one_tlp_above_max_tlp(self, fixture_data):
        # Every TLP of the entity is checked, not only the last one
        fixture_data["enrichment_entity"]["objectMarking"] = [
            {"definition_type": "TLP", "definition": "TLP:RED"},
            {"definition_type": "TLP", "definition": "TLP:GREEN"},
        ]
        with mock.patch.object(self.mock_config.connector, "max_tlp", TLPLevel.AMBER):
            result = self.connector.process_message(fixture_data)

        assert result.startswith("Do not send any data")
