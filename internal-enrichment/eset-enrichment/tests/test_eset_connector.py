import contextlib
import json
import urllib.parse
from unittest import mock

import pytest
from src.eset import EsetConnector


def find_call(calls, call_args: tuple):
    for call in calls:
        if call.args == call_args:
            return call


@contextlib.contextmanager
def patch_download(content):
    with mock.patch("requests.get") as mock_get:
        mock_response = mock.MagicMock(content=content, raise_for_status=mock.Mock())
        mock_response.__enter__.return_value = mock_response
        mock_get.return_value = mock_response
        yield mock_get


@pytest.mark.usefixtures("setup_config")
class TestEsetConnector(object):
    connector: EsetConnector

    def test_entity_is_none(self):
        with pytest.raises(TypeError, match="'NoneType' object is not subscriptable"):
            self.connector.process_message(None)

    @pytest.mark.usefixtures("enrichment_data")
    def test_entity_is_out_of_scope(self, enrichment_data):
        self.connector.helper.send_stix2_bundle.reset_mock()
        enrichment_data["entity_id"] = "identity--8133d9f2-79ad-52bf-9541-cde65d175ce0"
        enrichment_data["entity_type"] = "Identity"

        self.connector.process_message(enrichment_data)

        self.connector.helper.send_stix2_bundle.assert_not_called()
        assert (
            find_call(
                self.connector.helper.connector_logger.method_calls,
                (
                    "Skipping the following entity as it does not concern the initial scope found in the config connector: ",
                    {"entity_id": "identity--8133d9f2-79ad-52bf-9541-cde65d175ce0"},
                ),
            )
            is not None
        )

    @pytest.mark.usefixtures("enrichment_data")
    def test_skip_entity_not_created_by_eset(self, enrichment_data):
        self.connector.helper.send_stix2_bundle.reset_mock()
        enrichment_data["enrichment_entity"]["createdBy"]["name"] = "TEST"

        self.connector.process_message(enrichment_data)

        self.connector.helper.send_stix2_bundle.assert_not_called()
        assert (
            find_call(
                self.connector.helper.connector_logger.method_calls,
                (
                    "Skipping entity not created by ESET",
                    {"entity_id": "report--8133d9f2-79ad-52bf-9541-cde65d175ce0"},
                ),
            )
            is not None
        )

    @pytest.mark.usefixtures("enrichment_data")
    def test_skip_connector_has_lower_tlp(self, enrichment_data):
        with mock.patch.object(self.connector, "max_tlp", "TLP:GREEN"):
            with pytest.raises(
                ValueError,
                match="\[CONNECTOR\] Do not send any data, TLP of the observable is greater than MAX TLP,"
                "the connector does not has access to this observable, please check the group of "
                "the connector user",
            ):
                self.connector.process_message(enrichment_data)

    @pytest.mark.usefixtures("enrichment_data")
    def test_skip_entity_with_no_portal_link(self, enrichment_data):
        self.connector.helper.send_stix2_bundle.reset_mock()

        enrichment_data["enrichment_entity"]["objects"] = []
        enrichment_data["enrichment_entity"]["objectsIds"] = []

        self.connector.process_message(enrichment_data)

        self.connector.helper.send_stix2_bundle.assert_not_called()
        assert (
            find_call(
                self.connector.helper.connector_logger.method_calls,
                (
                    "Skipping report without ETI portal link",
                    {"entity_id": "report--8133d9f2-79ad-52bf-9541-cde65d175ce0"},
                ),
            )
            is not None
        )

    @pytest.mark.parametrize("api_host", ["https://eti.eset.com/", "http://test.com"])
    @pytest.mark.usefixtures("enrichment_data")
    @pytest.mark.usefixtures("report_payload")
    def test_enrich_entity(self, api_host, enrichment_data, report_payload):
        self.connector.helper.send_stix2_bundle.reset_mock()

        with mock.patch.object(self.connector, "host", api_host):
            with patch_download(report_payload) as mock_get:
                self.connector.process_message(enrichment_data)

                mock_get.assert_called_once()
                mock_get.assert_called_with(
                    urllib.parse.urljoin(
                        api_host,
                        "api/v2/apt-reports/40121508-c3ad-4430-adc8-a2a406ab61d3/download/pdf",
                    ),
                    headers={"Authorization": "Bearer changeme|changeme"},
                )
                self.connector.helper.send_stix2_bundle.assert_called_once()

                for o in json.loads(
                    self.connector.helper.send_stix2_bundle.call_args.args[0]
                )["objects"]:
                    if o["type"] == "report":
                        assert o["x_opencti_files"] == [
                            {
                                "name": "AS-2024-0005 Report.pdf",
                                "data": "VEhJUyBJUyBNT0NLIFJFUE9SVA==",
                                "mime_type": "application/octet-pdf",
                                "object_marking_refs": "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
                            }
                        ]
                        break
                else:
                    assert False, "Report not found in sent bundle"
                self.connector.helper.send_stix2_bundle.reset_mock()

    @pytest.mark.parametrize("api_host", ["https://eti.eset.com/"])
    @pytest.mark.usefixtures("enrichment_data")
    @pytest.mark.usefixtures("report_payload")
    def test_enrich_entity_with_default_tlp(
        self, api_host, enrichment_data, report_payload
    ):
        self.connector.helper.send_stix2_bundle.reset_mock()

        enrichment_data["enrichment_entity"]["objectMarking"] = [
            {
                "id": "aa707c73-6fe6-487e-9e99-99d30ecd6614",
                "standard_id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                "entity_type": "Marking-Definition",
                "definition_type": "TLP",
                "definition": "TLP:CLEAR",
                "created": "2026-03-12T11:39:41.424Z",
                "modified": "2026-03-12T11:54:57.183Z",
                "x_opencti_order": 1,
                "x_opencti_color": "#ffffff",
                "createdById": None,
            }
        ]

        with mock.patch.object(self.connector, "host", api_host):
            with patch_download(report_payload):
                self.connector.process_message(enrichment_data)

                for o in json.loads(
                    self.connector.helper.send_stix2_bundle.call_args.args[0]
                )["objects"]:
                    if o["type"] == "report":
                        assert o["x_opencti_files"] == [
                            {
                                "name": "AS-2024-0005 Report.pdf",
                                "data": "VEhJUyBJUyBNT0NLIFJFUE9SVA==",
                                "mime_type": "application/octet-pdf",
                                "object_marking_refs": "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
                            }
                        ]
                        break
                else:
                    assert False, "Report not found in sent bundle"
                self.connector.helper.send_stix2_bundle.reset_mock()

    @pytest.mark.parametrize("api_host", ["https://eti.eset.com/"])
    @pytest.mark.usefixtures("enrichment_data")
    @pytest.mark.usefixtures("report_payload")
    def test_enrich_entity_with_default_tlp_and_missing_label_tlp(
        self, api_host, enrichment_data, report_payload
    ):
        self.connector.helper.send_stix2_bundle.reset_mock()

        enrichment_data["enrichment_entity"]["objectMarking"] = [
            {
                "id": "aa707c73-6fe6-487e-9e99-99d30ecd6614",
                "standard_id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                "entity_type": "Marking-Definition",
                "definition_type": "TLP",
                "definition": "TLP:CLEAR",
                "created": "2026-03-12T11:39:41.424Z",
                "modified": "2026-03-12T11:54:57.183Z",
                "x_opencti_order": 1,
                "x_opencti_color": "#ffffff",
                "createdById": None,
            }
        ]
        enrichment_data["enrichment_entity"]["objectLabel"] = [
            {
                "id": "e2528867-8a15-423e-909c-744eb1007c61",
                "value": "activity summary",
                "color": "#95b717",
                "createdById": None,
            },
            {
                "id": "4aa66244-3479-4821-8ed7-38d5aa7b65c5",
                "value": "eset",
                "color": "#dda52f",
                "createdById": None,
            },
        ]

        with mock.patch.object(self.connector, "host", api_host):
            with patch_download(report_payload):
                self.connector.process_message(enrichment_data)

                for o in json.loads(
                    self.connector.helper.send_stix2_bundle.call_args.args[0]
                )["objects"]:
                    if o["type"] == "report":
                        assert o["x_opencti_files"] == [
                            {
                                "name": "AS-2024-0005 Report.pdf",
                                "data": "VEhJUyBJUyBNT0NLIFJFUE9SVA==",
                                "mime_type": "application/octet-pdf",
                                "object_marking_refs": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                            }
                        ]
                        break
                else:
                    assert False, "Report not found in sent bundle"
                self.connector.helper.send_stix2_bundle.reset_mock()

    @pytest.mark.usefixtures("enrichment_data")
    def test_skip_entity_with_report(self, enrichment_data):
        self.connector.helper.send_stix2_bundle.reset_mock()

        enrichment_data["enrichment_entity"]["importFiles"].append(
            {
                "name": "AS-2024-0005 Report.pdf",
                "data": "VEhJUyBJUyBNT0NLIFJFUE9SVA==",
                "mime_type": "application/octet-pdf",
            }
        )

        self.connector.process_message(enrichment_data)

        self.connector.helper.send_stix2_bundle.assert_not_called()
        assert (
            find_call(
                self.connector.helper.connector_logger.method_calls,
                (
                    "Report already has attachment imported",
                    {
                        "entity_id": "report--8133d9f2-79ad-52bf-9541-cde65d175ce0",
                        "name": "AS-2024-0005 Report.pdf",
                    },
                ),
            )
            is not None
        )
