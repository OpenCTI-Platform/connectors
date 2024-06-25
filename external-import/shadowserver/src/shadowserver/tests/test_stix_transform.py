import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from pycti import CustomObjectCaseIncident, OpenCTIConnectorHelper
from shadowserver.stix_transform import ShadowserverStixTransformation
from shadowserver.utils import datetime_to_string
from stix2 import (
    Artifact,
    DomainName,
    Identity,
    IPv4Address,
    IPv6Address,
    MACAddress,
    MarkingDefinition,
)


class TestShadowserverStixTransformation(unittest.TestCase):
    def setUp(self):
        self.api_helper = MagicMock(spec=OpenCTIConnectorHelper)
        self.api_helper.log_debug = MagicMock()
        self.api_helper.log_info = MagicMock()
        self.api_helper.log_error = MagicMock()

        self.marking_refs = MarkingDefinition(
            type="marking-definition",
            spec_version="2.1",
            id="marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            created=datetime(2017, 1, 20, 0, 0, 0, 0),
            definition_type="tlp",
            name="TLP:WHITE",
            definition={"tlp": "white"},
        )
        self.report_list = [{"timestamp": "2022-01-01 00:00:00Z", "key": "value"}]
        self.report = {
            "type": "scan",
            "id": "test_report_id",
            "url": "http://example.com/report",
        }
        self.labels = ["Shadowserver"]

        self.transformation = ShadowserverStixTransformation(
            marking_refs=self.marking_refs,
            report_list=self.report_list,
            report=self.report,
            api_helper=self.api_helper,
            labels=self.labels,
            incident={
                "create": True,
                "severity": "medium",
                "priority": "P4",
            },
        )

    def test_create_author(self):
        self.transformation.create_author()
        self.assertTrue(
            any(isinstance(obj, Identity) for obj in self.transformation.stix_objects)
        )

    def test_create_external_reference(self):
        self.transformation.create_external_reference()
        self.assertIsNotNone(self.transformation.external_reference)
        self.assertEqual(
            self.transformation.external_reference["url"], self.report["url"]
        )

    def test_create_custom_properties(self):
        self.transformation.create_custom_properties()
        self.assertIn("external_references", self.transformation.custom_properties)
        self.assertIn("created_by_ref", self.transformation.custom_properties)
        self.assertIn("x_opencti_labels", self.transformation.custom_properties)

    def test_get_published_date(self):
        expected_date = datetime_to_string(
            datetime.strptime("2022-01-01T00:00:00Z", "%Y-%m-%dT%H:%M:%SZ")
        )
        self.assertEqual(
            self.transformation.get_published_date(self.report_list), expected_date
        )

    def test_upload_stix2_artifact(self):
        with patch(
            "shadowserver.stix_transform.magic.from_buffer", return_value="text/csv"
        ):
            self.transformation.upload_stix2_artifact(self.report_list)
            self.assertTrue(
                any(
                    isinstance(obj, Artifact)
                    for obj in self.transformation.stix_objects
                )
            )

    def test_create_observed_data(self):
        observables_list = ["ipv4-addr--1"]
        labels_list = ["test"]
        self.transformation.create_observed_data(observables_list, labels_list)
        self.assertTrue(
            obj.startswith("observed-data--")
            for obj in self.transformation.stix_objects
        )

    def test_create_stix_note_from_data(self):
        self.transformation.create_stix_note_from_data()
        self.assertTrue(
            obj.startswith("note--") for obj in self.transformation.stix_objects
        )

    def test_create_ip(self):
        ipv4 = self.transformation.create_ip("192.168.0.1")
        ipv6 = self.transformation.create_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        self.assertIsInstance(ipv4, IPv4Address)
        self.assertIsInstance(ipv6, IPv6Address)

    def test_create_hostname(self):
        hostname = self.transformation.create_hostname("example.com")
        self.assertIsInstance(hostname, DomainName)

    def test_create_mac_address(self):
        mac_address = self.transformation.create_mac_address("00:0a:95:9d:68:16")
        self.assertIsInstance(mac_address, MACAddress)

    def test_create_network_traffic(self):
        with patch(
            "shadowserver.utils.find_stix_object_by_id", return_value="192.168.0.1"
        ):
            network_traffic = self.transformation.create_network_traffic(
                dst_port=80,
                protocol="tcp",
                dst_ref="ipv4-addr--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            )
            self.assertTrue(isinstance(network_traffic, str))
            self.assertTrue(network_traffic.startswith("network-traffic--"))

    def test_create_x509_certificate(self):
        data = {
            "sha1_fingerprint": "D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2",
            "sha256_fingerprint": "E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3",
            "sha512_fingerprint": "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387",
            "md5_fingerprint": "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1",
            "cert_issue_date": "2022-01-01 00:00:00",
            "cert_expiration_date": "2023-01-01 00:00:00",
            "serial_number": "123456789",
            "signature_algorithm": "SHA256",
            "issuer": "Issuer",
            "subject": "Subject",
        }
        certificate = self.transformation.create_x509_certificate(data)
        self.assertTrue(isinstance(certificate, str))
        self.assertTrue(certificate.startswith("x509-certificate--"))

    def test_create_opencti_case(self):
        self.transformation.create_opencti_case()
        self.assertTrue(
            any(
                isinstance(obj, CustomObjectCaseIncident)
                for obj in self.transformation.stix_objects
            )
        )


if __name__ == "__main__":
    unittest.main()
