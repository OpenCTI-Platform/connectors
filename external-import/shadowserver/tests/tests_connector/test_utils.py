import unittest
from datetime import datetime

from shadowserver.utils import (
    check_ip_address,
    clean_dict,
    clean_list_of_dicts,
    datetime_to_string,
    dicts_to_markdown,
    find_stix_object_by_id,
    from_csv_to_list,
    from_list_to_csv,
    get_stix_id_precedence,
    note_timestamp_to_datetime,
    string_to_datetime,
    validate_date_format,
    validate_marking_refs,
)
from stix2 import DomainName, IPv4Address


class TestValidateDateFormat(unittest.TestCase):
    def test_valid_date_format(self):
        self.assertTrue(validate_date_format("2022-01-01"))
        self.assertTrue(validate_date_format("2022-12-31"))

    def test_invalid_date_format(self):
        self.assertFalse(validate_date_format("2022-111-1"))
        self.assertFalse(validate_date_format("2022-13-01"))
        self.assertFalse(validate_date_format("2022-02-29"))
        self.assertFalse(validate_date_format("20220101"))


class TestValidateMarkingRefs(unittest.TestCase):
    def test_valid_marking_refs(self):
        self.assertTrue(validate_marking_refs("TLP:WHITE"))
        self.assertTrue(validate_marking_refs("TLP:GREEN"))
        self.assertTrue(validate_marking_refs("TLP:AMBER"))
        self.assertTrue(validate_marking_refs("TLP:RED"))

    def test_invalid_marking_refs(self):
        with self.assertRaises(ValueError):
            validate_marking_refs("invalid_marking_refs")
        with self.assertRaises(ValueError):
            validate_marking_refs("TLP:INVALID")
        with self.assertRaises(ValueError):
            validate_marking_refs("TLP:INVALID:INVALID")
        with self.assertRaises(ValueError):
            validate_marking_refs("TLP:INVALID:INVALID:INVALID")


class TestDatetimeConversions(unittest.TestCase):
    def test_datetime_to_string(self):
        dt = datetime(2022, 1, 1, 12, 30, 45, 123456)
        self.assertEqual(datetime_to_string(dt), "2022-01-01T12:30:45.123Z")

    def test_string_to_datetime(self):
        date_string = "2022-01-01"
        self.assertEqual(string_to_datetime(date_string), datetime(2022, 1, 1))
        self.assertIsNone(string_to_datetime("2022-13-01"))

    def test_note_timestamp_to_datetime(self):
        date_string = "2022-01-01 12:30:45Z"
        self.assertEqual(
            note_timestamp_to_datetime(date_string), datetime(2022, 1, 1, 12, 30, 45)
        )


class TestDictsToMarkdown(unittest.TestCase):
    def test_dicts_to_markdown_single_dict(self):
        data = {"key1": "value1", "key2": "value2"}
        expected = (
            "| Key   | Value   |\n"
            "|:------|:--------|\n"
            "| key1  | value1  |\n"
            "| key2  | value2  |\n"
            "\n"
        )
        self.assertEqual(dicts_to_markdown(data), expected)

    def test_dicts_to_markdown_list_of_dicts(self):
        data = [{"key1": "value1"}, {"key2": "value2"}]
        expected = (
            "| Key   | Value   |\n"
            "|:------|:--------|\n"
            "| key1  | value1  |\n"
            "\n"
            "| Key   | Value   |\n"
            "|:------|:--------|\n"
            "| key2  | value2  |\n"
            "\n"
        )
        self.assertEqual(dicts_to_markdown(data), expected)

    def test_dicts_to_markdown_filters_empty_values(self):
        data = {"ip": "1.2.3.4", "hostname": "", "sector": None, "geo": "US"}
        expected = (
            "| Key   | Value   |\n"
            "|:------|:--------|\n"
            "| ip    | 1.2.3.4 |\n"
            "| geo   | US      |\n\n"
        )
        self.assertEqual(dicts_to_markdown(data), expected)

    def test_dicts_to_markdown_all_empty_dict_skipped(self):
        data = [{"a": None, "b": ""}, {"key": "value"}]
        expected = (
            "| Key   | Value   |\n"
            "|-------|---------|\n"
            "\n"
            "| Key   | Value   |\n"
            "|:------|:--------|\n"
            "| key   | value   |\n\n"
        )
        self.assertEqual(dicts_to_markdown(data), expected)

    def test_dicts_to_markdown_empty_list(self):
        self.assertEqual(dicts_to_markdown([]), "")


class TestCheckIPAddress(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertEqual(check_ip_address("192.168.0.1"), "IPv4 address")

    def test_valid_ipv6(self):
        self.assertEqual(
            check_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), "IPv6 address"
        )

    def test_invalid_ip(self):
        self.assertEqual(check_ip_address("999.999.999.999"), "Invalid IP/CIDR")


class TestCleanDict(unittest.TestCase):
    def test_clean_dict(self):
        data = {"key1": "value1", "key2": None, "key3": ""}
        expected_output = {"key1": "value1"}
        self.assertEqual(clean_dict(data), expected_output)


class TestCleanListOfDicts(unittest.TestCase):
    def test_clean_list_of_dicts(self):
        data = [{"key1": "value1", "key2": None}, {"key3": "", "key4": "value4"}]
        expected_output = [{"key1": "value1"}, {"key4": "value4"}]
        self.assertEqual(clean_list_of_dicts(data), expected_output)


class TestFromListToCSV(unittest.TestCase):
    def test_from_list_to_csv(self):
        data = [
            {"key1": "value1", "key2": "value2"},
            {"key1": "value3", "key2": "value4"},
        ]
        expected_output = "key1,key2\nvalue1,value2\nvalue3,value4\n"
        self.assertEqual(from_list_to_csv(data), expected_output)

    def test_from_list_to_csv_cleans_none_and_empty(self):
        data = [
            {"ip": "1.2.3.4", "hostname": None, "geo": "US"},
            {"ip": "5.6.7.8", "hostname": "", "geo": "DE"},
        ]
        expected_output = "ip,geo\n1.2.3.4,US\n5.6.7.8,DE\n"
        self.assertEqual(from_list_to_csv(data), expected_output)

    def test_from_list_to_csv_empty_list(self):
        output = from_list_to_csv([])
        # Empty input produces no data rows
        self.assertFalse(output.strip())

    def test_from_list_to_csv_superset_keys(self):
        """Rows with different keys produce a CSV with the union of all keys."""
        data = [
            {"ip": "1.2.3.4", "geo": "US"},
            {"ip": "5.6.7.8", "port": "80"},
        ]
        output = from_list_to_csv(data)
        lines = output.strip().split("\n")
        self.assertEqual(lines[0], "ip,geo,port")
        self.assertEqual(lines[1], "1.2.3.4,US,")
        self.assertEqual(lines[2], "5.6.7.8,,80")


class TestGetStixIDPrecedence(unittest.TestCase):
    def test_get_stix_id_precedence(self):
        stix_ids = ["ipv4-addr--1", "domain-name--2", "ipv6-addr--3"]
        self.assertEqual(get_stix_id_precedence(stix_ids), "ipv4-addr--1")


class TestFindStixObjectByID(unittest.TestCase):
    def test_find_stix_object_by_id(self):
        stix_objects = [
            IPv4Address(
                value="192.168.0.1",
                id="ipv4-addr--00000000-0000-4000-8000-000000000000",
            ),
            DomainName(
                value="example.com",
                id="domain-name--00000000-0000-4000-8000-000000000000",
            ),
        ]
        self.assertEqual(
            find_stix_object_by_id(
                stix_objects, "domain-name--00000000-0000-4000-8000-000000000000"
            ),
            "example.com",
        )
        self.assertIsNone(find_stix_object_by_id(stix_objects, "non-existent-id"))


class TestFromCSVToList(unittest.TestCase):
    def test_from_csv_to_list_basic(self):
        csv_bytes = (
            b'"timestamp","severity","ip","protocol","port","hostname"\n'
            b'"2026-02-06 15:21:24","info","173.224.16.226","udp",500,"host.example.net"\n'
            b'"2026-02-06 17:29:26","info","91.249.143.206","udp",500,"other.example.de"\n'
        )
        expected = [
            {
                "timestamp": "2026-02-06 15:21:24",
                "severity": "info",
                "ip": "173.224.16.226",
                "protocol": "udp",
                "port": 500,
                "hostname": "host.example.net",
            },
            {
                "timestamp": "2026-02-06 17:29:26",
                "severity": "info",
                "ip": "91.249.143.206",
                "protocol": "udp",
                "port": 500,
                "hostname": "other.example.de",
            },
        ]
        self.assertEqual(from_csv_to_list(csv_bytes), expected)

    def test_from_csv_to_list_empty_fields_become_none(self):
        csv_bytes = (
            b'"timestamp","severity","ip","hostname","sector"\n'
            b'"2026-02-06 17:35:36","info","12.147.142.252",,\n'
        )
        expected = [
            {
                "timestamp": "2026-02-06 17:35:36",
                "severity": "info",
                "ip": "12.147.142.252",
                "hostname": None,
                "sector": None,
            }
        ]
        self.assertEqual(from_csv_to_list(csv_bytes), expected)

    def test_from_csv_to_list_empty_csv(self):
        csv_bytes = b'"key1","key2"\n'
        result = from_csv_to_list(csv_bytes)
        self.assertEqual(result, [])

    def test_from_csv_to_list_shadowserver_report_structure(self):
        """Test with a structure matching a real Shadowserver report (isakmp)."""
        csv_bytes = (
            b'"timestamp","severity","ip","protocol","port","hostname","tag","asn","geo","region","city","naics","hostname_source","sector"\n'
            b'"2026-02-06 15:21:24","info","173.224.16.226","udp",500,"173-224-16-226.ptcnet.net","isakmp",46328,"US","NEBRASKA","PIERCE",,"ptr",\n'
            b'"2026-02-06 17:29:26","info","91.249.143.206","udp",500,"example.de","isakmp",9145,"DE","NIEDERSACHSEN","HASBERGEN",517111,"ptr","Utilities"\n'
        )
        expected = [
            {
                "timestamp": "2026-02-06 15:21:24",
                "severity": "info",
                "ip": "173.224.16.226",
                "protocol": "udp",
                "port": 500,
                "hostname": "173-224-16-226.ptcnet.net",
                "tag": "isakmp",
                "asn": 46328,
                "geo": "US",
                "region": "NEBRASKA",
                "city": "PIERCE",
                "naics": None,
                "hostname_source": "ptr",
                "sector": None,
            },
            {
                "timestamp": "2026-02-06 17:29:26",
                "severity": "info",
                "ip": "91.249.143.206",
                "protocol": "udp",
                "port": 500,
                "hostname": "example.de",
                "tag": "isakmp",
                "asn": 9145,
                "geo": "DE",
                "region": "NIEDERSACHSEN",
                "city": "HASBERGEN",
                "naics": 517111,
                "hostname_source": "ptr",
                "sector": "Utilities",
            },
        ]
        self.assertEqual(from_csv_to_list(csv_bytes), expected)


if __name__ == "__main__":
    unittest.main()
