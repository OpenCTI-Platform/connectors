import unittest
from datetime import datetime

from shadowserver.utils import (
    check_ip_address,
    clean_dict,
    clean_list_of_dicts,
    datetime_to_string,
    dicts_to_markdown,
    find_stix_object_by_id,
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
        expected_keys = "| Key   | Value  |"
        actual_output = dicts_to_markdown(data)
        self.assertTrue(actual_output.startswith(expected_keys[0]))
        self.assertTrue(isinstance(actual_output, str))

    def test_dicts_to_markdown_list_of_dicts(self):
        data = [{"key1": "value1"}, {"key2": "value2"}]
        expected_keys = "| Key   | Value  |"
        actual_output = dicts_to_markdown(data)
        self.assertTrue(actual_output.startswith(expected_keys[0]))
        self.assertTrue(isinstance(actual_output, str))


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


if __name__ == "__main__":
    unittest.main()
