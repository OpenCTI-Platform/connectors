import unittest
from shadowserver.utils import validate_date_format, validate_marking_refs

class TestValidateDateFormat(unittest.TestCase):
    def test_valid_date_format(self):
        # Test valid date format
        self.assertTrue(validate_date_format("2022-01-01"))
        self.assertTrue(validate_date_format("2022-12-31"))
    
    def test_invalid_date_format(self):
        # Test invalid date format
        self.assertFalse(validate_date_format("2022-111-1"))
        self.assertFalse(validate_date_format("2022-13-01"))
        self.assertFalse(validate_date_format("2022-02-29"))
        self.assertFalse(validate_date_format("20220101"))
    
    def test_valid_marking_refs(self):
        # Test valid marking references
        self.assertTrue(validate_marking_refs("TLP:WHITE"))
        self.assertTrue(validate_marking_refs("TLP:GREEN"))
        self.assertTrue(validate_marking_refs("TLP:AMBER"))
        self.assertTrue(validate_marking_refs("TLP:RED"))

    def test_invalid_marking_refs(self):
        # Test invalid marking references
        self.assertFalse(validate_marking_refs("invalid_marking_refs"))
        self.assertFalse(validate_marking_refs("TLP:INVALID"))
        self.assertFalse(validate_marking_refs("TLP:INVALID:INVALID"))
        self.assertFalse(validate_marking_refs("TLP:INVALID:INVALID:INVALID"))

if __name__ == '__main__':
    unittest.main()