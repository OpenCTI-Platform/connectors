"""Tests for harfanglab models."""

from harfanglab_incidents_connector.models.harfanglab import Process


class TestProcessHashes:
    """Tests for Process hash parsing, including fix for issue #5707."""

    def test_hashes_all_present(self):
        """When all hashes are provided, they should all be in the dict."""
        data = {
            "process_name": "malware.exe",
            "hashes": {
                "sha256": "a" * 64,
                "sha1": "b" * 40,
                "md5": "c" * 32,
            },
        }
        process = Process(data)
        assert process.hashes == {
            "SHA-256": "a" * 64,
            "SHA-1": "b" * 40,
            "MD5": "c" * 32,
        }

    def test_hashes_partial(self):
        """When only some hashes are provided, only those should be in the dict."""
        data = {
            "process_name": "malware.exe",
            "hashes": {
                "sha256": "a" * 64,
                "sha1": None,
                "md5": None,
            },
        }
        process = Process(data)
        assert process.hashes == {"SHA-256": "a" * 64}

    def test_hashes_all_none(self):
        """When all hash values are None, hashes should be None (fix for #5707)."""
        data = {
            "process_name": "malware.exe",
            "hashes": {
                "sha256": None,
                "sha1": None,
                "md5": None,
            },
        }
        process = Process(data)
        assert process.hashes is None

    def test_hashes_empty_dict(self):
        """When hashes dict is empty, hashes should be None."""
        data = {
            "process_name": "malware.exe",
            "hashes": {},
        }
        process = Process(data)
        assert process.hashes is None

    def test_hashes_missing_key(self):
        """When 'hashes' key is missing from data, hashes should be None."""
        data = {
            "process_name": "malware.exe",
        }
        process = Process(data)
        assert process.hashes is None

    def test_hashes_none_value(self):
        """When 'hashes' is explicitly None in data, hashes should be None."""
        data = {
            "process_name": "malware.exe",
            "hashes": None,
        }
        process = Process(data)
        assert process.hashes is None

    def test_hashes_empty_strings_filtered(self):
        """Empty string hash values should be filtered out."""
        data = {
            "process_name": "malware.exe",
            "hashes": {
                "sha256": "",
                "sha1": "",
                "md5": "c" * 32,
            },
        }
        process = Process(data)
        assert process.hashes == {"MD5": "c" * 32}

    def test_process_name(self):
        """Process name should be correctly parsed."""
        data = {
            "process_name": "explorer.exe",
            "hashes": {"sha256": "a" * 64},
        }
        process = Process(data)
        assert process.name == "explorer.exe"

    def test_process_name_missing(self):
        """Missing process name should result in None."""
        data = {"hashes": {}}
        process = Process(data)
        assert process.name is None
