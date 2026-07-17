"""Tests for the Metras Stream converter (file-path extraction / blocklist build)."""

from connector.converter_to_external import ConverterToExternal


def test_extract_file_name_only():
    conv = ConverterToExternal()
    data = {
        "type": "indicator",
        "name": "evil exe",
        "pattern": "[file:name = 'evil.exe']",
    }
    item = conv.build_item(data)
    assert item is not None
    assert item["file_paths"] == ["evil.exe"]
    assert item["name"] == "opencti-evil-exe"
    assert item["action"] == "ALERT"


def test_extract_dir_plus_name():
    conv = ConverterToExternal(platform="windows")
    pattern = "[directory:path = 'C:\\\\Windows' AND file:name = 'evil.exe']"
    paths = conv.extract_file_paths({"pattern": pattern})
    assert paths == ["C:\\Windows\\evil.exe"]


def test_extract_dir_plus_name_posix():
    # POSIX directory must stay POSIX (no back-slash separator).
    conv = ConverterToExternal()
    pattern = "[directory:path = '/usr/bin' AND file:name = 'evil']"
    assert conv.extract_file_paths({"pattern": pattern}) == ["/usr/bin/evil"]


def test_non_file_indicator_is_unconvertible():
    conv = ConverterToExternal()
    data = {
        "type": "indicator",
        "name": "bad ip",
        "pattern": "[ipv4-addr:value = '1.2.3.4']",
    }
    assert conv.build_item(data) is None
    assert conv.extract_file_paths(data) == []


def test_deterministic_name_uses_indicator_name_not_id():
    conv = ConverterToExternal()
    a = conv.blocklist_name({"name": "APT Rule", "id": "indicator--aaa"})
    b = conv.blocklist_name({"name": "APT Rule", "id": "indicator--bbb"})
    assert a == b == "opencti-apt-rule"
