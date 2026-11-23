"""Tests for reading CrowdStrike rule set downloads in any format (issue #6418)."""

import gzip
import io
import logging
import struct
import tarfile
import zipfile
from unittest.mock import MagicMock

import pytest
from crowdstrike_feeds_connector.connector import CrowdStrike
from crowdstrike_feeds_connector.rule.snort_suricata_master_importer import (
    SnortMasterImporter,
)
from crowdstrike_feeds_connector.rule.yara_master_importer import YaraMasterImporter
from crowdstrike_feeds_services.utils import CrowdStrikeAPIError
from crowdstrike_feeds_services.utils.rule_file import (
    RuleFileFormatError,
    extract_rule_file,
)

YARA_FILE_NAME = "crowdstrike_intel_yara.yara"
SNORT_FILE_NAME = "crowdstrike_intel_snort.rules"

YARA_RULE_TEMPLATE = """rule CrowdStrike_CSIT_0000{n}_01 : example
{{
    meta:
        copyright = "(c) Example"
        description = "Synthetic rule used by the tests"
        last_modified = "2026-01-02"
        reports = "CSIT-0000{n}"
        actor = "N/A"
        malware_family = "ExampleFamily"
    strings:
        $a = "synthetic{n}"
    condition:
        $a
}}
"""

YARA_RULES = YARA_RULE_TEMPLATE.format(n=1)
YARA_THREE_RULES = "".join(YARA_RULE_TEMPLATE.format(n=n) for n in (1, 2, 3))

SNORT_RULE = (
    "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS "
    '(msg: "Malware CrowdStrike MALWARE_NAME Outbound [CSIT-00001]"; '
    'content:"evil"; rev:20250528; sid:1000001;)\n'
)

UTF8_BOM = b"\xef\xbb\xbf"

# Bodies that are not a rule file: each must fail the work.
NOT_RULE_FILES = {
    "empty": b"",
    "proxy-html": (
        b"<!DOCTYPE html><html><body><h1>502 Bad Gateway</h1>"
        b"<p>Access policy blocked by the corporate proxy</p></body></html>"
    ),
    "json-error": (
        b'{"errors": [{"code": 500, "message": "internal error"}], "resources": []}'
    ),
    "empty-zip": b"PK\x05\x06" + b"\x00" * 18,
}


def _zip(members: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in members.items():
            archive.writestr(name, text)
    return buffer.getvalue()


def _deflate64_zip(file_name: str, text: str) -> bytes:
    """Stored ZIP whose headers claim deflate64 (method 9), unsupported by zipfile."""
    content = bytearray(_zip({file_name: text}))
    deflate64 = struct.pack("<H", 9)
    content[8:10] = deflate64  # local file header
    central_directory = content.rindex(b"PK\x01\x02")
    content[central_directory + 10 : central_directory + 12] = deflate64
    return bytes(content)


def _corrupt_lzma_zip(file_name: str, text: str) -> bytes:
    """LZMA ZIP whose member has invalid LZMA properties (zipfile raises LZMAError)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_LZMA) as archive:
        archive.writestr(file_name, text)
    content = bytearray(buffer.getvalue())
    # The member data starts after the 30-byte local header and the name; its
    # first 4 bytes are the LZMA version and properties size, then the properties.
    properties = 30 + len(file_name) + 4
    content[properties : properties + 5] = b"\xff" * 5
    return bytes(content)


def _tar_gz(members: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, text in members.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class TestExtractRuleFile:
    """Each format the API can send gives back the rule file text."""

    def test_zip(self):
        content = _zip({YARA_FILE_NAME: YARA_RULES})
        assert extract_rule_file(content, YARA_FILE_NAME) == YARA_RULES

    def test_zip_with_other_member_name_logs_a_warning(self, caplog):
        content = _zip({"README.txt": "readme", "yara-master.yara": YARA_RULES})

        with caplog.at_level(logging.WARNING):
            assert extract_rule_file(content, YARA_FILE_NAME) == YARA_RULES

        assert "reading yara-master.yara instead" in caplog.text

    def test_zip_in_a_folder(self):
        content = _zip({f"rules/{YARA_FILE_NAME}": YARA_RULES})
        assert extract_rule_file(content, YARA_FILE_NAME) == YARA_RULES

    def test_gzip(self):
        content = gzip.compress(YARA_RULES.encode("utf-8"))
        assert extract_rule_file(content, YARA_FILE_NAME) == YARA_RULES

    def test_tar_gz(self):
        content = _tar_gz({YARA_FILE_NAME: YARA_RULES})
        assert extract_rule_file(content, YARA_FILE_NAME) == YARA_RULES

    def test_plain_text(self):
        content = YARA_RULES.encode("utf-8")
        assert extract_rule_file(content, YARA_FILE_NAME) == YARA_RULES

    def test_gzip_of_zero_blocks_is_read_as_text(self):
        content = gzip.compress(b"\x00" * 1024)
        assert extract_rule_file(content, YARA_FILE_NAME) == "\x00" * 1024

    def test_zip_without_matching_member(self):
        content = _zip({"a.yara": YARA_RULES, "b.yara": YARA_RULES})
        with pytest.raises(RuleFileFormatError, match="not found in the archive"):
            extract_rule_file(content, YARA_FILE_NAME)

    def test_excluded_member_is_not_a_fallback(self):
        content = _zip({"crowdstrike_intel_suricata.rules": SNORT_RULE})
        with pytest.raises(RuleFileFormatError, match="not found in the archive"):
            extract_rule_file(content, SNORT_FILE_NAME, excluded=("suricata",))

    def test_truncated_zip(self):
        content = _zip({YARA_FILE_NAME: YARA_RULES})[:20]
        with pytest.raises(RuleFileFormatError):
            extract_rule_file(content, YARA_FILE_NAME)

    def test_truncated_gzip(self):
        content = gzip.compress(YARA_RULES.encode("utf-8"))[:15]
        with pytest.raises(RuleFileFormatError):
            extract_rule_file(content, YARA_FILE_NAME)

    def test_deflate64_zip(self):
        content = _deflate64_zip(YARA_FILE_NAME, YARA_RULES)
        with pytest.raises(RuleFileFormatError, match="compression method"):
            extract_rule_file(content, YARA_FILE_NAME)

    def test_zip_with_corrupt_lzma_member(self):
        content = _corrupt_lzma_zip(YARA_FILE_NAME, YARA_RULES)

        with pytest.raises(RuleFileFormatError, match="Cannot read"):
            extract_rule_file(content, YARA_FILE_NAME)

    def test_binary_garbage(self):
        with pytest.raises(RuleFileFormatError, match="starts with"):
            extract_rule_file(b"\xff\xfe\x00\x81binary", YARA_FILE_NAME)

    def test_error_is_a_crowdstrike_api_error(self):
        assert issubclass(RuleFileFormatError, CrowdStrikeAPIError)


def _importer(cls, download):
    importer = cls.__new__(cls)
    importer.helper = MagicMock()
    importer.rules_api_cs = MagicMock()
    importer.rules_api_cs.get_latest_rule_file.return_value = download
    return importer


class TestYaraMasterImporterDownload:
    """The YARA importer reads any format and fails on anything else."""

    @pytest.mark.parametrize(
        "download",
        [
            _zip({YARA_FILE_NAME: YARA_RULES}),
            gzip.compress(YARA_RULES.encode("utf-8")),
            YARA_RULES.encode("utf-8"),
        ],
        ids=["zip", "gzip", "plain"],
    )
    def test_rules_are_parsed(self, download):
        yara_master = _importer(YaraMasterImporter, download)._fetch_yara_master()

        assert yara_master is not None
        assert [rule.name for rule in yara_master.rules] == [
            "CrowdStrike_CSIT_00001_01"
        ]

    @pytest.mark.parametrize(
        "download",
        [
            gzip.compress(UTF8_BOM + YARA_THREE_RULES.encode("utf-8")),
            UTF8_BOM + YARA_THREE_RULES.encode("utf-8"),
        ],
        ids=["gzip", "plain"],
    )
    def test_bom_keeps_every_rule(self, download):
        yara_master = _importer(YaraMasterImporter, download)._fetch_yara_master()

        assert yara_master is not None
        assert len(yara_master.rules) == 3

    def test_unreadable_download_raises(self):
        importer = _importer(YaraMasterImporter, b"\xff\xfe\x00\x81binary")

        with pytest.raises(RuleFileFormatError, match="starts with"):
            importer._fetch_yara_master()

    @pytest.mark.parametrize(
        "download", NOT_RULE_FILES.values(), ids=NOT_RULE_FILES.keys()
    )
    def test_not_a_rule_file_raises(self, download):
        importer = _importer(YaraMasterImporter, download)

        with pytest.raises(RuleFileFormatError):
            importer._fetch_yara_master()


class TestSnortMasterImporterDownload:
    """The Snort importer shares the same download handling."""

    def test_gzip_rules_are_parsed(self):
        download = gzip.compress(SNORT_RULE.encode("utf-8"))
        snort_master = _importer(SnortMasterImporter, download)._fetch_snort_master()

        assert snort_master is not None
        assert len(snort_master.rules) == 1

    def test_unreadable_download_raises(self):
        importer = _importer(SnortMasterImporter, b"\xff\xfe\x00\x81binary")

        with pytest.raises(RuleFileFormatError, match="starts with"):
            importer._fetch_snort_master()

    @pytest.mark.parametrize(
        "download", NOT_RULE_FILES.values(), ids=NOT_RULE_FILES.keys()
    )
    def test_not_a_rule_file_raises(self, download):
        importer = _importer(SnortMasterImporter, download)

        with pytest.raises(RuleFileFormatError):
            importer._fetch_snort_master()

    def test_suricata_only_zip_raises(self):
        download = _zip({"crowdstrike_intel_suricata.rules": SNORT_RULE})
        importer = _importer(SnortMasterImporter, download)

        with pytest.raises(RuleFileFormatError, match="not found in the archive"):
            importer._fetch_snort_master()


def test_process_message_marks_unreadable_rule_file_as_failed_work():
    connector = CrowdStrike.__new__(CrowdStrike)

    connector.helper = MagicMock()
    connector.helper.connect_name = "CrowdStrike"

    connector._current_unix_timestamp = MagicMock(return_value=1234567890)
    connector._load_state = MagicMock(return_value={})
    connector._initiate_work = MagicMock(side_effect=["work-1", "work-2"])

    yara = _importer(YaraMasterImporter, NOT_RULE_FILES["proxy-html"])

    working = MagicMock()
    working.name = "Malware"
    working.start.return_value = {"malware_latest": 1}

    connector.importers = [yara, working]

    connector.process_message()

    to_processed = connector.helper.api.work.to_processed
    assert to_processed.call_count == 2

    first = to_processed.call_args_list[0]
    assert first.args[0] == "work-1"
    assert first.args[1].startswith("No YARA rule in the download")
    assert first.kwargs == {"in_error": True}

    second = to_processed.call_args_list[1]
    assert second.args[0] == "work-2"
    assert "in_error" not in second.kwargs
    working.start.assert_called_once()
