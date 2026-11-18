"""Tests for reading CrowdStrike rule set downloads in any format (issue #6418)."""

import gzip
import io
import tarfile
import zipfile
from unittest.mock import MagicMock

import pytest
from crowdstrike_feeds_connector.rule.snort_suricata_master_importer import (
    SnortMasterImporter,
)
from crowdstrike_feeds_connector.rule.yara_master_importer import YaraMasterImporter
from crowdstrike_feeds_services.utils.rule_file import (
    RuleFileFormatError,
    extract_rule_file,
)

YARA_FILE_NAME = "crowdstrike_intel_yara.yara"

YARA_RULES = """rule CrowdStrike_CSIT_00001_01 : example
{
    meta:
        copyright = "(c) Example"
        description = "Synthetic rule used by the tests"
        last_modified = "2026-01-02"
        reports = "CSIT-00001"
        actor = "N/A"
        malware_family = "ExampleFamily"
    strings:
        $a = "synthetic"
    condition:
        $a
}
"""

SNORT_RULE = (
    "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS "
    '(msg: "Malware CrowdStrike MALWARE_NAME Outbound [CSIT-00001]"; '
    'content:"evil"; rev:20250528; sid:1000001;)\n'
)


def _zip(members: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in members.items():
            archive.writestr(name, text)
    return buffer.getvalue()


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

    def test_zip_with_other_member_name(self):
        content = _zip({"README.txt": "readme", "yara-master.yara": YARA_RULES})
        assert extract_rule_file(content, YARA_FILE_NAME) == YARA_RULES

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

    def test_zip_without_matching_member(self):
        content = _zip({"a.yara": YARA_RULES, "b.yara": YARA_RULES})
        with pytest.raises(RuleFileFormatError, match="not found in the archive"):
            extract_rule_file(content, YARA_FILE_NAME)

    def test_truncated_zip(self):
        content = _zip({YARA_FILE_NAME: YARA_RULES})[:20]
        with pytest.raises(RuleFileFormatError):
            extract_rule_file(content, YARA_FILE_NAME)

    def test_truncated_gzip(self):
        content = gzip.compress(YARA_RULES.encode("utf-8"))[:15]
        with pytest.raises(RuleFileFormatError):
            extract_rule_file(content, YARA_FILE_NAME)

    def test_binary_garbage(self):
        with pytest.raises(RuleFileFormatError, match="starts with"):
            extract_rule_file(b"\xff\xfe\x00\x81binary", YARA_FILE_NAME)


def _importer(cls, download):
    importer = cls.__new__(cls)
    importer.helper = MagicMock()
    importer.rules_api_cs = MagicMock()
    importer.rules_api_cs.get_latest_rule_file.return_value = download
    return importer


class TestYaraMasterImporterDownload:
    """The YARA importer reads any format and skips an unreadable download."""

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

    def test_unreadable_download_is_logged_and_skipped(self):
        importer = _importer(YaraMasterImporter, b"\xff\xfe\x00\x81binary")

        assert importer._fetch_yara_master() is None
        importer.helper.log_error.assert_called_once()
        assert "Failed to read YARA master" in importer.helper.log_error.call_args[0][0]


class TestSnortMasterImporterDownload:
    """The Snort importer shares the same download handling."""

    def test_gzip_rules_are_parsed(self):
        download = gzip.compress(SNORT_RULE.encode("utf-8"))
        snort_master = _importer(SnortMasterImporter, download)._fetch_snort_master()

        assert snort_master is not None
        assert len(snort_master.rules) == 1

    def test_unreadable_download_is_logged_and_skipped(self):
        importer = _importer(SnortMasterImporter, b"\xff\xfe\x00\x81binary")

        assert importer._fetch_snort_master() is None
        importer.helper.log_error.assert_called_once()
