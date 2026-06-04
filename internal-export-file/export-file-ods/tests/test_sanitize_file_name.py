"""Unit tests for ``lib.filenames.sanitize_file_name``.

The helper guards against path traversal (``os.path.basename`` of the raw
payload) and extension mangling (the literal ``.unknown`` suffix is
removed, an existing ``.ods`` extension is preserved) before the
spreadsheet is uploaded back to OpenCTI. The cases below pin the contract
so a future change cannot silently reintroduce unsafe filenames.
"""

import pytest
from lib.filenames import sanitize_file_name


class TestSanitizeFileNameDirectoryComponents:
    """Directory components must be stripped to defend against path traversal."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("/etc/passwd", "passwd.ods"),
            ("../../etc/passwd", "passwd.ods"),
            ("subdir/report.ods", "report.ods"),
            ("nested/path/to/report", "report.ods"),
        ],
    )
    def test_directory_components_are_stripped(self, raw, expected):
        assert sanitize_file_name(raw) == expected


class TestSanitizeFileNameUnknownSuffix:
    """The literal ``.unknown`` suffix must be removed exactly."""

    def test_unknown_suffix_is_removed_exactly(self):
        assert sanitize_file_name("report.unknown") == "report.ods"

    def test_only_trailing_unknown_is_removed(self):
        # The previous ``rstrip(".unknown")`` implementation would have
        # mangled ``file.unk`` to ``file`` (or worse). The new exact-
        # suffix removal must leave that filename alone, only appending
        # the ``.ods`` extension because ``.unk`` is not ``.ods``.
        assert sanitize_file_name("file.unk") == "file.unk.ods"

    def test_unknown_inside_basename_is_preserved(self):
        # ``.unknown`` not at the end of the basename is part of the
        # name proper.
        assert sanitize_file_name("unknown-host.txt") == "unknown-host.txt.ods"


class TestSanitizeFileNameOdsExtension:
    """Existing ``.ods`` extensions must be preserved as-is."""

    def test_existing_ods_extension_is_preserved(self):
        # No ``.ods.ods`` double extension when the request already
        # supplies a ``.ods`` filename.
        assert sanitize_file_name("report.ods") == "report.ods"

    @pytest.mark.parametrize("raw", ["REPORT.ODS", "Report.Ods", "report.OdS"])
    def test_existing_ods_extension_is_preserved_case_insensitively(self, raw):
        assert sanitize_file_name(raw) == raw

    def test_missing_extension_gets_ods(self):
        assert sanitize_file_name("report") == "report.ods"

    def test_other_extension_gets_ods_appended(self):
        assert sanitize_file_name("report.csv") == "report.csv.ods"


class TestSanitizeFileNameEmptyOrMissing:
    """Empty / missing filenames must fall back to a safe default."""

    @pytest.mark.parametrize("raw", ["", None])
    def test_empty_or_none_fallback_to_export(self, raw):
        assert sanitize_file_name(raw) == "export.ods"

    def test_only_unknown_suffix_falls_back_to_export(self):
        # Stripping ``.unknown`` from a payload that contains only that
        # suffix leaves an empty basename, which must fall back to the
        # ``export`` default instead of producing ``.ods``.
        assert sanitize_file_name(".unknown") == "export.ods"

    def test_only_directory_falls_back_to_export(self):
        # ``os.path.basename("/")`` is the empty string on POSIX, which
        # must fall back to the ``export`` default.
        assert sanitize_file_name("/") == "export.ods"
