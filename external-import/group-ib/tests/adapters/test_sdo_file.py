from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from adapters.adapter import DataToSTIXAdapter
from connector.settings import ConfigConnector


def _adapter(*, is_ioc: bool = False) -> DataToSTIXAdapter:
    helper = SimpleNamespace(connector_logger=MagicMock())
    return DataToSTIXAdapter(
        mitre_mapper={},
        collection="apt/threat",
        tlp_color="amber",
        helper=helper,
        is_ioc=is_ioc,
        threat_actor_name=None,
        config=ConfigConnector(),
    )


_VALID_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
_VALID_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
_VALID_SHA256 = "e3b0c44298fc1c149afbf4c8996fb924" "27ae41e4649b934ca495991b7852b855"


# ``_retrieve_ttl_dates`` derives valid_from from ``date-modified`` (else
# ``date-created``) and valid_until = date + ttl. Pass both so the IOC
# branches build valid stix2.Indicator objects.
_DATE_OBJ = {
    "date-created": "2024-01-01T00:00:00+00:00",
    "date-modified": "2024-01-15T00:00:00+00:00",
    "ttl": 30,
}


class TestGenerateStixFileWithList:
    def test_file_list_with_valid_hashes(self):
        a = _adapter(is_ioc=True)
        out = a.generate_stix_file(
            obj={
                "file_list": [
                    {
                        "md5": _VALID_MD5,
                        "sha1": _VALID_SHA1,
                        "sha256": _VALID_SHA256,
                    },
                ],
            },
            json_date_obj=_DATE_OBJ,
            related_objects=[],
            file_is_ioc=True,
        )
        assert isinstance(out, list)
        assert len(out) >= 1

    def test_file_list_multiple_entries(self):
        a = _adapter()
        out = a.generate_stix_file(
            obj={
                "file_list": [
                    {"md5": _VALID_MD5},
                    {"sha256": _VALID_SHA256},
                ],
            },
            json_date_obj=_DATE_OBJ,
            related_objects=[],
            file_is_ioc=False,
        )
        # Two valid hashes → two FileHash wrappers.
        assert len(out) == 2

    def test_file_list_invalid_hashes_ignored(self):
        # Each entry has bad-format hashes; valid sha1 still produces a file.
        a = _adapter()
        out = a.generate_stix_file(
            obj={
                "file_list": [
                    {"md5": "not-a-hash", "sha1": _VALID_SHA1},
                ],
            },
            json_date_obj=_DATE_OBJ,
            related_objects=[],
            file_is_ioc=False,
        )
        assert len(out) == 1
        # MD5 line was logged as an error before being dropped.
        a.helper.connector_logger.error.assert_called()

    def test_file_list_all_invalid_skipped(self):
        a = _adapter()
        out = a.generate_stix_file(
            obj={
                "file_list": [
                    {"md5": "x", "sha1": "y", "sha256": "z"},
                ],
            },
            json_date_obj=_DATE_OBJ,
            related_objects=[],
            file_is_ioc=False,
        )
        # No valid hash → no file emitted.
        assert out == []


class TestGenerateStixFileBareObject:
    """``obj`` is a bare ``{md5, sha1, sha256}`` dict (no ``file_list``
    wrapper) — used by collections that ship a single file per event."""

    def test_bare_dict_with_hashes(self):
        a = _adapter()
        out = a.generate_stix_file(
            obj={"md5": _VALID_MD5, "sha256": _VALID_SHA256},
            json_date_obj=_DATE_OBJ,
            related_objects=[],
            file_is_ioc=False,
        )
        assert len(out) == 1

    def test_bare_dict_only_invalid_hashes(self):
        a = _adapter()
        out = a.generate_stix_file(
            obj={"md5": "bad", "sha1": "alsobad"},
            json_date_obj=_DATE_OBJ,
            related_objects=[],
            file_is_ioc=False,
        )
        assert out == []

    def test_bare_dict_invalid_sha1_dropped_valid_md5_kept(self):
        a = _adapter()
        out = a.generate_stix_file(
            obj={"md5": _VALID_MD5, "sha1": "bad"},
            json_date_obj=_DATE_OBJ,
            related_objects=[],
            file_is_ioc=False,
        )
        # Valid MD5 alone still produces one file.
        assert len(out) == 1
