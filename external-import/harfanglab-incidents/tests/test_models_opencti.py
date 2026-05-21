"""Tests for OpenCTI models, focusing on File observable (fix for issue #5707)."""

from harfanglab_incidents_connector.models.opencti import Author, File


class TestFileModel:
    """Tests for File model STIX2 conversion, including fix for issue #5707."""

    def _make_author(self):
        return Author(name="HarfangLab", description="Test author")

    def test_file_with_hashes(self):
        """File with valid hashes should produce a STIX2 File with hashes."""
        author = self._make_author()
        hashes = {"SHA-256": "a" * 64, "MD5": "c" * 32}
        file_obj = File(
            name="malware.exe",
            hashes=hashes,
            author=author,
        )
        stix_obj = file_obj.to_stix2_object()
        assert stix_obj["type"] == "file"
        assert stix_obj["name"] == "malware.exe"
        assert stix_obj["hashes"]["SHA-256"] == "a" * 64
        assert stix_obj["hashes"]["MD5"] == "c" * 32

    def test_file_with_none_hashes(self):
        """File with hashes=None should not crash (fix for #5707)."""
        author = self._make_author()
        file_obj = File(
            name="malware.exe",
            hashes=None,
            author=author,
        )
        stix_obj = file_obj.to_stix2_object()
        assert stix_obj["type"] == "file"
        assert stix_obj["name"] == "malware.exe"
        assert "hashes" not in stix_obj or stix_obj.get("hashes") is None

    def test_file_with_empty_hashes(self):
        """File with hashes={} should not crash."""
        author = self._make_author()
        file_obj = File(
            name="malware.exe",
            hashes={},
            author=author,
        )
        stix_obj = file_obj.to_stix2_object()
        assert stix_obj["type"] == "file"
        assert stix_obj["name"] == "malware.exe"
        assert "hashes" not in stix_obj or stix_obj.get("hashes") is None

    def test_file_has_author_ref(self):
        """File should have created_by_ref set to author id."""
        author = self._make_author()
        file_obj = File(
            name="test.bin",
            hashes={"SHA-256": "a" * 64},
            author=author,
        )
        stix_obj = file_obj.to_stix2_object()
        assert stix_obj["created_by_ref"] == author.id

    def test_file_has_marking_refs(self):
        """File should have default marking definitions."""
        author = self._make_author()
        file_obj = File(
            name="test.bin",
            hashes={"SHA-256": "a" * 64},
            author=author,
        )
        stix_obj = file_obj.to_stix2_object()
        assert len(stix_obj["object_marking_refs"]) > 0

    def test_file_id_is_deterministic(self):
        """Same file params should produce the same STIX ID."""
        author = self._make_author()
        kwargs = dict(name="test.bin", hashes={"SHA-256": "a" * 64}, author=author)
        file1 = File(**kwargs)
        file2 = File(**kwargs)
        assert file1.id == file2.id
