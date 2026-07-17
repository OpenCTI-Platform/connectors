"""Coverage for archive_handler, document_handler, and registry recursion.

ZIP archives are built with the stdlib (plain only — stdlib cannot *write*
encrypted zips). py7zr/msoffcrypto/pikepdf are optional and absent in CI, so the
7z/office/pdf decrypt paths are exercised via their graceful-fallback branches.
"""

import io
import zipfile

import pytest

from attachment_handler.archive_handler import ArchiveHandler
from attachment_handler.document_handler import DocumentHandler
from attachment_handler.registry import HandlerRegistry


def _zip_bytes(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# ArchiveHandler
# --------------------------------------------------------------------------- #
class TestArchiveHandler:
    def test_supported_extensions(self):
        assert set(ArchiveHandler().supported_extensions()) == {".zip", ".7z", ".rar"}

    def test_extract_plain_zip(self, tmp_path):
        p = tmp_path / "a.zip"
        p.write_bytes(_zip_bytes({"f1.txt": b"hello", "f2.txt": b"world"}))
        out = ArchiveHandler().extract(str(p))
        names = {e.filename for e in out}
        assert names == {"f1.txt", "f2.txt"}
        assert all(e.was_encrypted is False for e in out)
        assert all(e.hashes for e in out)

    def test_extract_zip_skips_directories(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("dir/", b"")
            zf.writestr("dir/file.txt", b"data")
        p = tmp_path / "a.zip"
        p.write_bytes(buf.getvalue())
        out = ArchiveHandler().extract(str(p))
        assert [e.filename for e in out] == ["file.txt"]

    def test_bad_zip_returns_empty(self, tmp_path):
        p = tmp_path / "a.zip"
        p.write_bytes(b"not a real zip")
        assert ArchiveHandler().extract(str(p)) == []

    def test_unknown_extension_returns_empty(self, tmp_path):
        p = tmp_path / "a.tar"
        p.write_bytes(b"x")
        assert ArchiveHandler().extract(str(p)) == []

    def test_7z_without_py7zr_is_graceful(self, tmp_path):
        pytest.importorskip  # noqa: B018  (documentation: not skipping)
        try:
            import py7zr  # noqa: F401

            pytest.skip("py7zr installed — graceful-fallback path not exercised")
        except ImportError:
            pass
        p = tmp_path / "a.7z"
        p.write_bytes(b"7z\xbc\xaf\x27\x1c")  # 7z magic, not a real archive
        assert ArchiveHandler().extract(str(p)) == []

    def test_rar_without_bsdtar_is_graceful(self, tmp_path, monkeypatch):
        import shutil

        # _extract_rar imports shutil locally; patch the source attribute.
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        p = tmp_path / "a.rar"
        p.write_bytes(b"Rar!\x1a\x07\x00")
        assert ArchiveHandler().extract(str(p)) == []


# --------------------------------------------------------------------------- #
# DocumentHandler
# --------------------------------------------------------------------------- #
class TestDocumentHandler:
    def test_supported_extensions(self):
        assert set(DocumentHandler().supported_extensions()) == {".xlsx", ".pdf"}

    def test_xlsx_no_password_passthrough(self, tmp_path):
        p = tmp_path / "book.xlsx"
        p.write_bytes(b"PK\x03\x04 fake xlsx bytes")
        out = DocumentHandler().extract(str(p))
        assert len(out) == 1
        assert out[0].content_type.endswith("spreadsheetml.sheet")
        assert out[0].was_encrypted is False
        assert out[0].hashes

    def test_pdf_no_password_passthrough(self, tmp_path):
        p = tmp_path / "doc.pdf"
        p.write_bytes(b"%PDF-1.7 fake")
        out = DocumentHandler().extract(str(p))
        assert out[0].content_type == "application/pdf"
        assert out[0].was_encrypted is False

    def test_pdf_with_password_but_no_pikepdf_keeps_original(self, tmp_path):
        # pikepdf absent -> _decrypt_pdf returns None -> content unchanged
        try:
            import pikepdf  # noqa: F401

            pytest.skip("pikepdf installed — fallback path not exercised")
        except ImportError:
            pass
        p = tmp_path / "doc.pdf"
        p.write_bytes(b"%PDF-1.7 fake")
        out = DocumentHandler().extract(str(p), passwords=["secret"])
        assert out[0].was_encrypted is False

    def test_xlsx_with_password_but_no_msoffcrypto_keeps_original(self, tmp_path):
        try:
            import msoffcrypto  # noqa: F401

            pytest.skip("msoffcrypto installed — fallback path not exercised")
        except ImportError:
            pass
        p = tmp_path / "book.xlsx"
        p.write_bytes(b"PK\x03\x04 fake")
        out = DocumentHandler().extract(str(p), passwords=["secret"])
        assert out[0].was_encrypted is False

    def test_unknown_extension_returns_empty(self, tmp_path):
        p = tmp_path / "x.doc"
        p.write_bytes(b"x")
        assert DocumentHandler().extract(str(p)) == []


# --------------------------------------------------------------------------- #
# Registry recursion
# --------------------------------------------------------------------------- #
class TestRegistryRecursion:
    def setup_method(self):
        self.registry = HandlerRegistry()

    def test_archive_with_inner_document(self):
        zip_bytes = _zip_bytes({"notes.txt": b"plain text note"})
        out = self.registry.process_attachment("bundle.zip", zip_bytes)
        assert len(out) == 1
        inner = out[0]
        assert inner.filename == "notes.txt"
        # passthrough handler runs on the inner .txt
        assert inner.inner_files
        assert inner.inner_files[0].filename == "notes.txt"

    def test_nested_archive_recurses(self):
        inner_zip = _zip_bytes({"deep.txt": b"deep content"})
        outer_zip = _zip_bytes({"inner.zip": inner_zip})
        out = self.registry.process_attachment("outer.zip", outer_zip)
        assert len(out) == 1
        assert out[0].filename == "inner.zip"
        # nested archive extracted into inner_files
        assert out[0].inner_files
        assert out[0].inner_files[0].filename == "deep.txt"

    def test_non_archive_preserves_original_filename(self):
        out = self.registry.process_attachment("report.pdf", b"%PDF-1.7 x")
        assert out[0].filename == "report.pdf"

    def test_oversized_skipped(self):
        big = b"x" * (2 * 1024 * 1024)
        out = self.registry.process_attachment("big.zip", big, max_size_mb=1)
        assert out[0].metadata.get("skipped") == "exceeds_max_size"
        assert out[0].content == b""

    def test_unknown_extension_returns_raw(self):
        out = self.registry.process_attachment("data.bin", b"raw")
        assert out[0].content == b"raw"
        assert out[0].hashes
