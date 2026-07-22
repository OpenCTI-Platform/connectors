"""Unit tests for attachment_handler.passthrough_handler and registry routing."""

import os

import pytest

from attachment_handler.base import BaseAttachmentHandler, ExtractedFile
from attachment_handler.passthrough_handler import PassthroughHandler
from attachment_handler.registry import HandlerRegistry

# ---------------------------------------------------------------------------
# PassthroughHandler
# ---------------------------------------------------------------------------


class TestPassthroughHandler:
    def setup_method(self):
        self.handler = PassthroughHandler()

    def test_supported_extensions(self):
        exts = self.handler.supported_extensions()
        assert ".csv" in exts
        assert ".txt" in exts
        assert ".eml" in exts
        assert ".json" in exts

    def test_can_handle(self):
        assert self.handler.can_handle("notes.txt") is True
        assert self.handler.can_handle("DATA.CSV") is True
        assert self.handler.can_handle("archive.zip") is False

    @pytest.mark.parametrize(
        "ext,expected_mime",
        [
            (".csv", "text/csv"),
            (".txt", "text/plain"),
            (".eml", "message/rfc822"),
            (".json", "application/json"),
            (".xml", "application/xml"),
            (".html", "text/html"),
        ],
    )
    def test_content_type_mapping(self, tmp_path, ext, expected_mime):
        f = tmp_path / f"sample{ext}"
        f.write_bytes(b"hello")
        results = self.handler.extract(str(f))
        assert len(results) == 1
        assert results[0].content_type == expected_mime
        assert results[0].content == b"hello"
        assert results[0].was_encrypted is False

    def test_extract_populates_hashes(self, tmp_path):
        f = tmp_path / "x.txt"
        f.write_bytes(b"hello")
        results = self.handler.extract(str(f))
        assert set(results[0].hashes.keys()) == {"MD5", "SHA-1", "SHA-256"}


# ---------------------------------------------------------------------------
# HandlerRegistry routing
# ---------------------------------------------------------------------------


class TestHandlerRegistryRouting:
    def setup_method(self):
        self.registry = HandlerRegistry()

    def test_get_handler_by_extension(self):
        h = self.registry.get_handler("notes.txt")
        assert isinstance(h, PassthroughHandler)

    def test_get_handler_unknown_extension(self):
        # .xyz is not registered by any default handler
        assert self.registry.get_handler("file.xyz") is None

    def test_get_handler_no_extension(self):
        assert self.registry.get_handler("noext") is None

    def test_case_insensitive_matching(self):
        assert isinstance(self.registry.get_handler("NOTES.TXT"), PassthroughHandler)

    def test_archive_handler_registered_for_zip(self):
        # ArchiveHandler should claim .zip
        h = self.registry.get_handler("evidence.zip")
        assert h is not None
        assert h.__class__.__name__ == "ArchiveHandler"


# ---------------------------------------------------------------------------
# HandlerRegistry.process_attachment
# ---------------------------------------------------------------------------


class TestProcessAttachment:
    def setup_method(self):
        self.registry = HandlerRegistry()

    def test_oversized_file_returns_skipped(self):
        big = b"x" * (2 * 1024 * 1024)  # 2 MiB
        results = self.registry.process_attachment("huge.txt", big, max_size_mb=1)
        assert len(results) == 1
        assert results[0].metadata.get("skipped") == "exceeds_max_size"
        assert results[0].content == b""
        # Hashes are still computed against the original bytes
        assert results[0].hashes

    def test_unknown_extension_returns_raw_with_hashes(self):
        results = self.registry.process_attachment(
            "weird.xyz", b"payload", max_size_mb=10
        )
        assert len(results) == 1
        assert results[0].content == b"payload"
        assert results[0].content_type == "application/octet-stream"
        assert "SHA-256" in results[0].hashes

    def test_passthrough_file_processed(self):
        results = self.registry.process_attachment(
            "notes.txt", b"hello world", max_size_mb=10
        )
        assert len(results) == 1
        assert results[0].filename == "notes.txt"
        assert results[0].content == b"hello world"
        assert results[0].content_type == "text/plain"


# ---------------------------------------------------------------------------
# Custom handler registration (extensibility)
# ---------------------------------------------------------------------------


class FakeHandler(BaseAttachmentHandler):
    def supported_extensions(self):
        return [".fake"]

    def extract(self, file_path, passwords=None):
        return [
            ExtractedFile(
                filename=os.path.basename(file_path),
                content=b"FAKE",
                content_type="application/x-fake",
            )
        ]


class TestCustomHandlerRegistration:
    def test_register_custom_handler(self):
        registry = HandlerRegistry()
        registry.register(FakeHandler())
        h = registry.get_handler("thing.fake")
        assert isinstance(h, FakeHandler)

    def test_custom_handler_used_by_process(self, tmp_path):
        registry = HandlerRegistry()
        registry.register(FakeHandler())
        results = registry.process_attachment("a.fake", b"ignored", max_size_mb=10)
        assert len(results) == 1
        assert results[0].content == b"FAKE"
        assert results[0].content_type == "application/x-fake"
