import os
import tempfile

from attachment_handler.archive_handler import ArchiveHandler
from attachment_handler.base import BaseAttachmentHandler, ExtractedFile
from attachment_handler.document_handler import DocumentHandler
from attachment_handler.passthrough_handler import PassthroughHandler
from connector.utils import compute_file_hashes


class HandlerRegistry:
    """Registry mapping file extensions to attachment handlers.

    Supports adding custom handlers at runtime for extensibility.
    """

    def __init__(self):
        self._handlers: dict[str, BaseAttachmentHandler] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register built-in handlers."""
        for handler in [ArchiveHandler(), DocumentHandler(), PassthroughHandler()]:
            self.register(handler)

    def register(self, handler: BaseAttachmentHandler) -> None:
        """Register a handler for its supported extensions."""
        for ext in handler.supported_extensions():
            self._handlers[ext.lower()] = handler

    def get_handler(self, filename: str) -> BaseAttachmentHandler | None:
        """Get the appropriate handler for a filename."""
        if "." not in filename:
            return None
        ext = "." + filename.rsplit(".", 1)[-1].lower()
        return self._handlers.get(ext)

    def process_attachment(
        self,
        filename: str,
        content: bytes,
        passwords: list[str] | None = None,
        max_size_mb: int = 25,
    ) -> list[ExtractedFile]:
        """Process an attachment through the appropriate handler.

        For archives, recursively processes inner files (trying passwords
        on nested encrypted content).
        """
        if len(content) > max_size_mb * 1024 * 1024:
            # Return file metadata without processing
            return [
                ExtractedFile(
                    filename=filename,
                    content=b"",  # Don't store oversized content
                    content_type="application/octet-stream",
                    hashes=compute_file_hashes(content),
                    metadata={"skipped": "exceeds_max_size"},
                )
            ]

        handler = self.get_handler(filename)
        if handler is None:
            # No handler — return raw file with hashes
            return [
                ExtractedFile(
                    filename=filename,
                    content=content,
                    content_type="application/octet-stream",
                    hashes=compute_file_hashes(content),
                )
            ]

        # Write to temp file for handler processing
        tmp_path = None
        try:
            suffix = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(content)
                tmp_path = tmp.name

            extracted = handler.extract(tmp_path, passwords)

            # For non-archives, preserve the original filename
            if not isinstance(handler, ArchiveHandler):
                for ef in extracted:
                    ef.filename = filename

            # For archives: recursively process inner files
            if isinstance(handler, ArchiveHandler):
                all_results = []
                for ef in extracted:
                    inner_handler = self.get_handler(ef.filename)
                    if inner_handler:
                        if isinstance(inner_handler, ArchiveHandler):
                            # Nested archive (e.g., encrypted zip inside
                            # unprotected zip) — recurse with depth tracking
                            inner_results = self._process_nested_archive(
                                ef, passwords, max_size_mb, depth=1
                            )
                            ef.inner_files = inner_results
                        else:
                            # Document/passthrough inside archive
                            inner_results = self._process_inner_file(
                                ef, passwords, max_size_mb
                            )
                            ef.inner_files = inner_results
                    all_results.append(ef)
                return all_results

            return extracted

        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _process_nested_archive(
        self,
        extracted_file: ExtractedFile,
        passwords: list[str] | None,
        max_size_mb: int,
        depth: int,
    ) -> list[ExtractedFile]:
        """Recursively process a nested archive (archive inside archive)."""
        if depth >= 3:  # Max nesting depth
            return []

        tmp_path = None
        try:
            suffix = (
                "." + extracted_file.filename.rsplit(".", 1)[-1]
                if "." in extracted_file.filename
                else ""
            )
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(extracted_file.content)
                tmp_path = tmp.name

            handler = self.get_handler(extracted_file.filename)
            if handler is None:
                return []

            inner_extracted = handler.extract(tmp_path, passwords)

            # Process files inside this nested archive too
            all_results = []
            for ef in inner_extracted:
                inner_handler = self.get_handler(ef.filename)
                if inner_handler:
                    if isinstance(inner_handler, ArchiveHandler):
                        ef.inner_files = self._process_nested_archive(
                            ef, passwords, max_size_mb, depth + 1
                        )
                    else:
                        ef.inner_files = self._process_inner_file(
                            ef, passwords, max_size_mb
                        )
                all_results.append(ef)
            return all_results
        except Exception:
            return []
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _process_inner_file(
        self,
        extracted_file: ExtractedFile,
        passwords: list[str] | None,
        max_size_mb: int,
    ) -> list[ExtractedFile]:
        """Process an inner file extracted from an archive."""
        handler = self.get_handler(extracted_file.filename)
        if handler is None:
            return []

        tmp_path = None
        try:
            suffix = (
                "." + extracted_file.filename.rsplit(".", 1)[-1]
                if "." in extracted_file.filename
                else ""
            )
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(extracted_file.content)
                tmp_path = tmp.name

            results = handler.extract(tmp_path, passwords)
            # Preserve original filename for non-archive handlers
            if not isinstance(handler, ArchiveHandler):
                for ef in results:
                    ef.filename = extracted_file.filename
            return results
        except Exception:
            return []
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
