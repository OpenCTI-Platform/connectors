import io
import logging

from attachment_handler.base import BaseAttachmentHandler, ExtractedFile
from connector.utils import compute_file_hashes

logger = logging.getLogger(__name__)


class DocumentHandler(BaseAttachmentHandler):
    """Handler for document files: xlsx, pdf (with password support)."""

    def supported_extensions(self) -> list[str]:
        return [".xlsx", ".pdf"]

    def extract(
        self,
        file_path: str,
        passwords: list[str] | None = None,
    ) -> list[ExtractedFile]:
        lower = file_path.lower()
        if lower.endswith(".xlsx"):
            return self._handle_xlsx(file_path, passwords)
        if lower.endswith(".pdf"):
            return self._handle_pdf(file_path, passwords)
        return []

    def _handle_xlsx(
        self,
        file_path: str,
        passwords: list[str] | None,
    ) -> list[ExtractedFile]:
        with open(file_path, "rb") as fh:
            content = fh.read()
        was_encrypted = False

        # Try to decrypt if passwords provided
        if passwords:
            decrypted = self._decrypt_office(file_path, passwords)
            if decrypted is not None:
                content = decrypted
                was_encrypted = True

        hashes = compute_file_hashes(content)
        return [
            ExtractedFile(
                filename=file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1],
                content=content,
                content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                hashes=hashes,
                was_encrypted=was_encrypted,
            )
        ]

    def _decrypt_office(self, file_path: str, passwords: list[str]) -> bytes | None:
        """Attempt to decrypt an Office file using msoffcrypto-tool."""
        try:
            import msoffcrypto
        except ImportError:
            logger.warning(
                "msoffcrypto-tool not installed — cannot decrypt Office files"
            )
            return None

        for pwd in passwords:
            try:
                with open(file_path, "rb") as f:
                    office_file = msoffcrypto.OfficeFile(f)
                    if not office_file.is_encrypted():
                        return None
                    office_file.load_key(password=pwd)
                    output = io.BytesIO()
                    office_file.decrypt(output)
                    return output.getvalue()
            except Exception as e:
                logger.debug("Office decrypt attempt failed: %s — %s", file_path, e)
                continue
        logger.warning("All password attempts failed for Office file: %s", file_path)
        return None

    def _handle_pdf(
        self,
        file_path: str,
        passwords: list[str] | None,
    ) -> list[ExtractedFile]:
        with open(file_path, "rb") as fh:
            content = fh.read()
        was_encrypted = False

        if passwords:
            decrypted = self._decrypt_pdf(file_path, passwords)
            if decrypted is not None:
                content = decrypted
                was_encrypted = True

        hashes = compute_file_hashes(content)
        return [
            ExtractedFile(
                filename=file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1],
                content=content,
                content_type="application/pdf",
                hashes=hashes,
                was_encrypted=was_encrypted,
            )
        ]

    def _decrypt_pdf(self, file_path: str, passwords: list[str]) -> bytes | None:
        """Attempt to decrypt a PDF using pikepdf."""
        try:
            import pikepdf
        except ImportError:
            logger.warning("pikepdf not installed — cannot decrypt PDF files")
            return None

        for pwd in passwords:
            try:
                pdf = pikepdf.open(file_path, password=pwd)
                output = io.BytesIO()
                pdf.save(output)
                pdf.close()
                return output.getvalue()
            except Exception as e:
                logger.debug("PDF decrypt attempt failed: %s — %s", file_path, e)
                continue
        logger.warning("All password attempts failed for PDF: %s", file_path)
        return None
