from attachment_handler.base import BaseAttachmentHandler, ExtractedFile
from connector.utils import compute_file_hashes


class PassthroughHandler(BaseAttachmentHandler):
    """Handler for files that don't need decryption: csv, txt, eml, msg."""

    def supported_extensions(self) -> list[str]:
        return [".csv", ".txt", ".eml", ".msg", ".json", ".xml", ".html"]

    def extract(
        self,
        file_path: str,
        passwords: list[str] | None = None,
    ) -> list[ExtractedFile]:
        with open(file_path, "rb") as fh:
            content = fh.read()
        hashes = compute_file_hashes(content)
        filename = file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]

        ext_to_mime = {
            ".csv": "text/csv",
            ".txt": "text/plain",
            ".eml": "message/rfc822",
            ".msg": "application/vnd.ms-outlook",
            ".json": "application/json",
            ".xml": "application/xml",
            ".html": "text/html",
        }
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        content_type = ext_to_mime.get(ext, "application/octet-stream")

        return [
            ExtractedFile(
                filename=filename,
                content=content,
                content_type=content_type,
                hashes=hashes,
                was_encrypted=False,
            )
        ]
