from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ExtractedFile:
    """Represents an extracted/processed file from an attachment."""

    filename: str
    content: bytes
    content_type: str
    hashes: dict[str, str] = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    was_encrypted: bool = False
    inner_files: list["ExtractedFile"] = field(default_factory=list)


class BaseAttachmentHandler(ABC):
    """Abstract base class for attachment handlers.

    Subclass this to add custom attachment parsing. Register your handler
    with the HandlerRegistry for the file extensions you want to handle.

    Example:
        class MyCustomHandler(BaseAttachmentHandler):
            def supported_extensions(self) -> list[str]:
                return [".custom"]

            def extract(self, file_path, password=None):
                # Parse your file and return ExtractedFile objects
                ...
                return [ExtractedFile(filename="...", content=b"...", ...)]
    """

    @abstractmethod
    def supported_extensions(self) -> list[str]:
        """Return list of file extensions this handler supports (e.g., ['.zip', '.7z'])."""

    @abstractmethod
    def extract(
        self,
        file_path: str,
        passwords: list[str] | None = None,
    ) -> list[ExtractedFile]:
        """Extract/process the file, optionally using provided passwords.

        Args:
            file_path: Path to the file to process.
            passwords: Optional list of passwords to try for decryption.

        Returns:
            List of ExtractedFile objects representing extracted content.
        """

    def can_handle(self, filename: str) -> bool:
        """Check if this handler can process the given filename."""
        lower = filename.lower()
        return any(lower.endswith(ext) for ext in self.supported_extensions())
