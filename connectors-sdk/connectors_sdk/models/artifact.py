"""Artifact."""

import base64
import hashlib
from typing import Any

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.enums import HashAlgorithm
from pydantic import Field, model_validator
from stix2.v21 import Artifact as Stix2Artifact


class Artifact(BaseObservableEntity):
    """Define an artifact observable on OpenCTI: binary content such as a PDF.

    An artifact holds either its content or a URL with at least one hash. When
    built from content without hashes, its SHA-256 is computed. Its id only
    depends on the content and hashes, so the same content always gives the
    same artifact, whatever its file names.

    Examples:
        >>> artifact = Artifact(
        ...     content=b"%PDF-1.7",
        ...     mime_type="application/pdf",
        ...     additional_names=["report.pdf"],
        ... )
        >>> artifact.hashes[HashAlgorithm.SHA256][:8]
        '86edbaa2'

    """

    content: bytes | None = Field(
        default=None,
        description="The binary content of the artifact (serialised as base64 `payload_bin`).",
    )
    url: str | None = Field(
        default=None,
        description="A URL to the content. Requires at least one hash.",
    )
    hashes: dict[HashAlgorithm, str] | None = Field(
        default=None,
        description="A dictionary of hashes of the content.",
        min_length=1,
    )
    mime_type: str | None = Field(
        default=None,
        description="The MIME type of the content, e.g. application/pdf.",
    )
    additional_names: list[str] | None = Field(
        default=None,
        description="File names of the artifact. OpenCTI names the stored file after the first one.",
    )

    @model_validator(mode="before")
    @classmethod
    def _validate_data(cls, data: Any) -> Any:
        """Check content/URL combinations and hash the content before the id is computed.

        Notes:
            Like `File`, this runs before `self.id` is evaluated, so invalid
            combinations raise a `pydantic.ValidationError` instead of a
            `stix2` exception.
        """
        if isinstance(data, dict):
            content, url = data.get("content"), data.get("url")
            if content is not None and url is not None:
                raise ValueError("'content' and 'url' are mutually exclusive.")
            if content is None and url is None:
                raise ValueError("Either 'content' or 'url' must be provided.")
            if url is not None and not data.get("hashes"):
                raise ValueError("'hashes' must be provided with 'url'.")
            if content is not None and not data.get("hashes"):
                raw = content.encode() if isinstance(content, str) else bytes(content)
                data = {
                    **data,
                    "hashes": {HashAlgorithm.SHA256: hashlib.sha256(raw).hexdigest()},
                }
        return data

    def to_stix2_object(self) -> Stix2Artifact:
        """Make stix object."""
        return Stix2Artifact(
            payload_bin=(
                base64.b64encode(self.content).decode("ascii")
                if self.content is not None
                else None
            ),
            url=self.url,
            hashes=self.hashes,
            mime_type=self.mime_type,
            x_opencti_additional_names=self.additional_names,
            **self._common_stix2_properties(),
        )
