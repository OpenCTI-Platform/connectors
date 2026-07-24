"""Safe, bounded decoding for untrusted RansomLook capture evidence."""

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EvidencePayload:
    """One validated passive capture ready for STIX conversion."""

    kind: str
    mime_type: str
    content: bytes
    sha256: str


class EvidenceBudget:
    """Run-scoped decoded and emitted-representation evidence budgets."""

    def __init__(
        self, max_count: int, max_bytes: int, max_serialized_bytes: int | None = None
    ) -> None:
        self.max_count = max_count
        self.max_bytes = max_bytes
        self.max_serialized_bytes = max_serialized_bytes or max_bytes * 4
        self.count = 0
        self.bytes = 0
        self.serialized_bytes = 0
        self.hashes: set[tuple[str, str]] = set()
        self.rejected = 0
        self.exhausted = 0

    def reject(self) -> None:
        """Record one rejected optional payload without retaining its content."""
        self.rejected += 1

    def reserve(
        self,
        kind: str,
        digest: str,
        size: int,
        representations: int = 1,
    ) -> tuple[bool, str | None]:
        """Reserve every owner occurrence and its exact base64 representations."""
        if representations < 1:
            raise ValueError("evidence representations must be positive")
        key = (kind, digest)
        if self.count >= self.max_count:
            self.exhausted += 1
            return False, "run artifact count budget exhausted"
        if size > self.max_bytes - self.bytes:
            self.exhausted += 1
            return False, "run decoded byte budget exhausted"
        encoded_size = (4 * ((size + 2) // 3)) * representations
        if encoded_size > self.max_serialized_bytes - self.serialized_bytes:
            self.exhausted += 1
            return False, "run serialized evidence byte budget exhausted"
        self.hashes.add(key)
        self.count += 1
        self.bytes += size
        self.serialized_bytes += encoded_size
        return True, None


class EvidenceDecoder:
    """Validate captures without rendering, executing, fetching, or unpacking them."""

    PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
    _BASE64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
    _HTML_START = re.compile(
        rb"^\s*(?:\xef\xbb\xbf)?\s*(?:<!doctype\s+html\b|<html\b)", re.IGNORECASE
    )

    def __init__(self, logger: Any, max_item_bytes: int, budget: EvidenceBudget):
        self.logger = logger
        self.max_item_bytes = max_item_bytes
        self.budget = budget
        self.last_rejection_retryable = False
        self.last_rejection_reason: str | None = None

    def decode(
        self,
        value: Any,
        kind: str,
        scope: str,
        upstream_identifier: str,
        representations: int = 1,
    ) -> EvidencePayload | None:
        """Decode and validate one base64 capture, failing closed and content-free."""
        identifier_hash = hashlib.sha256(upstream_identifier.encode()).hexdigest()[:16]
        try:
            encoded, declared_mime = self._carrier(value)
            content, digest = self._decode_base64(encoded)
            mime = self._validate_content(kind, content, declared_mime)
            accepted, reason = self.budget.reserve(
                kind, digest, len(content), representations
            )
            if not accepted:
                raise ValueError(reason)
        except (TypeError, ValueError, binascii.Error) as exc:
            reason = str(exc)[:160]
            self.last_rejection_reason = reason
            self.last_rejection_retryable = reason.startswith(
                "run "
            ) and reason.endswith("budget exhausted")
            self.budget.reject()
            self.logger.warning(
                "Skipping rejected RansomLook evidence",
                {
                    "scope": scope,
                    "kind": kind,
                    "identifier_sha256": identifier_hash,
                    "reason": reason,
                },
            )
            return None
        self.last_rejection_reason = None
        self.last_rejection_retryable = False
        self.logger.info(
            "Accepted bounded RansomLook evidence",
            {
                "scope": scope,
                "kind": kind,
                "identifier_sha256": identifier_hash,
                "sha256": digest,
                "decoded_bytes": len(content),
            },
        )
        return EvidencePayload(kind, mime, content, digest)

    def decode_note_original(
        self,
        value: Any,
        media_type: Any,
        upstream_identifier: str,
        representations: int = 1,
    ) -> EvidencePayload | None:
        """Retain exact ransom-note text as bounded passive evidence.

        RansomLook's note detail endpoint returns decoded text rather than the
        base64 capture carrier used by posts and locations.  Treat it as
        untrusted passive bytes and use the same per-item and run budgets.
        """
        identifier_hash = hashlib.sha256(upstream_identifier.encode()).hexdigest()[:16]
        try:
            if not isinstance(value, str) or not value:
                raise TypeError("note original is not non-empty text")
            content = value.encode("utf-8")
            if len(content) > self.max_item_bytes:
                raise ValueError("decoded artifact exceeds per-item limit")
            normalized_format = (
                media_type.strip().casefold() if isinstance(media_type, str) else ""
            )
            if normalized_format in {"html", "text/html"}:
                mime = "text/html"
            elif normalized_format in {"txt", "text", "text/plain", ""}:
                mime = "text/plain"
            else:
                raise ValueError("unsupported ransom-note media type")
            digest = hashlib.sha256(content).hexdigest()
            accepted, reason = self.budget.reserve(
                "ransom-note", digest, len(content), representations
            )
            if not accepted:
                raise ValueError(reason)
        except (TypeError, ValueError) as exc:
            self.budget.reject()
            self.logger.warning(
                "Skipping rejected RansomLook evidence",
                {
                    "scope": "actor-profile-note",
                    "kind": "ransom-note",
                    "identifier_sha256": identifier_hash,
                    "reason": str(exc)[:160],
                },
            )
            return None
        self.logger.info(
            "Accepted bounded RansomLook evidence",
            {
                "scope": "actor-profile-note",
                "kind": "ransom-note",
                "identifier_sha256": identifier_hash,
                "sha256": digest,
                "decoded_bytes": len(content),
            },
        )
        return EvidencePayload("ransom-note", mime, content, digest)

    def decode_torrent_file(
        self, value: Any, upstream_identifier: str, representations: int = 1
    ) -> EvidencePayload | None:
        """Decode a bounded passive ``.torrent`` carrier without parsing it.

        Only the outer bencoded-dictionary framing is checked.  The connector
        deliberately does not enumerate files, contact trackers, follow
        webseeds, or otherwise act on the untrusted metainfo payload.
        """
        identifier_hash = hashlib.sha256(upstream_identifier.encode()).hexdigest()[:16]
        try:
            encoded, declared_mime = self._carrier(value)
            content, digest = self._decode_base64(encoded)
            if declared_mime not in {
                None,
                "application/x-bittorrent",
                "application/octet-stream",
            }:
                raise ValueError("unsupported torrent media type")
            if not content.startswith(b"d") or not content.endswith(b"e"):
                raise ValueError("torrent metainfo is not a bencoded dictionary")
            accepted, reason = self.budget.reserve(
                "torrent", digest, len(content), representations
            )
            if not accepted:
                raise ValueError(reason)
        except (TypeError, ValueError, binascii.Error) as exc:
            self.budget.reject()
            self.logger.warning(
                "Skipping rejected RansomLook torrent evidence",
                {
                    "scope": "leak-mechanism",
                    "kind": "torrent",
                    "identifier_sha256": identifier_hash,
                    "reason": str(exc)[:160],
                },
            )
            return None
        return EvidencePayload("torrent", "application/x-bittorrent", content, digest)

    def decode_analysis_document(
        self,
        value: Any,
        media_type: Any,
        upstream_identifier: str,
        representations: int = 1,
    ) -> EvidencePayload | None:
        """Decode one explicitly supplied passive technical-analysis document.

        Only PDF, HTML, and plain UTF-8 text are supported.  The bytes are not
        rendered, parsed, unpacked, or used to fetch secondary resources.
        """
        identifier_hash = hashlib.sha256(upstream_identifier.encode()).hexdigest()[:16]
        try:
            encoded, carrier_mime = self._carrier(value)
            content, digest = self._decode_base64(encoded)
            declared = (
                media_type.strip().casefold() if isinstance(media_type, str) else None
            ) or carrier_mime
            aliases = {
                "pdf": "application/pdf",
                "html": "text/html",
                "text": "text/plain",
                "txt": "text/plain",
            }
            mime = aliases.get(declared, declared)
            if mime == "application/pdf":
                if not content.startswith(b"%PDF-"):
                    raise ValueError("analysis PDF does not have PDF magic bytes")
            elif mime == "text/html":
                if b"\x00" in content or not self._HTML_START.match(content):
                    raise ValueError("analysis document is not recognizable HTML")
                content.decode("utf-8", errors="strict")
            elif mime == "text/plain":
                if b"\x00" in content:
                    raise ValueError("analysis text contains NUL bytes")
                content.decode("utf-8", errors="strict")
            else:
                raise ValueError("unsupported analysis document media type")
            accepted, reason = self.budget.reserve(
                "technical-analysis", digest, len(content), representations
            )
            if not accepted:
                raise ValueError(reason)
        except (TypeError, ValueError, binascii.Error, UnicodeDecodeError) as exc:
            self.budget.reject()
            self.logger.warning(
                "Skipping rejected RansomLook analysis document",
                {
                    "scope": "actor-profile-analysis",
                    "kind": "technical-analysis",
                    "identifier_sha256": identifier_hash,
                    "reason": str(exc)[:160],
                },
            )
            return None
        return EvidencePayload("technical-analysis", mime, content, digest)

    @staticmethod
    def _carrier(value: Any) -> tuple[str, str | None]:
        if not isinstance(value, str) or not value:
            raise TypeError("capture is not a non-empty string")
        if not value.startswith("data:"):
            return value, None
        header, separator, encoded = value.partition(",")
        if not separator or not header.casefold().endswith(";base64"):
            raise ValueError("data URI is not base64 encoded")
        mime = header[5:-7].strip().casefold()
        if not mime or ";" in mime:
            raise ValueError("data URI has unsupported media parameters")
        return encoded, mime

    def _decode_base64(self, encoded: str) -> tuple[bytes, str]:
        # Strict input and a decoded-size estimate prevent an oversized allocation.
        if any(character.isspace() for character in encoded):
            raise ValueError("base64 contains whitespace")
        if len(encoded) % 4 or not self._BASE64.fullmatch(encoded):
            raise ValueError("base64 encoding is malformed")
        padding = len(encoded) - len(encoded.rstrip("="))
        estimated = (len(encoded) // 4) * 3 - padding
        if estimated > self.max_item_bytes:
            raise ValueError("decoded artifact exceeds per-item limit")
        # Decode fixed, four-byte-aligned chunks and hash incrementally. The
        # output remains bounded by the estimate and is retained only because a
        # STIX Artifact must carry its passive payload.
        decoded = bytearray()
        hasher = hashlib.sha256()
        chunk_size = 8192
        for offset in range(0, len(encoded), chunk_size):
            chunk = base64.b64decode(
                encoded[offset : offset + chunk_size], validate=True
            )
            decoded.extend(chunk)
            hasher.update(chunk)
        if not decoded:
            raise ValueError("decoded artifact is empty")
        return bytes(decoded), hasher.hexdigest()

    def _validate_content(
        self, kind: str, content: bytes, declared_mime: str | None
    ) -> str:
        if kind == "screen":
            expected = "image/png"
            if not content.startswith(self.PNG_MAGIC):
                raise ValueError("screenshot does not have PNG magic bytes")
        elif kind == "source":
            expected = "text/html"
            if b"\x00" in content:
                raise ValueError("HTML source contains NUL bytes")
            try:
                content.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise ValueError("HTML source is not valid UTF-8") from exc
            if not self._HTML_START.match(content):
                raise ValueError("source is not recognizable HTML")
        else:
            raise ValueError("unsupported evidence kind")
        if declared_mime is not None and declared_mime != expected:
            raise ValueError("declared MIME type does not match evidence kind")
        return expected
