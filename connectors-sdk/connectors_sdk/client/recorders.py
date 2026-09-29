"""Request/response recorders for debugging :class:`BaseClientApi` HTTP traffic.

Recorders decouple *what* is captured (a normalized "exchange" dict) from
*where* it is stored, so the same recording can target:

- a local folder (:class:`FileSystemRecorder`) — self-hosted / docker-compose,
  where a volume can be mounted and the folder retrieved;
- the connector logs (:class:`LogRecorder`) — the only channel guaranteed to be
  visible in a managed catalog deployment;
- an uploaded bundle in OpenCTI (:class:`OpenCTIFileRecorder`) — a downloadable
  zip attached through a caller-provided upload callback, so the SDK stays
  decoupled from any specific pycti API.

Sensitive headers (authorization, cookies, API keys…) are always redacted so a
recording can be safely shared for debugging.
"""

from __future__ import annotations

import io
import json
import logging
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol, runtime_checkable

import requests

logger = logging.getLogger(__name__)

# Header names whose values are redacted, so recordings can be safely shared.
_SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "apikey",
        "x-auth-token",
        "x-auth",
        "token",
        "x-access-token",
    }
)

# Default maximum number of body characters kept when building an exchange.
_DEFAULT_BODY_MAX_CHARS = 100_000

# Default maximum length of a single serialized log line (LogRecorder).
_DEFAULT_LOG_MAX_CHARS = 4_000

_REDACTED = "***REDACTED***"


# ---------------------------------------------------------------------------
# Exchange building helpers
# ---------------------------------------------------------------------------


def redact_headers(headers: Any) -> dict[str, str]:
    """Return headers with sensitive values replaced by ``***REDACTED***``."""
    redacted: dict[str, str] = {}
    for name, value in dict(headers or {}).items():
        if name.lower() in _SENSITIVE_HEADERS:
            redacted[name] = _REDACTED
        else:
            redacted[name] = value
    return redacted


def serializable_body(body: Any, *, max_chars: int = _DEFAULT_BODY_MAX_CHARS) -> Any:
    """Return a JSON-serializable, size-bounded representation of a body."""
    if body is None:
        return None
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8")
        except UnicodeDecodeError:
            return f"<binary {len(body)} bytes>"
    text = body if isinstance(body, str) else str(body)
    if len(text) > max_chars:
        return text[:max_chars] + "...[truncated]"
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return text


def build_exchange(
    response: requests.Response,
    *,
    seq: int,
    body_max_chars: int = _DEFAULT_BODY_MAX_CHARS,
) -> dict[str, Any]:
    """Build a normalized, redacted exchange dict from a response."""
    request = response.request
    return {
        "seq": seq,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request": {
            "method": request.method,
            "url": request.url,
            "headers": redact_headers(request.headers),
            "body": serializable_body(request.body, max_chars=body_max_chars),
        },
        "response": {
            "status_code": response.status_code,
            "elapsed_ms": round(response.elapsed.total_seconds() * 1000, 2),
            "headers": redact_headers(response.headers),
            "body": serializable_body(response.content, max_chars=body_max_chars),
        },
    }


# ---------------------------------------------------------------------------
# Recorder protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class RequestRecorder(Protocol):
    """Sink for recorded HTTP exchanges.

    Implementations must never raise from :meth:`record` or :meth:`close`;
    recording is best-effort and must not interrupt the connector.
    """

    def record(self, exchange: dict[str, Any]) -> None:
        """Persist a single recorded exchange."""

    def close(self) -> None:
        """Flush and release any resources (called at client shutdown)."""


# ---------------------------------------------------------------------------
# Concrete recorders
# ---------------------------------------------------------------------------


class FileSystemRecorder:
    """Write each exchange as a JSON file into a timestamped session folder.

    Best for self-hosted / docker-compose deployments where the folder can be
    mounted on a volume and retrieved.
    """

    def __init__(self, record_dir: str | Path) -> None:
        """Create a timestamped session folder under ``record_dir``."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.session_dir = (
            Path(record_dir) / f"session_{timestamp}_{uuid.uuid4().hex[:8]}"
        )
        self.session_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Recording API requests to session folder: %s", self.session_dir)

    def record(self, exchange: dict[str, Any]) -> None:
        """Write the exchange as a numbered JSON file in the session folder."""
        try:
            method = (exchange.get("request", {}).get("method") or "REQUEST").upper()
            filename = f"{exchange.get('seq', 0):04d}_{method}.json"
            (self.session_dir / filename).write_text(
                json.dumps(exchange, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        except Exception:  # pragma: no cover - recording must never break requests
            logger.warning("Failed to record API exchange to folder", exc_info=True)

    def close(self) -> None:
        """No-op: exchanges are written eagerly."""


class LogRecorder:
    """Emit each exchange as a single JSON log line.

    The only recorder that works in a managed catalog deployment without a
    mounted volume: the connector logs are visible in the OpenCTI UI, so the
    user can copy them and share them for debugging.
    """

    def __init__(
        self,
        log_callback: Callable[[str], Any] | None = None,
        *,
        max_line_chars: int = _DEFAULT_LOG_MAX_CHARS,
    ) -> None:
        """Configure the log callback and per-line size limit.

        Args:
            log_callback: Callable receiving a single log message string. Pass a
                connector logger method (e.g. ``connector_logger.debug``) so
                records appear in the OpenCTI UI. Defaults to this module's
                ``logger.debug``.
            max_line_chars: Maximum length of a single serialized log line.
        """
        self._log = log_callback or logger.debug
        self._max_line_chars = max_line_chars

    def record(self, exchange: dict[str, Any]) -> None:
        """Emit the exchange as a single, size-bounded JSON log line."""
        try:
            line = json.dumps(exchange, ensure_ascii=False, default=str)
            if len(line) > self._max_line_chars:
                line = line[: self._max_line_chars] + "...[truncated]"
            self._log(f"API exchange recorded: {line}")
        except Exception:  # pragma: no cover - recording must never break requests
            logger.warning("Failed to record API exchange to logs", exc_info=True)

    def close(self) -> None:
        """No-op: exchanges are logged eagerly."""


class OpenCTIFileRecorder:
    """Buffer exchanges and upload them as a single zip on :meth:`close`.

    Keeps the SDK decoupled from any specific pycti API: the caller provides an
    ``upload_callback(filename, data)`` that stores the zip wherever it makes
    sense (e.g. ``helper.api.stix_domain_object.add_file(...)``). The uploaded
    file is then downloadable from the OpenCTI UI in managed deployments.
    """

    def __init__(
        self,
        upload_callback: Callable[[str, bytes], Any],
        *,
        filename: str | None = None,
    ) -> None:
        """Configure the upload callback and the target zip filename."""
        self._upload = upload_callback
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self._filename = filename or f"debug_session_{timestamp}.zip"
        self._exchanges: list[dict[str, Any]] = []

    def record(self, exchange: dict[str, Any]) -> None:
        """Buffer the exchange until :meth:`close` uploads the bundle."""
        self._exchanges.append(exchange)

    def close(self) -> None:
        """Build the zip bundle from buffered exchanges and upload it."""
        if not self._exchanges:
            return
        try:
            data = self._build_zip()
            self._upload(self._filename, data)
            logger.info(
                "Uploaded API debug session (%d exchanges) as %s",
                len(self._exchanges),
                self._filename,
            )
        except Exception:  # pragma: no cover - recording must never break requests
            logger.warning("Failed to upload API debug session", exc_info=True)
        finally:
            self._exchanges = []

    def _build_zip(self) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            index = []
            for exchange in self._exchanges:
                seq = exchange.get("seq", 0)
                method = (
                    exchange.get("request", {}).get("method") or "REQUEST"
                ).upper()
                name = f"{seq:04d}_{method}.json"
                archive.writestr(
                    name,
                    json.dumps(exchange, indent=2, ensure_ascii=False, default=str),
                )
                index.append(
                    {
                        "file": name,
                        "method": method,
                        "url": exchange.get("request", {}).get("url"),
                        "status_code": exchange.get("response", {}).get("status_code"),
                    }
                )
            archive.writestr(
                "index.json", json.dumps(index, indent=2, ensure_ascii=False)
            )
        return buffer.getvalue()


class MultiRecorder:
    """Fan out each exchange to several recorders (e.g. logs + upload)."""

    def __init__(self, recorders: list[RequestRecorder]) -> None:
        """Wrap a list of recorders to fan out each exchange."""
        self._recorders = list(recorders)

    def record(self, exchange: dict[str, Any]) -> None:
        """Forward the exchange to every wrapped recorder."""
        for recorder in self._recorders:
            try:
                recorder.record(exchange)
            except Exception:  # pragma: no cover - recording must never break requests
                logger.warning("A recorder failed to record an exchange", exc_info=True)

    def close(self) -> None:
        """Close every wrapped recorder."""
        for recorder in self._recorders:
            try:
                recorder.close()
            except Exception:  # pragma: no cover - recording must never break requests
                logger.warning("A recorder failed to close", exc_info=True)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_recorder(
    *,
    enabled: bool,
    mode: str = "log",
    record_dir: str | Path | None = None,
    log_callback: Callable[[str], Any] | None = None,
) -> RequestRecorder | None:
    """Build a recorder from simple config values (e.g. connector settings).

    Args:
        enabled: When ``False``, returns ``None`` (recording disabled).
        mode: ``"log"`` to record to the connector logs (works in managed
            catalog deployments) or ``"file"`` to record to a session folder
            (self-hosted / docker-compose with a mounted volume).
        record_dir: Target folder for ``"file"`` mode. Defaults to
            ``"recordings"`` when omitted.
        log_callback: Log callback for ``"log"`` mode, e.g. a connector logger
            method (``connector_logger.debug``) so records appear in the UI.

    Returns:
        A configured :class:`RequestRecorder`, or ``None`` when disabled.
    """
    if not enabled:
        return None
    if mode == "file":
        return FileSystemRecorder(record_dir or "recordings")
    return LogRecorder(log_callback=log_callback)
