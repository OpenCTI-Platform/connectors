"""OpenCTI CrowdStrike importer module."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, Optional

import stix2

if TYPE_CHECKING:
    from crowdstrike_feeds_connector import ConnectorSettings
    from pycti import OpenCTIConnectorHelper


class BaseImporter(ABC):
    """CrowdStrike importer module."""

    _NAME = None

    def __init__(
        self,
        config: "ConnectorSettings",
        helper: "OpenCTIConnectorHelper",
        author: stix2.Identity,
        tlp_marking: stix2.MarkingDefinition,
    ) -> None:
        """Initialize CrowdStrike importer module."""
        self.config = config
        self.helper = helper
        self.author = author
        self.tlp_marking = tlp_marking
        self.work_id: Optional[str] = None

        # Bundle batching: importers build a small bundle per entity but, rather
        # than POSTing each one (one ingestion request/job per entity), buffer
        # the objects and flush them as one larger bundle every ~batch_size
        # objects. Flush at natural boundaries (end of a processed page) so state
        # only advances once the buffered objects have actually been sent.
        try:
            self._bundle_batch_size = int(config.crowdstrike.bundle_batch_size)
        except Exception:  # noqa: BLE001 — be permissive about config shape
            self._bundle_batch_size = 5000
        if self._bundle_batch_size < 1:
            self._bundle_batch_size = 5000
        self._bundle_buffer: list = []
        self._bundle_seen_ids: set = set()
        # Also cap a bundle by serialized byte size: object count alone doesn't
        # bound the request body (a report embeds its PDF as base64, so a few
        # hundred objects can be hundreds of MB and trip the server's body
        # limit). Stays well under opencti-ng's 512 MiB request limit.
        self._bundle_bytes = 0
        self._bundle_max_bytes = 64 * 1024 * 1024

    def start(self, work_id: str, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Start import.

        :param work_id: Work identifier for current import process.
        :type work_id: str
        :param state: Current state of the importer.
        :type state: Dict[str, Any]
        :return: State after the import.
        :rtype: Dict[str, Any]
        """
        self.work_id = work_id

        return self.run(state)

    @abstractmethod
    def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run import.

        :param state: Current state of the importer.
        :type state: Dict[str, Any]
        :return: State after the import.
        :rtype: Dict[str, Any]
        """
        ...

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _debug(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_debug(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)

    def _warning(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_warning(fmt_msg)

    def _source_name(self) -> str:
        return self.author["name"]

    def _confidence_level(self) -> int:
        return self.helper.connect_confidence_level

    def _set_state(self, state: Dict[str, Any]) -> None:
        self.helper.set_state(state)

    def _send_bundle(self, bundle: stix2.Bundle) -> None:
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(
            serialized_bundle,
            work_id=self.work_id,
            bypass_split=True,
        )

    # ── bundle batching ──────────────────────────────────────────────────
    def _batch_bundle(self, bundle: stix2.Bundle) -> None:
        """Buffer a per-entity bundle's objects; flush when the buffer is full.

        De-dups by STIX id within the current buffer (shared objects like the
        author identity or TLP marking repeat across entities). Call
        :meth:`_flush_bundle` at the end of a processing run to emit the tail.
        """
        for obj in bundle.objects:
            oid = getattr(obj, "id", None)
            if oid is not None and oid in self._bundle_seen_ids:
                continue
            if oid is not None:
                self._bundle_seen_ids.add(oid)
            self._bundle_buffer.append(obj)
            try:
                self._bundle_bytes += len(obj.serialize())
            except Exception:  # noqa: BLE001 — sizing is best-effort
                self._bundle_bytes += 1024
            # Flush on either limit — a single large object (PDF) flushes at once.
            if (
                len(self._bundle_buffer) >= self._bundle_batch_size
                or self._bundle_bytes >= self._bundle_max_bytes
            ):
                self._flush_bundle()

    def _flush_bundle(self) -> None:
        """Send any buffered objects as a single bundle and reset the buffer."""
        if not self._bundle_buffer:
            return
        self._send_bundle(stix2.Bundle(objects=self._bundle_buffer, allow_custom=True))
        self._bundle_buffer = []
        self._bundle_seen_ids = set()
        self._bundle_bytes = 0

    @property
    def name(self):
        return self._NAME
