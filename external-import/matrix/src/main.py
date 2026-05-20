"""OpenCTI Matrix external-import connector.

Listens on a Matrix server, decrypts incoming messages and attachments
(end-to-end-encrypted or in clear) and forwards them to OpenCTI as a
stream of STIX 2.1 bundles. Each Matrix room becomes a ``channel`` SDO,
each event becomes a ``media-content`` observable (with optional file
attachments encoded as ``x_opencti_files``), and message authors become
``identity`` SDOs (class ``individual``). Thread replies are emitted as
``related-to`` relationships toward the root post.
"""

import asyncio
import base64
import logging
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import stix2
import yaml
from lib.helpers import (
    channel_display_name,
    media_content_id,
    publication_date_from_event,
    resolve_tlp,
)
from nio import (
    AsyncClient,
    AsyncClientConfig,
    RoomEncryptedAudio,
    RoomEncryptedFile,
    RoomEncryptedImage,
    RoomEncryptedVideo,
    RoomMessageAudio,
    RoomMessageFile,
    RoomMessageImage,
    RoomMessageNotice,
    RoomMessageText,
    RoomMessageUnknown,
    RoomMessageVideo,
    UnknownEvent,
    crypto,
    store,
)
from pycti import Channel as PyctiChannel
from pycti import (
    CustomObjectChannel,
    CustomObservableMediaContent,
)
from pycti import Identity as PyctiIdentity
from pycti import (
    OpenCTIConnectorHelper,
)
from pycti import StixCoreRelationship as PyctiSCR
from pycti import (
    get_config_variable,
)

# Batching knobs for ``_maybe_flush_bundle`` — we deliberately do NOT
# initiate one OpenCTI Work per Matrix event (which can be very noisy
# on active rooms). Instead the connector buffers up to
# ``_FLUSH_BATCH_SIZE`` STIX objects, or up to ``_FLUSH_INTERVAL_SECONDS``
# of wall-clock time, before opening + closing a single Work.
_FLUSH_BATCH_SIZE = 25
_FLUSH_INTERVAL_SECONDS = 30.0

# A flush that fails ``_MAX_FLUSH_FAILURES`` times in a row is assumed
# to be triggered by a poison object in the buffer; the buffer is then
# dropped (with a loud log line) so a single malformed event cannot
# pollute the OpenCTI work queue indefinitely.
_MAX_FLUSH_FAILURES = 3

# Event types the connector subscribes to.
_TEXT_EVENTS = (RoomMessageText, RoomMessageNotice)
_ENCRYPTED_FILE_EVENTS = (
    RoomEncryptedImage,
    RoomEncryptedFile,
    RoomEncryptedAudio,
    RoomEncryptedVideo,
)
_PLAIN_FILE_EVENTS = (
    RoomMessageImage,
    RoomMessageFile,
    RoomMessageAudio,
    RoomMessageVideo,
)
_ALL_EVENT_CLASSES = (
    *_TEXT_EVENTS,
    *_ENCRYPTED_FILE_EVENTS,
    *_PLAIN_FILE_EVENTS,
    RoomMessageUnknown,
    UnknownEvent,
)


def _load_config() -> Dict[str, Any]:
    """Return the connector configuration.

    When ``src/config.yml`` is present (next to ``main.py``) it is parsed
    with :func:`yaml.safe_load`. Otherwise an empty mapping is returned and
    :class:`OpenCTIConnectorHelper` falls back to environment variables.
    """
    config_file_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "config.yml"
    )
    if not os.path.isfile(config_file_path):
        return {}
    with open(config_file_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _coerce_bool(value: Any, *, default: bool) -> bool:
    """Return a sane :class:`bool` from a user-provided value."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalised = value.strip().lower()
        if normalised in ("true", "1", "yes", "on"):
            return True
        if normalised in ("false", "0", "no", "off", ""):
            return False
    return default


class MatrixConnector:
    """OpenCTI external-import connector that streams Matrix events."""

    def __init__(self) -> None:
        config = _load_config()
        self.helper = OpenCTIConnectorHelper(config)

        self.matrix_server: str = self._require_string(
            config, "MATRIX_SERVER", ["matrix", "server"]
        )
        self.matrix_user_id: str = self._require_string(
            config, "MATRIX_USER_ID", ["matrix", "user_id"]
        )
        self.matrix_password: str = self._require_string(
            config, "MATRIX_PASSWORD", ["matrix", "password"]
        )
        self.matrix_device_name: str = get_config_variable(
            "MATRIX_DEVICE_NAME",
            ["matrix", "device_name"],
            config,
            default="octi_bot",
        )
        tlp_name = get_config_variable(
            "MATRIX_TLP", ["matrix", "tlp"], config, default="AMBER"
        )
        # ``resolve_tlp`` returns the full ``stix2.MarkingDefinition``
        # so we can both (1) reference it from ``object_marking_refs``
        # via its canonical id and (2) ship the marking object itself
        # in every flushed bundle, which is what registers the
        # OpenCTI-specific markings (``TLP:CLEAR``, ``TLP:AMBER+STRICT``)
        # with the platform — they are not built-in stix2 constants.
        self.matrix_marking: stix2.MarkingDefinition = resolve_tlp(tlp_name)
        self.matrix_marking_id: str = self.matrix_marking.id
        self.matrix_debug: bool = _coerce_bool(
            get_config_variable(
                "MATRIX_DEBUG",
                ["matrix", "debug"],
                config,
                default=False,
            ),
            default=False,
        )
        if self.matrix_debug:
            # Promote matrix-nio's loggers (HTTP, WebSocket, crypto, ...)
            # to DEBUG so operators get the verbose protocol traces
            # advertised by ``MATRIX_DEBUG`` in the README.
            for logger_name in ("nio", "nio.client", "nio.crypto", "nio.http"):
                logging.getLogger(logger_name).setLevel(logging.DEBUG)
        self.matrix_store_path: str = get_config_variable(
            "MATRIX_STORE_PATH",
            ["matrix", "store_path"],
            config,
            default=None,
        ) or os.path.join(os.path.dirname(os.path.abspath(__file__)), "store")
        os.makedirs(self.matrix_store_path, exist_ok=True)

        # NEVER log the password.
        self.helper.log_debug(
            "MatrixConnector initialised for user "
            f"{self.matrix_user_id} on {self.matrix_server} "
            f"(device={self.matrix_device_name}, debug={self.matrix_debug})"
        )

        self.client_config = AsyncClientConfig(
            store=store.SqliteStore,
            max_limit_exceeded=0,
            max_timeouts=0,
            store_sync_tokens=True,
            encryption_enabled=True,
        )
        self.bundle: List[Any] = []
        self.client: Optional[AsyncClient] = None
        # ``_maybe_flush_bundle`` tracks the last flush so we can
        # batch many events into a single OpenCTI Work.
        self._last_flush_ts: float = time.monotonic()
        # Serialises concurrent flush attempts (the size-triggered
        # flush from ``_on_event`` vs. the time-triggered flush from
        # the periodic background task) so two concurrent
        # ``initiate_work`` / ``send_stix2_bundle`` calls do not race
        # on the same buffer.
        self._flush_lock: asyncio.Lock = asyncio.Lock()
        # Consecutive flush failure counter — see ``_MAX_FLUSH_FAILURES``.
        self._consecutive_failures: int = 0
        # Background task that drains the buffer when the room is
        # quiet (no incoming event triggers ``_maybe_flush_bundle``).
        self._periodic_flush_task: Optional[asyncio.Task] = None
        # In-memory caches of the deterministic Channel / Identity
        # standard ids we have already emitted in this connector
        # lifetime, so ``_on_event`` no longer issues a synchronous
        # OpenCTI HTTP ``list()`` call per Matrix event (which would
        # stall the asyncio loop driving ``sync_forever``). The
        # platform dedups SCOs / SDOs by ``standard_id`` on
        # ingestion, so re-emitting an already-known Channel / Identity
        # in a different bundle is harmless — we just avoid doing it.
        self._known_channel_ids: set[str] = set()
        self._known_author_ids: set[str] = set()

    @staticmethod
    def _require_string(config: Dict[str, Any], env_name: str, path: List[str]) -> str:
        value = get_config_variable(env_name, path, config, default=None)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{env_name} is required and must be a non-empty string.")
        return value.strip()

    # ------------------------------------------------------------------
    # Bundle helpers
    # ------------------------------------------------------------------
    async def _maybe_flush_bundle(self) -> None:
        """Flush the buffer when it is large enough *or* old enough.

        Matrix events arrive asynchronously and can be very frequent
        on active rooms. Flushing once per event would create one
        OpenCTI Work record per Matrix message, which becomes very
        noisy and puts unnecessary load on the platform. Instead we
        buffer up to ``_FLUSH_BATCH_SIZE`` objects or wait at most
        ``_FLUSH_INTERVAL_SECONDS`` seconds between flushes.
        """
        if not self.bundle:
            return
        elapsed = time.monotonic() - self._last_flush_ts
        if len(self.bundle) >= _FLUSH_BATCH_SIZE or elapsed >= _FLUSH_INTERVAL_SECONDS:
            await self._flush_bundle()

    async def _flush_bundle(self) -> None:
        """Send the buffered STIX objects to OpenCTI via a thread executor.

        ``OpenCTIConnectorHelper.api`` and ``send_stix2_bundle`` are
        synchronous HTTP calls; running them directly from the async
        ``_on_event`` callback would stall the asyncio loop driving
        ``sync_forever``. The actual HTTP work therefore runs in a
        thread executor via :func:`asyncio.to_thread`.

        ``_flush_lock`` serialises concurrent flush attempts (size
        trigger vs. periodic-task trigger) so two callers do not race
        on the same buffer. The OpenCTI Work is always closed: with
        ``to_processed(..., in_error=True)`` on failure or with the
        success message on success. After ``_MAX_FLUSH_FAILURES``
        consecutive failures the buffer is dropped (with a loud log
        line) so a single poison object cannot keep producing
        in-error Work records indefinitely.
        """
        async with self._flush_lock:
            if not self.bundle:
                return
            pending = self.bundle
            self.bundle = []
            try:
                await asyncio.to_thread(self._send_pending_objects, pending)
                self._consecutive_failures = 0
                # Only advance ``_last_flush_ts`` on a successful flush.
                # On failure we leave it untouched so the next periodic
                # tick can retry as soon as it fires, instead of waiting
                # another ``_FLUSH_INTERVAL_SECONDS`` window in a quiet
                # room (where the size-trigger from ``_on_event`` won't
                # fire either).
                self._last_flush_ts = time.monotonic()
            except Exception as exc:  # noqa: BLE001
                self._consecutive_failures += 1
                if self._consecutive_failures >= _MAX_FLUSH_FAILURES:
                    self.helper.log_error(
                        f"Dropping {len(pending)} buffered STIX objects "
                        f"after {self._consecutive_failures} consecutive "
                        f"flush failures (last error: {exc})."
                    )
                    # Forget every Channel / Identity SDO that lived
                    # **only** in the dropped batch. Without this, the
                    # in-memory ``_known_*`` caches still consider those
                    # ids ``known`` after the SDOs themselves have been
                    # silently dropped, so the next ``_ensure_channel``
                    # / ``_ensure_author`` call for the same room /
                    # sender would short-circuit and **not** re-emit
                    # the SDO — and the next flushed bundle would carry
                    # media-content / relationships that reference ids
                    # the platform has never ingested.
                    self._forget_dropped_known_ids(pending)
                    self._consecutive_failures = 0
                    # The poison batch has been dropped; treat that as
                    # "we made progress" so the timer restarts here.
                    self._last_flush_ts = time.monotonic()
                else:
                    # Put the failed batch back at the front of the
                    # buffer so the next flush cycle retries it. Newer
                    # events that arrived during the failed send remain
                    # at the end of the buffer. ``_last_flush_ts`` is
                    # **not** updated, so the next periodic tick fires
                    # at the originally-scheduled time and retries
                    # without waiting another full interval.
                    self.bundle = pending + self.bundle
                    self.helper.log_warning(
                        f"Flush failed (attempt {self._consecutive_failures}/"
                        f"{_MAX_FLUSH_FAILURES}); will retry on the next "
                        f"flush cycle: {exc}"
                    )

    def _forget_dropped_known_ids(self, pending: List[Any]) -> None:
        """Prune ``_known_channel_ids`` / ``_known_author_ids`` after a drop.

        Called from :meth:`_flush_bundle` when a batch is discarded
        after ``_MAX_FLUSH_FAILURES`` consecutive flush failures.
        Any Channel / Identity SDO present in the dropped batch was
        only ever emitted into the buffer once (the in-memory caches
        guarantee at-most-once emission per connector lifetime), so
        if the batch never reaches OpenCTI we must forget those ids
        too — otherwise the next event from the same room / sender
        finds the id in ``_known_*``, skips the SDO re-emission, and
        the next flushed bundle ends up carrying media-content /
        relationships that reference a Channel / Identity id the
        platform has never ingested (silent dangling references).

        We only remove ids that are currently in the caches; any
        Channel / Identity SDO that was *also* emitted in a previous
        successful flush stays known (the platform already has it).
        """
        for obj in pending:
            stix_id = getattr(obj, "id", None)
            if not stix_id:
                continue
            stix_type = getattr(obj, "type", None)
            if stix_type == "channel":
                self._known_channel_ids.discard(stix_id)
            elif stix_type == "identity":
                self._known_author_ids.discard(stix_id)

    def _send_pending_objects(self, pending: List[Any]) -> None:
        """Synchronous OpenCTI HTTP work called via :func:`asyncio.to_thread`.

        Raising propagates the failure to the caller, which adjusts the
        consecutive-failure counter and decides whether to retry or to
        drop the batch.

        The connector does **not** persist any cursor state: the Matrix
        sync token is owned by ``matrix-nio``'s SQLite store (see
        ``MATRIX_STORE_PATH``), so writing a ``last_run`` timestamp on
        every batch would only add a helper round-trip per flush
        without giving us anything to resume from. The Work record
        itself records the time of every successful send.
        """
        now = datetime.now(tz=timezone.utc)
        friendly_name = f"{self.helper.connect_name} run @ " + now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        # Prepend the configured marking-definition object so the
        # OpenCTI-specific markings (``TLP:CLEAR``, ``TLP:AMBER+STRICT``)
        # are registered with the platform alongside the data that
        # references them, instead of being left as dangling references.
        # Built-in stix2 markings (``TLP_WHITE`` / ``TLP_GREEN`` /
        # ``TLP_AMBER`` / ``TLP_RED``) are already known to the
        # platform but emitting them explicitly is harmless and keeps
        # the contract uniform across every supported alias.
        objects = [self.matrix_marking, *pending]
        objects_count = len(objects)
        try:
            bundle = stix2.Bundle(objects=objects, allow_custom=True).serialize()
            self.helper.log_info(f"Sending {objects_count} STIX objects to OpenCTI...")
            self.helper.send_stix2_bundle(
                bundle,
                update=True,
                work_id=work_id,
            )
        except Exception as exc:  # noqa: BLE001
            self.helper.log_error(
                f"Bundle send failed ({objects_count} objects): {exc}"
            )
            try:
                self.helper.api.work.to_processed(
                    work_id,
                    f"Bundle send failed: {exc}",
                    in_error=True,
                )
            except Exception as report_exc:  # noqa: BLE001
                self.helper.log_error(
                    f"Could not mark work {work_id} as failed: {report_exc}"
                )
            raise

        message = (
            f"{self.helper.connect_name} connector successfully sent "
            f"{objects_count} STIX objects."
        )
        self.helper.log_info(message)
        # ``send_stix2_bundle`` succeeded — the batch is already in
        # OpenCTI's ingestion queue. A failure to close the Work record
        # here must **not** propagate to the caller, otherwise
        # ``_flush_bundle`` would treat the whole batch as failed and
        # re-prepend it to the buffer, causing a duplicate send. Log
        # the close-failure loudly so an operator can clean up the
        # dangling in-progress Work manually.
        try:
            self.helper.api.work.to_processed(work_id, message)
        except Exception as report_exc:  # noqa: BLE001
            self.helper.log_error(
                f"Bundle was sent successfully but could not mark "
                f"work {work_id} as processed: {report_exc}"
            )

    async def _periodic_flush(self) -> None:
        """Background task that drains the buffer on a timer.

        ``_maybe_flush_bundle`` is also called from ``_on_event`` so
        active rooms see a size-triggered flush as soon as the buffer
        fills up. The periodic task covers the opposite case: a quiet
        room where events arrive in lulls, and where the buffered tail
        would otherwise wait until the next event before being sent.
        """
        while True:
            try:
                await asyncio.sleep(_FLUSH_INTERVAL_SECONDS)
                await self._maybe_flush_bundle()
            except asyncio.CancelledError:
                break
            except Exception:  # noqa: BLE001
                self.helper.log_error(traceback.format_exc())

    # ------------------------------------------------------------------
    # Matrix client + event handling
    # ------------------------------------------------------------------
    async def _download_attachment(self, url: str) -> bytes:
        """Download an attachment from the Matrix media repository."""
        assert self.client is not None
        self.helper.log_debug(f"Downloading attachment: {url}")
        response = await self.client.download(mxc=url)
        body = getattr(response, "body", None)
        if body is None:
            self.helper.log_warning(
                f"Attachment download failed for {url}: {response!r}"
            )
            return b""
        return body

    def _ensure_channel(self, room_id: str, room_name: Optional[str]) -> str:
        """Return the deterministic STIX id of the channel for ``room_id``.

        The Channel SDO is emitted into the buffer **once per connector
        lifetime** (tracked via :attr:`_known_channel_ids`); subsequent
        events in the same room only carry the deterministic
        ``standard_id`` reference. There is no OpenCTI HTTP round-trip
        per event, so the asyncio loop driving ``sync_forever`` is not
        stalled on platform latency. The platform dedups SCOs / SDOs
        by ``standard_id`` on ingestion, so if the Channel was created
        by a previous connector run (or by another tooling) the same
        deterministic id resolves to the existing SDO.

        The Channel ``name`` is the human-friendly room display name
        (with a fallback to the raw ``room_id``); the opaque
        ``room_id`` is preserved on the SDO as the description and as
        an entry in the first-class ``aliases`` field (declared on
        ``CustomObjectChannel``, indexed by OpenCTI as the canonical
        Channel-alias field — see also
        ``connectors-sdk.models.channel`` and
        ``external-import/flashpoint``) so analysts can search by
        either form. The deterministic ``standard_id`` is always
        computed from ``room_id``.
        """
        channel_id = PyctiChannel.generate_id(room_id)
        if channel_id in self._known_channel_ids:
            return channel_id
        display_name = channel_display_name(room_id, room_name)
        # Avoid carrying a redundant ``room_id`` alias when the display
        # name already collapses back to ``room_id`` (empty / missing
        # display name). The ``standard_id`` already carries the opaque
        # id so dedup is never affected.
        aliases = [room_id] if display_name != room_id else None
        channel = CustomObjectChannel(
            id=channel_id,
            name=display_name,
            description=f"Matrix room {room_id}",
            aliases=aliases,
            object_marking_refs=[self.matrix_marking_id],
            channel_types=["Matrix"],
        )
        self.bundle.append(channel)
        self._known_channel_ids.add(channel_id)
        self.helper.log_debug(
            f"Channel object queued: {channel_id} (name='{display_name}')"
        )
        return channel_id

    def _ensure_author(self, sender: str) -> str:
        """Return the deterministic STIX id of the author identity for ``sender``.

        Same rationale as :meth:`_ensure_channel`: the Identity SDO is
        emitted into the buffer once per connector lifetime, the
        deterministic ``standard_id`` is used for relationships, and
        the platform handles cross-run deduplication on ingestion.

        The Matrix sender id (e.g. ``@alice:matrix.example.org``) is
        preserved as the Identity ``name`` so the SDO is uniquely
        identifiable even when the OpenCTI tenant also contains
        manually-created identities, and is also exposed as an
        ``x_opencti_aliases`` entry so analysts can search by the
        Matrix handle.
        """
        author_id = PyctiIdentity.generate_id(sender, "individual")
        if author_id in self._known_author_ids:
            return author_id
        author = stix2.Identity(
            id=author_id,
            name=sender,
            identity_class="individual",
            description="Matrix author",
            object_marking_refs=[self.matrix_marking_id],
            allow_custom=True,
            custom_properties={"x_opencti_aliases": [sender]},
        )
        self.bundle.append(author)
        self._known_author_ids.add(author_id)
        return author_id

    def _resolve_thread_root(self, content: Dict[str, Any]) -> Optional[str]:
        """Return the deterministic STIX id of the root post for a threaded reply.

        Computes the id locally from the Matrix root event id rather
        than calling OpenCTI's ``stix_cyber_observable.list``: a URL
        lookup is non-unique once an edit (``m.replace``) reuses the
        original event id as the URL of a separate observable, and
        the previous code would silently drop the relationship as soon
        as ``len(existing) != 1``. Computing the id from the same
        ``url -> id`` recipe used everywhere else gives us a stable
        target even when the root post was ingested in a previous run.
        """
        relates = content.get("m.relates_to") or {}
        if relates.get("rel_type") != "m.thread":
            return None
        root_event_id = relates.get("event_id")
        if not root_event_id:
            return None
        return media_content_id(root_event_id)

    def _build_media_content(
        self,
        *,
        url: str,
        publication_date: datetime,
        author_id: str,
        content: str,
        description: str,
        attachments: Optional[List[Dict[str, Any]]] = None,
    ) -> Any:
        # OpenCTI extension fields on SCOs follow the canonical
        # ``x_opencti_*`` prefix (see zvelo / vulncheck / ...).
        # Setting ``created_by_ref`` directly on an SCO is ignored
        # by the ingestion path; the description likewise needs to
        # go through ``x_opencti_description``.
        custom: Dict[str, Any] = {
            "x_opencti_created_by_ref": author_id,
            "x_opencti_description": description,
        }
        if attachments:
            custom["x_opencti_files"] = attachments
        return CustomObservableMediaContent(
            url=url,
            content=content,
            publication_date=publication_date,
            media_category="matrix",
            object_marking_refs=[self.matrix_marking_id],
            allow_custom=True,
            custom_properties=custom,
        )

    def _build_relationship(self, source_id: str, target_id: str) -> Any:
        return stix2.Relationship(
            id=PyctiSCR.generate_id("related-to", source_id, target_id, None, None),
            relationship_type="related-to",
            source_ref=source_id,
            target_ref=target_id,
            object_marking_refs=[self.matrix_marking_id],
        )

    async def _decrypt_attachment(self, event: Any) -> Optional[Dict[str, Any]]:
        """Download and decrypt an encrypted Matrix attachment."""
        media_data = await self._download_attachment(event.url)
        if not media_data:
            return None
        file_meta = event.source["content"].get("file") or {}
        try:
            decrypted = crypto.attachments.decrypt_attachment(
                media_data,
                file_meta["key"]["k"],
                file_meta["hashes"]["sha256"],
                file_meta["iv"],
            )
        except (KeyError, ValueError, TypeError) as exc:
            self.helper.log_warning(
                f"Could not decrypt attachment for event {event.event_id}: {exc}"
            )
            return None
        content = event.source.get("content", {})
        return {
            "name": content.get("body", event.event_id),
            "data": base64.b64encode(decrypted).decode("ascii"),
            "mime_type": (content.get("info") or {}).get("mimetype", ""),
        }

    async def _plain_attachment(self, event: Any) -> Optional[Dict[str, Any]]:
        """Download a plain (unencrypted) Matrix attachment."""
        media_data = await self._download_attachment(event.url)
        if not media_data:
            return None
        content = event.source.get("content", {})
        return {
            "name": content.get("body", event.event_id),
            "data": base64.b64encode(media_data).decode("ascii"),
            "mime_type": (content.get("info") or {}).get("mimetype", ""),
        }

    async def _on_event(self, room: Any, event: Any) -> None:
        """Handle an event delivered by ``AsyncClient.sync_forever``."""
        try:
            self.helper.log_debug(
                f"Event {event.event_id} in room {room.room_id} "
                f"({room.display_name}) ts={event.server_timestamp}"
            )

            # We defer the ``_ensure_channel`` / ``_ensure_author`` calls
            # until after the supported-event-type check below. Building
            # the publication date first costs nothing but lets us bail
            # on unknown event types before allocating Channel / Identity
            # SDOs that the buffer would otherwise carry around for an
            # event that never produces a ``media-content`` observable.
            publication_date = publication_date_from_event(
                event, self.helper.log_warning
            )
            sender = event.sender
            room_id = room.room_id
            room_name = room.display_name
            content_data = event.source.get("content") or {}
            thread_root = self._resolve_thread_root(content_data)

            media_content: Optional[Any] = None
            author_id: Optional[str] = None
            channel_id: Optional[str] = None

            edit_target_event_id: Optional[str] = None
            if isinstance(event, _TEXT_EVENTS):
                # Only build the Channel / Identity SDOs when we are
                # certain the event will produce a ``media-content``
                # observable. For unknown / unsupported event types we
                # bail in the ``else`` branch below without polluting
                # the buffer (and the in-memory caches) with orphan
                # SDOs.
                channel_id = self._ensure_channel(room_id, room_name)
                author_id = self._ensure_author(sender)
                relates = content_data.get("m.relates_to") or {}
                is_edit = (
                    "m.new_content" in content_data
                    and relates.get("rel_type") == "m.replace"
                )
                if is_edit:
                    # An edit (``m.replace``) becomes its **own**
                    # ``media-content`` observable keyed by its own
                    # event id, plus a ``related-to`` relationship to
                    # the original post. This preserves the original
                    # message body in OpenCTI (the previous behaviour
                    # reused the original event id as the edit's URL,
                    # which silently overwrote the original observable
                    # with the new content because OpenCTI dedups SCOs
                    # by their URL-derived ``standard_id``).
                    edit_target_event_id = relates.get("event_id")
                    description = (event.body or "") + "\n\n[updated]"
                else:
                    description = event.body or ""
                media_content = self._build_media_content(
                    url=event.event_id,
                    publication_date=publication_date,
                    author_id=author_id,
                    content=event.body or "",
                    description=description,
                )
            elif isinstance(event, _ENCRYPTED_FILE_EVENTS):
                attachment = await self._decrypt_attachment(event)
                if attachment is not None:
                    # Decryption succeeded — emit the Channel / Identity
                    # SDOs only now that we know we will produce a
                    # ``media-content`` observable.
                    channel_id = self._ensure_channel(room_id, room_name)
                    author_id = self._ensure_author(sender)
                    media_content = self._build_media_content(
                        url=event.event_id,
                        publication_date=publication_date,
                        author_id=author_id,
                        content=content_data.get("body", ""),
                        description=content_data.get("body", ""),
                        attachments=[attachment],
                    )
            elif isinstance(event, _PLAIN_FILE_EVENTS):
                attachment = await self._plain_attachment(event)
                if attachment is not None:
                    channel_id = self._ensure_channel(room_id, room_name)
                    author_id = self._ensure_author(sender)
                    media_content = self._build_media_content(
                        url=event.event_id,
                        publication_date=publication_date,
                        author_id=author_id,
                        content=content_data.get("body", ""),
                        description=content_data.get("body", ""),
                        attachments=[attachment],
                    )
            else:
                self.helper.log_debug(
                    f"Ignoring unsupported event type: {type(event).__name__}"
                )
                return

            if media_content is None:
                # Attachment download / decryption failed (the unknown
                # event branch above already returned). Because the
                # Channel / Identity SDOs are now only emitted inside
                # the ``if attachment is not None`` branches, we have
                # nothing extra to roll back here — the buffer is
                # untouched and other rooms' batches are preserved.
                return

            self.bundle.append(media_content)
            self.bundle.append(
                self._build_relationship(media_content["id"], channel_id)
            )
            if thread_root:
                self.bundle.append(
                    self._build_relationship(media_content["id"], thread_root)
                )
            if edit_target_event_id:
                # Link the new edit observable back to the original post
                # so operators can navigate from one to the other in
                # OpenCTI without losing the original message body.
                self.bundle.append(
                    self._build_relationship(
                        media_content["id"],
                        media_content_id(edit_target_event_id),
                    )
                )
            await self._maybe_flush_bundle()
        except asyncio.CancelledError:
            # Let cancellation propagate so the sync loop can shut down.
            raise
        except Exception:  # noqa: BLE001 - log unexpected errors and continue
            self.helper.log_error(traceback.format_exc())

    async def run_client(self) -> None:
        self.helper.log_info("Creating Matrix client...")
        self.client = AsyncClient(
            homeserver=self.matrix_server,
            user=self.matrix_user_id,
            store_path=self.matrix_store_path,
            config=self.client_config,
        )
        self.helper.log_info("Logging in to Matrix...")
        await self.client.login(
            password=self.matrix_password,
            device_name=self.matrix_device_name,
            token=None,
        )
        self.client.load_store()
        if self.client.should_upload_keys:
            self.helper.log_info("Uploading device keys...")
            await self.client.keys_upload()
        self.client.add_event_callback(self._on_event, _ALL_EVENT_CLASSES)
        # Background task that drains the buffer on a timer so quiet
        # rooms don't keep events pending until the next message.
        self._periodic_flush_task = asyncio.create_task(self._periodic_flush())
        self.helper.log_info("Starting sync_forever...")
        try:
            await self.client.sync_forever(full_state=True)
        finally:
            # Stop the background flush task first so it does not
            # race with the final shutdown drain below.
            if self._periodic_flush_task is not None:
                self._periodic_flush_task.cancel()
                try:
                    await self._periodic_flush_task
                except asyncio.CancelledError:
                    pass
                self._periodic_flush_task = None
            # Drain any buffered events before shutting the client so
            # a SIGTERM / Ctrl-C does not lose the tail of the batch.
            try:
                await self._flush_bundle()
            except Exception as exc:  # noqa: BLE001
                self.helper.log_error(f"Final flush failed during shutdown: {exc}")
            await self.client.close()


def _run() -> None:
    try:
        asyncio.run(MatrixConnector().run_client())
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:  # noqa: BLE001 - last-resort safety net
        # Use ``traceback.print_exc`` so the full traceback is preserved
        # (instead of the bare ``str(exc)`` from ``print(exc)``). The
        # ``OpenCTIConnectorHelper`` logger may not be reachable here
        # (the helper itself may have failed to initialise), so we fall
        # back to stderr — which Docker / systemd / Kubernetes capture
        # the same way as the helper's logs.
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)


if __name__ == "__main__":
    _run()
