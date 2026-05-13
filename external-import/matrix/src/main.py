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
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import stix2
import yaml
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

# ``stix2`` exposes constants for TLP_WHITE / GREEN / AMBER / RED. AMBER+STRICT
# is an OpenCTI-specific marking and is not exported as a constant, so we keep
# its canonical id here.
_TLP_AMBER_STRICT_ID = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"

_TLP_MAP: Dict[str, str] = {
    "CLEAR": stix2.TLP_WHITE.id,
    "WHITE": stix2.TLP_WHITE.id,
    "GREEN": stix2.TLP_GREEN.id,
    "AMBER": stix2.TLP_AMBER.id,
    "AMBER_STRICT": _TLP_AMBER_STRICT_ID,
    "AMBER+STRICT": _TLP_AMBER_STRICT_ID,
    "RED": stix2.TLP_RED.id,
}

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


def _resolve_tlp(name: str) -> str:
    """Return the marking-definition id for ``name`` (case-insensitive)."""
    normalised = (name or "").strip().upper().replace(" ", "_")
    try:
        return _TLP_MAP[normalised]
    except KeyError as exc:
        valid = ", ".join(sorted({"CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"}))
        raise ValueError(
            f"Unsupported MATRIX_TLP value '{name}'. Expected one of {valid}."
        ) from exc


def _list_filter(field: str, value: str) -> Dict[str, Any]:
    """Build a filter compatible with the modern OpenCTI API."""
    return {
        "mode": "and",
        "filters": [
            {
                "key": field,
                "values": [value],
                "operator": "eq",
                "mode": "and",
            }
        ],
        "filterGroups": [],
    }


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
        self.matrix_device_name: str = (
            get_config_variable(
                "MATRIX_DEVICE_NAME",
                ["matrix", "device_name"],
                config,
                default="octi_bot",
            )
            or "octi_bot"
        )
        tlp_name = (
            get_config_variable(
                "MATRIX_TLP", ["matrix", "tlp"], config, default="AMBER"
            )
            or "AMBER"
        )
        self.matrix_marking_id = _resolve_tlp(tlp_name)
        self.matrix_debug: bool = _coerce_bool(
            get_config_variable(
                "MATRIX_DEBUG",
                ["matrix", "debug"],
                config,
                default=False,
            ),
            default=False,
        )
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

    @staticmethod
    def _require_string(config: Dict[str, Any], env_name: str, path: List[str]) -> str:
        value = get_config_variable(env_name, path, config, default=None)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{env_name} is required and must be a non-empty string.")
        return value.strip()

    # ------------------------------------------------------------------
    # Bundle helpers
    # ------------------------------------------------------------------
    def _flush_bundle(self) -> None:
        """Send the buffered STIX objects to OpenCTI and reset the buffer."""
        if not self.bundle:
            return

        now = datetime.now(tz=timezone.utc)
        friendly_name = f"{self.helper.connect_name} run @ " + now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        bundle = stix2.Bundle(objects=self.bundle, allow_custom=True).serialize()
        self.helper.log_info(f"Sending {len(self.bundle)} STIX objects to OpenCTI...")
        self.helper.send_stix2_bundle(
            bundle,
            update=True,
            work_id=work_id,
        )

        timestamp = int(time.time())
        message = (
            f"{self.helper.connect_name} connector successfully run, "
            f"storing last_run as {timestamp}"
        )
        self.helper.log_info(message)
        current_state = self.helper.get_state() or {}
        current_state["last_run"] = timestamp
        self.helper.set_state(current_state)
        self.helper.api.work.to_processed(work_id, message)
        self.bundle = []

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

    def _ensure_channel(self, room_id: str, room_name: str) -> str:
        """Return the STIX id of the channel matching ``room_id``."""
        existing = self.helper.api.channel.list(filters=_list_filter("name", room_id))
        if existing:
            return existing[0]["standard_id"]

        channel = CustomObjectChannel(
            id=PyctiChannel.generate_id(room_id),
            name=room_id,
            description=room_name,
            object_marking_refs=[self.matrix_marking_id],
            channel_types=["Matrix"],
            allow_custom=True,
        )
        self.bundle.append(channel)
        self.helper.log_debug(f"Channel object created: {channel['id']}")
        return channel["id"]

    def _ensure_author(self, sender: str) -> str:
        """Return the STIX id of the author identity, creating it if needed."""
        identities = self.helper.api.identity.list(filters=_list_filter("name", sender))
        if identities:
            return identities[0]["standard_id"]

        author = stix2.Identity(
            id=PyctiIdentity.generate_id(sender, "individual"),
            name=sender,
            identity_class="individual",
            description="Matrix author",
            object_marking_refs=[self.matrix_marking_id],
        )
        self.bundle.append(author)
        return author["id"]

    def _resolve_thread_root(self, content: Dict[str, Any]) -> Optional[str]:
        """Return the OpenCTI STIX id of the root post for a threaded reply."""
        relates = content.get("m.relates_to") or {}
        if relates.get("rel_type") != "m.thread":
            return None
        root_event_id = relates.get("event_id")
        if not root_event_id:
            return None
        existing = self.helper.api.stix_cyber_observable.list(
            filters=_list_filter("url", root_event_id)
        )
        if len(existing) == 1:
            return existing[0]["standard_id"]
        return None

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
        custom: Dict[str, Any] = {"created_by_ref": author_id}
        if attachments:
            custom["x_opencti_files"] = attachments
        return CustomObservableMediaContent(
            url=url,
            content=content,
            description=description,
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
                f"Could not decrypt attachment for event " f"{event.event_id}: {exc}"
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

            publication_date = datetime.fromtimestamp(
                event.server_timestamp / 1000, tz=timezone.utc
            )
            sender = event.sender
            room_id = room.room_id
            room_name = room.display_name

            channel_id = self._ensure_channel(room_id, room_name)
            author_id = self._ensure_author(sender)
            content_data = event.source.get("content") or {}
            thread_root = self._resolve_thread_root(content_data)

            media_content: Optional[Any] = None

            if isinstance(event, _TEXT_EVENTS):
                relates = content_data.get("m.relates_to") or {}
                if (
                    "m.new_content" in content_data
                    and relates.get("rel_type") == "m.replace"
                ):
                    url = relates.get("event_id", event.event_id)
                    description = (event.body or "") + "\n\n[updated]"
                else:
                    url = event.event_id
                    description = event.body or ""
                media_content = self._build_media_content(
                    url=url,
                    publication_date=publication_date,
                    author_id=author_id,
                    content=event.body or "",
                    description=description,
                )
            elif isinstance(event, _ENCRYPTED_FILE_EVENTS):
                attachment = await self._decrypt_attachment(event)
                if attachment is not None:
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
                # Nothing to publish (decryption failure / empty event); drop
                # any partial bundle entries for this event before returning.
                self.bundle = []
                return

            self.bundle.append(media_content)
            self.bundle.append(
                self._build_relationship(media_content["id"], channel_id)
            )
            if thread_root:
                self.bundle.append(
                    self._build_relationship(media_content["id"], thread_root)
                )
            self._flush_bundle()
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
        self.helper.log_info("Starting sync_forever...")
        try:
            await self.client.sync_forever(full_state=True)
        finally:
            await self.client.close()


def _run() -> None:
    try:
        asyncio.run(MatrixConnector().run_client())
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001 - last-resort safety net
        print(exc)
        time.sleep(10)
        sys.exit(1)


if __name__ == "__main__":
    _run()
