import base64
import hashlib
import json
import pprint
import sys
import time
import traceback
from datetime import datetime, timezone
from typing import Optional

import lib.intel2stix
import requests
import stix2
from bs4 import BeautifulSoup
from lib.external_import import ExternalImportConnector
from lib.intel2stix import get_date
from pycti import Channel as PyctiChannel
from pycti import CustomObjectChannel as Channel
from pycti import CustomObservableMediaContent as MediaContent
from pycti import Identity as PyctiIdentity
from pycti import Incident as PyctiIncident
from pycti import Report as PyctiReport
from pycti import StixCoreRelationship as PyctiSCR
from pycti import ThreatActorIndividual as PyctiTAI
from pycti import get_config_variable
from stix2 import Identity, Incident, Relationship, Report

# Default timeout (seconds) applied to every Intel471 HTTP call so that a
# stuck network does not block the connector loop indefinitely.
_HTTP_TIMEOUT_SECONDS = 30


def _b64(payload) -> str:
    """Return a UTF-8-safe base64 string for ``x_opencti_files`` payloads.

    STIX bundles must serialise to JSON, so the ``data`` of every attached
    file has to be a *string*, not the raw ``bytes`` returned by
    :func:`base64.b64encode`.
    """
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return base64.b64encode(payload).decode("ascii")


_STIX_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def _stix_timestamp(seconds_epoch) -> str:
    """Return a STIX-compatible timestamp string for ``seconds_epoch``.

    The input matches the seconds-since-epoch value historically passed to
    ``datetime.utcfromtimestamp(...)`` by this connector. Uses a
    timezone-aware UTC datetime and avoids the private
    ``stix2.utils._TIMESTAMP_FORMAT_FRAC`` constant referenced by the
    initial version of this connector.
    """
    return datetime.fromtimestamp(seconds_epoch, tz=timezone.utc).strftime(
        _STIX_TIMESTAMP_FORMAT
    )


class Intel471AlertsConnector(ExternalImportConnector):
    def __init__(self):
        """Initialization of the connector

        Note that additional attributes for the connector can be set after the super() call.

        Standarised way to grab attributes from environment variables is as follows:

        >>>         ...
        >>>         super().__init__()
        >>>         self.my_attribute = os.environ.get("MY_ATTRIBUTE", "INFO")

        This will make use of the `os.environ.get` method to grab the environment variable and set a default value (in the example "INFO") if it is not set.
        Additional tunning can be made to the connector by adding additional environment variables.

        Raising ValueErrors or similar might be useful for tracking down issues with the connector initialization.
        """
        super().__init__()

        # Connector-specific settings are loaded through
        # ``get_config_variable`` so they honour both ``src/config.yml``
        # (nested ``intel471.*`` keys) and the documented environment
        # variables (``INTEL471_*``). The base class already loaded the
        # config in ``__init__``; we reuse the same on-disk file rather
        # than reaching into the helper's internals.
        config = self._load_config()

        self.intel471_api_url = get_config_variable(
            "INTEL471_API_URL",
            ["intel471", "api_url"],
            config,
            default="https://api.intel471.com/v1",
        )
        self.intel471_api_username = get_config_variable(
            "INTEL471_API_USERNAME",
            ["intel471", "api_username"],
            config,
        )
        self.intel471_api_key = get_config_variable(
            "INTEL471_API_KEY",
            ["intel471", "api_key"],
            config,
        )
        self.intel471_initial_history_alerts = str(
            get_config_variable(
                "INTEL471_DARKNET_INITIAL_HISTORY_ALERTS",
                ["intel471", "initial_history_alerts"],
                config,
                default="0",
            )
            or "0"
        )
        # ``object_marking_refs`` expects a *list* of marking-definition
        # references, so we store the resolved id as a one-element list.
        # Every callsite ends up writing ``object_marking_refs=self.intel471_darknet_tlp``
        # which therefore produces a valid STIX value.
        self.intel471_darknet_tlp = [
            self._get_tlp(
                get_config_variable(
                    "INTEL471_DARKNET_TLP",
                    ["intel471", "tlp"],
                    config,
                    default="AMBER",
                )
                or "AMBER"
            )
        ]
        self.intel471_watchers = {}

        # collecting watchers
        self.helper.log_debug("Collecting watcher info")
        watcher_groups = self._intel471_get_json(
            f"{self.intel471_api_url}/watcherGroups"
        )
        if watcher_groups and "watcherGroups" in watcher_groups:
            for wg in watcher_groups["watcherGroups"]:
                watchers = self._intel471_get_json(
                    f"{self.intel471_api_url}/watcherGroups/{wg['uid']}/watchers"
                )
                if not watchers or "watchers" not in watchers:
                    self.helper.log_debug(f"No watchers in group {wg['uid']}")
                    continue
                for w in watchers["watchers"]:
                    self.intel471_watchers[w["uid"]] = w["description"]
            # Only log counts here so the watcher metadata (which can carry
            # sensitive descriptions / queries) does not end up in the
            # connector logs at INFO level.
            self.helper.log_debug(
                f"Watcher collection complete: {len(self.intel471_watchers)} "
                f"watcher(s) across {len(watcher_groups['watcherGroups'])} "
                "group(s)"
            )
        else:
            self.helper.log_debug("No watcher groups returned by the API.")

        # get author id
        identity_list = self.helper.api.identity.list(
            filters={
                "mode": "and",
                "filters": {
                    "key": "name",
                    "values": "Intel 471 Inc.",
                    "operator": "eq",
                    "mode": "and",
                },
                "filterGroups": [],
            },
        )
        if len(identity_list) == 0:
            x_author = stix2.Identity(
                id=PyctiIdentity.generate_id("Intel471 Inc.", "organization"),
                name="Intel471 Inc.",
                identity_class="organization",
            )
            self.intel471_id = x_author["id"]
            self.helper.log_debug(f"x_author_id = {self.intel471_id}")
        else:
            x_author = identity_list[0]
            self.intel471_id = x_author["standard_id"]
            self.helper.log_debug(f"x_author_standard_id = {self.intel471_id}")

    _TLP_AMBER_STRICT_ID = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
    _TLP_MAP = {
        "CLEAR": stix2.TLP_WHITE.id,
        "WHITE": stix2.TLP_WHITE.id,
        "GREEN": stix2.TLP_GREEN.id,
        "AMBER": stix2.TLP_AMBER.id,
        "AMBER_STRICT": _TLP_AMBER_STRICT_ID,
        "AMBER+STRICT": _TLP_AMBER_STRICT_ID,
        "RED": stix2.TLP_RED.id,
    }

    @classmethod
    def _get_tlp(cls, tlp_string: str) -> str:
        """Return the marking-definition id for ``tlp_string``.

        Normalises case so ``amber``/``Amber``/``AMBER`` all match, and
        accepts both ``AMBER_STRICT`` and the documented ``AMBER+STRICT``
        spellings. The previous version silently mapped both ``WHITE`` and
        ``CLEAR`` (and unknown values) to ``TLP_RED`` — they now map to
        ``TLP_WHITE`` (the canonical "no restriction" marking), and
        unknown values raise a clear ``ValueError`` at startup.
        """
        normalised = (tlp_string or "").strip().upper().replace(" ", "_")
        try:
            return cls._TLP_MAP[normalised]
        except KeyError as exc:
            valid = ", ".join(
                sorted({"CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"})
            )
            raise ValueError(  # noqa: TRY003 - human-friendly startup error
                f"Unsupported INTEL471_DARKNET_TLP value '{tlp_string}'. "
                f"Expected one of {valid}."
            ) from exc

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    def _intel471_request(self, url, **kwargs):
        """Wrap :func:`requests.get` with timeout / authentication / errors."""
        kwargs.setdefault("timeout", _HTTP_TIMEOUT_SECONDS)
        kwargs.setdefault("auth", (self.intel471_api_username, self.intel471_api_key))
        try:
            response = requests.get(url, **kwargs)
            response.raise_for_status()
        except requests.RequestException as exc:
            # Never log the response body — it may contain credentials or
            # other sensitive Intel 471 data. Status code is safe.
            status = getattr(getattr(exc, "response", None), "status_code", None)
            self.helper.log_warning(
                f"Intel 471 request failed (url={url}, status={status}): {exc}"
            )
            return None
        return response

    def _intel471_get_json(self, url, **kwargs):
        """GET ``url`` and return the parsed JSON body (or ``None`` on error)."""
        response = self._intel471_request(url, **kwargs)
        if response is None or not response.content:
            return None
        try:
            return response.json()
        except json.JSONDecodeError as exc:
            self.helper.log_warning(
                f"Intel 471 returned non-JSON content for {url}: {exc}"
            )
            return None

    def _intel471_get_bytes(self, url, **kwargs):
        """GET ``url`` and return the raw bytes body (or ``None`` on error)."""
        response = self._intel471_request(url, **kwargs)
        if response is None:
            return None
        return response.content

    def _getPrivateMessageContent(self, privateMessage: dict) -> []:
        """
        Transforms a private message dictionnary in STIX content
        Returns a list of all the created STIX objects. Media content is at the beginning.
        """
        objects = []
        x_message = BeautifulSoup(privateMessage["message"], features="lxml").get_text()
        x_forum = (
            privateMessage["links"]["forum"]["name"]
            if "forum" in privateMessage["links"]
            else ""
        )
        x_thread = (
            privateMessage["links"]["thread"]["uid"]
            if "thread" in privateMessage["links"]
            else ""
        )
        x_actor = (
            privateMessage["links"]["authorActor"]["handle"]
            if "authorActor" in privateMessage["links"]
            and "handle" in privateMessage["links"]["authorActor"]
            else ""
        )
        x_recipient = (
            privateMessage["links"]["recipientActor"]["handle"]
            if "recipientActor" in privateMessage["links"]
            and "handle" in privateMessage["links"]["recipientActor"]
            else ""
        )
        if "lastUpdated" in privateMessage:
            lu = privateMessage["lastUpdated"] / 1000
            x_lastupdate = get_date(_stix_timestamp(lu))
        else:
            x_lastupdate = ""
        d = privateMessage["date"] / 1000
        x_date = _stix_timestamp(d)

        # are there some images?
        octi_filelist = []
        if "images" in privateMessage["links"]:
            forum_imagelist = privateMessage["links"]["images"]
            # self.helper.log_debug(f"Images? {forum_imagelist}")
            for f in forum_imagelist:
                try:
                    imagename = f["hash"]
                    image_bytes = self._intel471_get_bytes(f["imageOriginal"])
                    if image_bytes is None:
                        continue
                    octi_filelist.append(
                        {
                            "name": imagename,
                            "data": base64.b64encode(image_bytes).decode("ascii"),
                            "mime_type": "image/*",
                        }
                    )
                except Exception as e:
                    self.helper.log_debug(f"Adding of image failed: {e}")

        # add message textfile
        octi_filelist.append(
            {
                "name": privateMessage["uid"] + "-message.txt",
                "data": _b64(pprint.pformat(x_message)),
                "mime_type": "txt",
            }
        )
        octi_filelist.append(
            {
                "name": privateMessage["uid"] + "-json.txt",
                "data": _b64(pprint.pformat(privateMessage)),
                "mime_type": "txt",
            }
        )

        # does the sender/receiver already exist in OCTI?
        # ``x_sender_id`` / ``x_receiver_id`` track *real* identity ids; the
        # ``created_by_ref`` placed on ``MediaContent`` falls back to the
        # connector author when no sender identity could be extracted so it
        # is always a valid STIX reference.
        x_sender_id = ""
        x_receiver_id = ""
        if x_actor:
            identity_list = self.helper.api.identity.list(
                filters={
                    "mode": "and",
                    "filters": {
                        "key": "name",
                        "values": x_actor,
                        "operator": "eq",
                        "mode": "and",
                    },
                    "filterGroups": [],
                },
            )
            if len(identity_list) == 0:
                x_sender = Identity(
                    id=PyctiIdentity.generate_id(
                        lib.intel2stix.sanitizeName(x_actor), "individual"
                    ),
                    name=lib.intel2stix.sanitizeName(x_actor),
                    object_marking_refs=self.intel471_darknet_tlp,
                    identity_class="individual",
                    created_by_ref=self.intel471_id,
                    description="Private Message Author",
                )
                x_sender_id = x_sender["id"]
                objects.append(x_sender)
            else:
                x_sender = identity_list[0]
                x_sender_id = x_sender["standard_id"]
        if x_recipient:
            identity_list = self.helper.api.identity.list(
                filters={
                    "mode": "and",
                    "filters": {
                        "key": "name",
                        "values": x_recipient,
                        "operator": "eq",
                        "mode": "and",
                    },
                    "filterGroups": [],
                },
            )
            if len(identity_list) == 0:
                x_receiver = Identity(
                    id=PyctiIdentity.generate_id(
                        lib.intel2stix.sanitizeName(x_recipient), "individual"
                    ),
                    name=lib.intel2stix.sanitizeName(x_recipient),
                    object_marking_refs=self.intel471_darknet_tlp,
                    identity_class="individual",
                    created_by_ref=self.intel471_id,
                    description="Private Message Author",
                )
                x_receiver_id = x_receiver["id"]
                objects.append(x_receiver)
            else:
                x_receiver = identity_list[0]
                x_receiver_id = x_receiver["standard_id"]

        # channel creation
        channel_id = ""
        if x_thread:
            channel_list = self.helper.api.channel.list(
                filters={
                    "mode": "and",
                    "filters": {
                        "key": "name",
                        "values": x_thread,
                        "operator": "eq",
                        "mode": "and",
                    },
                    "filterGroups": [],
                },
            )
            if len(channel_list) == 0:
                x_channel = Channel(
                    id=PyctiChannel.generate_id(x_thread),
                    name=x_thread,
                    object_marking_refs=self.intel471_darknet_tlp,
                    created_by_ref=self.intel471_id,
                    channel_types=[x_forum],
                    allow_custom=True,
                )
                self.helper.log_debug("Channel object created.")
                objects.append(x_channel)
                self.helper.log_debug("Channel object added to bundle.")
                channel_id = x_channel["id"]
            else:
                channel_id = channel_list[0]["standard_id"]

        # content creation
        x_mc_description = (
            f"### Forum\n\n{x_forum}\n\n"
            f"### Sender\n\n{x_actor}\n\n"
            f"### Receiver\n\n{x_recipient}\n\n"
            f"### Last update\n\n{x_lastupdate}\n\n"
        )
        x_media_content = MediaContent(
            url=hashlib.md5(bytes(pprint.pformat(privateMessage), "utf-8")).hexdigest(),
            content=x_message,
            description=x_mc_description,
            publication_date=x_date,
            media_category="private forum message",
            object_marking_refs=self.intel471_darknet_tlp,
            allow_custom=True,
            custom_properties={
                "created_by_ref": x_sender_id or self.intel471_id,
                "x_opencti_files": octi_filelist,
            },
        )
        objects.insert(0, x_media_content)

        # relationships
        if channel_id:
            x_relationship = Relationship(
                id=PyctiSCR.generate_id(
                    "related-to", x_media_content["id"], channel_id, None, None
                ),
                relationship_type="related-to",
                source_ref=x_media_content["id"],
                target_ref=channel_id,
                created_by_ref=self.intel471_id,
                object_marking_refs=self.intel471_darknet_tlp,
            )
            objects.append(x_relationship)
        if x_sender_id and x_receiver_id:
            x_relationship = Relationship(
                id=PyctiSCR.generate_id(
                    "related-to", x_sender_id, x_receiver_id, None, None
                ),
                relationship_type="related-to",
                source_ref=x_sender_id,
                target_ref=x_receiver_id,
                created_by_ref=self.intel471_id,
                object_marking_refs=self.intel471_darknet_tlp,
            )
            objects.append(x_relationship)
            x_relationship = Relationship(
                id=PyctiSCR.generate_id(
                    "related-to", x_media_content["id"], x_sender_id, None, None
                ),
                relationship_type="related-to",
                source_ref=x_media_content["id"],
                target_ref=x_sender_id,
                created_by_ref=self.intel471_id,
                object_marking_refs=self.intel471_darknet_tlp,
            )
            objects.append(x_relationship)
            x_relationship = Relationship(
                id=PyctiSCR.generate_id(
                    "related-to", x_media_content["id"], x_receiver_id, None, None
                ),
                relationship_type="related-to",
                source_ref=x_media_content["id"],
                target_ref=x_receiver_id,
                created_by_ref=self.intel471_id,
                object_marking_refs=self.intel471_darknet_tlp,
            )
            objects.append(x_relationship)

        return objects

    def _getPostContent(self, post: dict) -> []:
        """
        Transforms a post message dictionnary in STIX content
        Returns a list of all the created STIX objects. Media content is at the beginning.
        """
        objects = []
        x_message = BeautifulSoup(post["message"], "lxml").get_text()
        x_actor = (
            post["links"]["authorActor"]["handle"]
            if "authorActor" in post["links"]
            else ""
        )
        x_forum = post["links"]["forum"]["name"] if "forum" in post["links"] else ""
        if "thread" in post["links"]:
            x_thread = (
                post["links"]["thread"]["topic"]
                if "topic" in post["links"]["thread"]
                else post["links"]["thread"]["uid"]
            )
        else:
            x_thread = ""
        if "lastUpdated" in post:
            lu = post["lastUpdated"] / 1000
            x_lastupdate = get_date(_stix_timestamp(lu))
        else:
            x_lastupdate = ""
        d = post["date"] / 1000
        x_date = _stix_timestamp(d)

        # are there some images?
        octi_filelist = []
        if "images" in post["links"]:
            forum_imagelist = post["links"]["images"]
            # self.helper.log_debug(f"Images? {forum_imagelist}")
            for f in forum_imagelist:
                try:
                    imagename = f["hash"]
                    image_bytes = self._intel471_get_bytes(f["imageOriginal"])
                    if image_bytes is None:
                        continue
                    octi_filelist.append(
                        {
                            "name": imagename,
                            "data": base64.b64encode(image_bytes).decode("ascii"),
                            "mime_type": "image/*",
                        }
                    )
                except Exception as e:
                    self.helper.log_debug(f"Adding of image failed: {e}")

        # add message textfile
        octi_filelist.append(
            {
                "name": post["uid"] + "-message.txt",
                "data": _b64(pprint.pformat(x_message)),
                "mime_type": "txt",
            }
        )
        octi_filelist.append(
            {
                "name": post["uid"] + "-json.txt",
                "data": _b64(pprint.pformat(post)),
                "mime_type": "txt",
            }
        )

        # does the author already exist in OCTI?
        x_author_id = ""
        if x_actor:
            identity_list = self.helper.api.identity.list(
                filters={
                    "mode": "and",
                    "filters": {
                        "key": "name",
                        "values": x_actor,
                        "operator": "eq",
                        "mode": "and",
                    },
                    "filterGroups": [],
                },
            )
            if len(identity_list) == 0:
                x_author = Identity(
                    id=PyctiIdentity.generate_id(
                        lib.intel2stix.sanitizeName(x_actor), "individual"
                    ),
                    name=lib.intel2stix.sanitizeName(x_actor),
                    object_marking_refs=self.intel471_darknet_tlp,
                    identity_class="individual",
                    created_by_ref=self.intel471_id,
                    description="Forum Author",
                )
                x_author_id = x_author["id"]
                objects.append(x_author)
            else:
                x_author = identity_list[0]
                x_author_id = x_author["standard_id"]

        # channel creation
        channel_id = ""
        if x_thread:
            channel_list = self.helper.api.channel.list(
                filters={
                    "mode": "and",
                    "filters": {
                        "key": "name",
                        "values": x_thread,
                        "operator": "eq",
                        "mode": "and",
                    },
                    "filterGroups": [],
                },
            )
            if len(channel_list) == 0:
                x_channel = Channel(
                    id=PyctiChannel.generate_id(x_thread),
                    name=x_thread,
                    object_marking_refs=self.intel471_darknet_tlp,
                    created_by_ref=self.intel471_id,
                    channel_types=[x_forum],
                    allow_custom=True,
                )
                self.helper.log_debug("Channel object created.")
                objects.append(x_channel)
                self.helper.log_debug("Channel object added to bundle.")
                channel_id = x_channel["id"]
            else:
                channel_id = channel_list[0]["standard_id"]

        # content creation
        x_mc_description = (
            f"### Forum\n\n{x_forum}\n\n"
            f"### Thread\n\n{x_thread}\n\n"
            f"### Last update\n\n{x_lastupdate}\n\n"
        )
        x_media_content = MediaContent(
            url=post["uid"],
            content=x_message,
            description=x_mc_description,
            publication_date=x_date,
            media_category="forum post",
            object_marking_refs=self.intel471_darknet_tlp,
            allow_custom=True,
            custom_properties={
                "created_by_ref": x_author_id or self.intel471_id,
                "x_opencti_files": octi_filelist,
            },
        )
        objects.insert(0, x_media_content)

        # relationships
        if channel_id:
            x_relationship = Relationship(
                id=PyctiSCR.generate_id(
                    "related-to", x_media_content["id"], channel_id, None, None
                ),
                relationship_type="related-to",
                source_ref=x_media_content["id"],
                target_ref=channel_id,
                created_by_ref=self.intel471_id,
                object_marking_refs=self.intel471_darknet_tlp,
            )
            objects.append(x_relationship)
        if x_author_id:
            x_relationship = Relationship(
                id=PyctiSCR.generate_id(
                    "related-to", x_media_content["id"], x_author_id, None, None
                ),
                relationship_type="related-to",
                source_ref=x_media_content["id"],
                target_ref=x_author_id,
                created_by_ref=self.intel471_id,
                object_marking_refs=self.intel471_darknet_tlp,
            )
            objects.append(x_relationship)

        return objects

    def _getInstantMessageContent(self, instantMessage: dict) -> []:
        """
        Transforms an instant message dictionnary in STIX content.
        Returns a list of all the created STIX objects. Instant message content is at the beginning.
        """
        objects = []
        x_message = BeautifulSoup(
            instantMessage["data"]["message"]["text"], features="lxml"
        ).get_text()
        x_channel_name = instantMessage["data"]["channel"]["name"]
        x_channel_url = instantMessage["data"]["channel"]["url"]
        x_server = instantMessage["data"]["server"]["service_type"]
        x_actor = instantMessage["data"]["actor"]["handle"]
        d = (
            instantMessage["activity"]["first"] / 1000
            if "first" in instantMessage["activity"]
            else 0
        )
        x_date = _stix_timestamp(d)
        lu = instantMessage["last_updated"] / 1000
        x_lastupdate = get_date(_stix_timestamp(lu))

        # add message textfile
        octi_filelist = [
            {
                "name": "message.txt",
                "data": _b64(pprint.pformat(x_message)),
                "mime_type": "txt",
            }
        ]
        octi_filelist.append(
            {
                "name": "json.txt",
                "data": _b64(pprint.pformat(instantMessage)),
                "mime_type": "txt",
            }
        )

        # does the author already exist in OCTI?
        x_author_id = ""
        if x_actor:
            identity_list = self.helper.api.identity.list(
                filters={
                    "mode": "and",
                    "filters": {
                        "key": "name",
                        "values": x_actor,
                        "operator": "eq",
                        "mode": "and",
                    },
                    "filterGroups": [],
                },
            )
            if len(identity_list) == 0:
                x_author = Identity(
                    id=PyctiIdentity.generate_id(
                        lib.intel2stix.sanitizeName(x_actor), "individual"
                    ),
                    name=lib.intel2stix.sanitizeName(x_actor),
                    object_marking_refs=self.intel471_darknet_tlp,
                    identity_class="individual",
                    created_by_ref=self.intel471_id,
                    description="Forum Author",
                )
                x_author_id = x_author["id"]
                objects.append(x_author)
            else:
                x_author = identity_list[0]
                x_author_id = x_author["standard_id"]

        # channel creation
        channel_id = ""
        if x_channel_name:
            channel_list = self.helper.api.channel.list(
                filters={
                    "mode": "and",
                    "filters": {
                        "key": "name",
                        "values": x_channel_name,
                        "operator": "eq",
                        "mode": "and",
                    },
                    "filterGroups": [],
                },
            )
            if len(channel_list) == 0:
                x_channel = Channel(
                    id=PyctiChannel.generate_id(x_channel_name),
                    name=x_channel_name,
                    object_marking_refs=self.intel471_darknet_tlp,
                    channel_types=[x_server],
                    created_by_ref=self.intel471_id,
                    external_references=[
                        {"source_name": x_server, "url": x_channel_url}
                    ],
                    allow_custom=True,
                )
                self.helper.log_debug("Channel object created.")
                objects.append(x_channel)
                self.helper.log_debug("Channel object added to bundle.")
                channel_id = x_channel["id"]
            else:
                channel_id = channel_list[0]["standard_id"]

        # content creation
        x_mc_description = (
            f"### Channel\n\n{x_channel_name}\n\n"
            f"### Server service type\n\n{x_server}\n\n"
            f"### Last update\n\n{x_lastupdate}\n\n"
        )
        x_media_content = MediaContent(
            url=hashlib.md5(bytes(pprint.pformat(instantMessage), "utf-8")).hexdigest(),
            content=x_message,
            description=x_mc_description,
            publication_date=x_date,
            media_category="instant message",
            object_marking_refs=self.intel471_darknet_tlp,
            allow_custom=True,
            custom_properties={
                "created_by_ref": x_author_id or self.intel471_id,
                "x_opencti_files": octi_filelist,
            },
        )
        objects.insert(0, x_media_content)

        # relationships
        if channel_id:
            x_relationship = Relationship(
                id=PyctiSCR.generate_id(
                    "related-to", x_media_content["id"], channel_id, None, None
                ),
                relationship_type="related-to",
                source_ref=x_media_content["id"],
                target_ref=channel_id,
                created_by_ref=self.intel471_id,
                object_marking_refs=self.intel471_darknet_tlp,
            )
            objects.append(x_relationship)
        if x_author_id:
            x_relationship = Relationship(
                id=PyctiSCR.generate_id(
                    "related-to", x_media_content["id"], x_author_id, None, None
                ),
                relationship_type="related-to",
                source_ref=x_media_content["id"],
                target_ref=x_author_id,
                created_by_ref=self.intel471_id,
                object_marking_refs=self.intel471_darknet_tlp,
            )
            objects.append(x_relationship)

        return objects

    def _getReportContent(self, report: dict) -> []:
        """
        Transforms a report dictionnary in STIX content.
        Returns a list of all the created STIX objects. Report content is at the beginning.
        """
        objects = []
        x_subject = report["subject"]
        x_source_charact = (
            report["sourceCharacterization"]
            if "sourceCharacterization" in report
            else ""
        )
        x_adm_code = (
            lib.intel2stix.getAdmiralty(report["admiraltyCode"])
            if "admiraltyCode" in report
            else (None, None)
        )
        x_motivation = (
            lib.intel2stix.getMotivation(report["motivation"])
            if "motivation" in report
            else ""
        )
        x_url = report["portalReportUrl"] if "portalReportUrl" in report else ""
        x_doc_family = report["documentFamily"] if "documentFamily" in report else ""
        doi = report["dateOfInformation"] / 1000
        x_doi = get_date(_stix_timestamp(doi))
        if "released" in report:
            dr = report["released"] / 1000
        elif "created" in report:
            dr = report["created"] / 1000
        else:
            dr = 0
        x_date = _stix_timestamp(dr)
        x_rep_description = ""
        if x_subject:
            x_rep_description += f"### Subject\n\n{x_subject}\n\n"
        if x_motivation:
            x_rep_description += f"### Motivation\n\n{x_motivation}\n\n"
        if x_source_charact:
            x_rep_description += (
                f"### Source characterization\n\n{x_source_charact}\n\n"
            )
        if x_doi:
            x_rep_description += f"### Date of information\n\n{x_doi}\n\n"

        x_obj_refs = []
        # STIX external-reference URLs must be valid URLs, so we only
        # emit the Intel 471 portal reference when ``portalReportUrl``
        # was actually provided. Other report fields (sources, entities,
        # ...) still attach their own external references below.
        x_ext_refs = []
        if x_url:
            x_ext_refs.append({"source_name": "Intel471 Inc.", "url": x_url})
        x_actors = []
        x_labels = []

        # add threat actors
        if "actorSubjectOfReport" in report:
            for actor in report["actorSubjectOfReport"]:
                a = lib.intel2stix.getThreatActorContent(
                    actor, self.intel471_darknet_tlp, self.intel471_id
                )
                objects.append(a)
                x_obj_refs.append(a["id"])
                x_actors.append(a["id"])

        # add victims
        if "victims" in report:
            for victim in report["victims"]:
                v = lib.intel2stix.getVictimContent(
                    victim, self.intel471_darknet_tlp, self.intel471_id
                )
                objects.append(v)
                x_obj_refs.append(v["id"])
                for a in x_actors:
                    r = Relationship(
                        id=PyctiSCR.generate_id("targets", a, v["id"], None, None),
                        relationship_type="targets",
                        source_ref=a,
                        target_ref=v["id"],
                        created_by_ref=self.intel471_id,
                        object_marking_refs=self.intel471_darknet_tlp,
                    )
                    objects.append(r)
                    x_obj_refs.append(r)

        # add entities
        if "entities" in report:
            for entity in report["entities"]:
                e = lib.intel2stix.getTypeValueContent(
                    entity, self.intel471_darknet_tlp, self.intel471_id
                )
                if e:
                    if e[0] == "Object":
                        objects.extend(e[1])
                        for o in e[1]:
                            x_obj_refs.append(o["id"])
                        for a in x_actors:
                            r = Relationship(
                                id=PyctiSCR.generate_id(
                                    "related-to", e[1][0]["id"], a, None, None
                                ),
                                relationship_type="related-to",
                                source_ref=e[1][0]["id"],
                                target_ref=a,
                                created_by_ref=self.intel471_id,
                                object_marking_refs=self.intel471_darknet_tlp,
                            )
                            objects.append(r)
                            x_obj_refs.append(r)
                    elif e[0] == "ExtRef":
                        x_ext_refs.append(e[1])
                    elif e[0] == "Tag":
                        x_labels.append(e[1])
                else:
                    self.helper.log_debug(f"Entity not supported: {entity}")

        # add locations
        if "locations" in report:
            for location in report["locations"]:
                location_content = lib.intel2stix.getLocationContent(
                    location, self.intel471_darknet_tlp, self.intel471_id
                )
                if location_content is None:
                    # No region/country information available — skip.
                    continue
                rel_type, loc = location_content
                objects.append(loc)
                x_obj_refs.append(loc)
                if rel_type in ["targets", "located-at"]:
                    for a in x_actors:
                        r = Relationship(
                            id=PyctiSCR.generate_id(rel_type, a, loc["id"], None, None),
                            relationship_type=rel_type,
                            source_ref=a,
                            target_ref=loc["id"],
                            created_by_ref=self.intel471_id,
                            object_marking_refs=self.intel471_darknet_tlp,
                        )
                        objects.append(r)
                        x_obj_refs.append(r)
                else:
                    x_rep_description += (
                        "### Threat Actor Origin\n\n"
                        f"{loc.get('region', '')} - {loc.get('country', '')}\n\n"
                    )

        # add files
        octi_filelist = []
        if "rawText" in report:
            octi_filelist.append(
                {
                    "name": "rawText.html",
                    "data": _b64(report["rawText"]),
                    "mime_type": "text/html",
                }
            )
        if "rawTextTranslated" in report:
            octi_filelist.append(
                {
                    "name": "rawTextTranslated.html",
                    "data": _b64(report["rawTextTranslated"]),
                    "mime_type": "text/html",
                }
            )
        if "researcherComments" in report:
            octi_filelist.append(
                {
                    "name": "researcherComments.html",
                    "data": _b64(report["researcherComments"]),
                    "mime_type": "text/html",
                }
            )
        if "executiveSummary" in report:
            octi_filelist.append(
                {
                    "name": "executiveSummary.html",
                    "data": _b64(report["executiveSummary"]),
                    "mime_type": "text/html",
                }
            )

        # add external references
        if "sources" in report:
            for s in report["sources"]:
                x_ext_refs.append({"source_name": s["title"], "url": s["url"]})

        # add tags
        if "tags" in report:
            for t in report["tags"]:
                x_labels.append(t)

        # report creation
        x_report = Report(
            id=PyctiReport.generate_id(x_subject, x_date),
            type="report",
            name=x_subject,
            description=x_rep_description,
            published=x_date,
            created_by_ref=self.intel471_id,
            external_references=x_ext_refs,
            object_marking_refs=self.intel471_darknet_tlp,
            confidence=x_adm_code[1],
            custom_properties={
                "x_opencti_files": octi_filelist,
                "report_types": [x_doc_family],
                "reliability": x_adm_code[0],
            },
            object_refs=x_obj_refs,
            labels=x_labels,
        )
        objects.insert(0, x_report)

        return objects

    def _getSpotReportContent(self, spotReport: dict) -> []:
        """
        Transforms a spotReport dictionnary in STIX content
        Returns a list of all the created STIX objects. Spot Report is at the beginning.
        """
        objects = []
        x_title = (
            spotReport["data"]["spot_report"]["spot_report_data"]["title"]
            if "title" in spotReport["data"]["spot_report"]["spot_report_data"]
            else spotReport["data"]["spot_report"]["spot_report_data"]["text"][0:100]
        )
        doi = (
            spotReport["data"]["spot_report"]["spot_report_data"]["date_of_information"]
            / 1000
        )
        x_doi = get_date(_stix_timestamp(doi))
        r = spotReport["data"]["spot_report"]["spot_report_data"]["released_at"] / 1000
        x_released = _stix_timestamp(r)
        lu = spotReport["last_updated"] / 1000
        x_lastupdate = get_date(_stix_timestamp(lu))

        x_rep_description = (
            f"### Title\n\n{x_title}\n\n"
            f"### Date of information\n\n{x_doi}\n\n"
            f"### Last updated\n\n{x_lastupdate}"
        )

        x_obj_refs = []
        x_ext_refs = []
        x_labels = []

        # add entities
        if "entities" in spotReport["data"]:
            for entity in spotReport["data"]["entities"]:
                e = lib.intel2stix.getTypeValueContent(
                    entity, self.intel471_darknet_tlp, self.intel471_id
                )
                if e:
                    if e[0] == "Object":
                        objects.extend(e[1])
                        for o in e[1]:
                            x_obj_refs.append(o["id"])
                    elif e[0] == "ExtRef":
                        x_ext_refs.append(e[1])
                    elif e[0] == "Tag":
                        x_labels.append(e[1])
                else:
                    self.helper.log_debug(f"Entity not supported: {entity}")

        # add victims
        if "victims" in spotReport["data"]["spot_report"]["spot_report_data"]:
            for victim in spotReport["data"]["spot_report"]["spot_report_data"][
                "victims"
            ]:
                v = lib.intel2stix.getVictimContent(
                    victim, self.intel471_darknet_tlp, self.intel471_id
                )
                objects.append(v)
                x_obj_refs.append(v["id"])

        # add text
        octi_filelist = []
        if "text" in spotReport["data"]["spot_report"]["spot_report_data"]:
            text = spotReport["data"]["spot_report"]["spot_report_data"]["text"]
            octi_filelist.append(
                {
                    "name": "text.txt",
                    "data": _b64(text),
                    "mime_type": "text/txt",
                }
            )

        # add external references
        if "links" in spotReport["data"]["spot_report"]["spot_report_data"]:
            for link in spotReport["data"]["spot_report"]["spot_report_data"]["links"]:
                x_ext_refs.append({"source_name": link["title"], "url": link["url"]})

        # report creation
        x_report = Report(
            id=PyctiReport.generate_id(x_title, x_released),
            type="report",
            name=x_title,
            description=x_rep_description,
            published=x_released,
            created_by_ref=self.intel471_id,
            external_references=x_ext_refs,
            object_marking_refs=self.intel471_darknet_tlp,
            custom_properties={
                "x_opencti_files": octi_filelist,
                "report_types": ["spot"],
            },
            object_refs=x_obj_refs,
            labels=x_labels,
        )
        objects.insert(0, x_report)

        return objects

    def _getBreachAlertContent(self, breachAlert: dict) -> []:
        """
        Transforms a breach alert dictionnary in STIX content
        Returns a list of all the created STIX objects. Brech alert content is at the beginning.
        """
        objects = []
        x_title = breachAlert["data"]["breach_alert"]["title"]
        doi = breachAlert["data"]["breach_alert"]["date_of_information"] / 1000
        x_doi = get_date(_stix_timestamp(doi))
        r = breachAlert["data"]["breach_alert"]["released_at"] / 1000
        x_released = _stix_timestamp(r)
        x_confidence = breachAlert["data"]["breach_alert"]["confidence"]
        x_confidence_int = lib.intel2stix.getBreachConfidence(x_confidence["level"])
        self.helper.log_debug(
            f"Breach Confidence: {x_confidence['level']} aka {x_confidence_int}"
        )
        lu = breachAlert["last_updated"] / 1000
        x_lastupdate = get_date(_stix_timestamp(lu))

        x_rep_description = (
            f"### Title\n\n{x_title}\n\n"
            f"### Confidence level\n\n{x_confidence['level']}\n\n"
            f"### Confidence description\n\n{x_confidence['description']}\n\n"
            f"### Date of information\n\n{x_doi}\n\n"
            f"### Last updated\n\n{x_lastupdate}"
        )

        x_obj_refs = []
        x_ext_refs = []
        x_labels = []
        x_actor = ""

        # add sources
        if "sources" in breachAlert["data"]["breach_alert"]:
            for s in breachAlert["data"]["breach_alert"]["sources"]:
                x_ext_refs.append({"source_name": s["title"], "url": s["url"]})

        # add threat actor
        if "actor_or_group" in breachAlert["data"]["breach_alert"]:
            name = breachAlert["data"]["breach_alert"]["actor_or_group"]
            handles = []
            splt = name.split(" aka ")
            handles.append(splt[0])
            if len(splt) > 1:
                handles.extend(splt[1].split(", "))
            a = lib.intel2stix.getThreatActorContent(
                {"handle": handles[0], "aliases": handles[1:]},
                self.intel471_darknet_tlp,
                self.intel471_id,
            )
            objects.append(a)
            x_obj_refs.append(a)
            x_actor = a["id"]

        # add entities
        if "entities" in breachAlert["data"]:
            for entity in breachAlert["data"]["entities"]:
                e = lib.intel2stix.getTypeValueContent(
                    entity, self.intel471_darknet_tlp, self.intel471_id
                )
                if e:
                    if e[0] == "Object":
                        objects.extend(e[1])
                        for o in e[1]:
                            x_obj_refs.append(o["id"])
                        # Skip the actor relationship when no actor was found:
                        # passing an empty ``source_ref``/``target_ref`` produces
                        # invalid STIX and breaks the bundle serialisation.
                        if x_actor:
                            r = Relationship(
                                id=PyctiSCR.generate_id(
                                    "related-to",
                                    e[1][0]["id"],
                                    x_actor,
                                    None,
                                    None,
                                ),
                                relationship_type="related-to",
                                source_ref=e[1][0]["id"],
                                target_ref=x_actor,
                                object_marking_refs=self.intel471_darknet_tlp,
                            )
                            objects.append(r)
                            x_obj_refs.append(r)
                    elif e[0] == "ExtRef":
                        x_ext_refs.append(e[1])
                    elif e[0] == "Tag":
                        x_labels.append(e[1])
                else:
                    self.helper.log_debug(f"Entity not supported: {entity}")

        # add victim, industries and location
        if "victim" in breachAlert["data"]["breach_alert"]:
            victim = breachAlert["data"]["breach_alert"]["victim"]
            v = lib.intel2stix.getVictimContent(
                victim, self.intel471_darknet_tlp, self.intel471_id
            )
            objects.append(v)
            x_obj_refs.append(v["id"])
            if x_actor:
                r = Relationship(
                    id=PyctiSCR.generate_id("targets", x_actor, v["id"], None, None),
                    relationship_type="targets",
                    source_ref=x_actor,
                    target_ref=v["id"],
                    created_by_ref=self.intel471_id,
                    object_marking_refs=self.intel471_darknet_tlp,
                )
                objects.append(r)
                x_obj_refs.append(r)
            for i in victim.get("industries") or []:
                s = lib.intel2stix.getIndustriesContent(
                    i, self.intel471_darknet_tlp, self.intel471_id
                )
                objects.append(s[0])
                x_obj_refs.append(s[0])
                objects.append(s[1])
                if x_actor:
                    r = Relationship(
                        id=PyctiSCR.generate_id(
                            "targets", x_actor, s[0]["id"], None, None
                        ),
                        relationship_type="targets",
                        source_ref=x_actor,
                        target_ref=s[0]["id"],
                        created_by_ref=self.intel471_id,
                        object_marking_refs=self.intel471_darknet_tlp,
                    )
                    objects.append(r)
                    x_obj_refs.append(r)
                r = Relationship(
                    id=PyctiSCR.generate_id(
                        "related-to", v["id"], s[0]["id"], None, None
                    ),
                    relationship_type="related-to",
                    source_ref=v["id"],
                    target_ref=s[0]["id"],
                    created_by_ref=self.intel471_id,
                    object_marking_refs=self.intel471_darknet_tlp,
                )
                objects.append(r)
                x_obj_refs.append(r)
                r = Relationship(
                    id=PyctiSCR.generate_id(
                        "part-of", s[0]["id"], s[1]["id"], None, None
                    ),
                    relationship_type="part-of",
                    source_ref=s[0]["id"],
                    target_ref=s[1]["id"],
                    created_by_ref=self.intel471_id,
                    object_marking_refs=self.intel471_darknet_tlp,
                )
                objects.append(r)
            location_content = lib.intel2stix.getLocationContent(
                victim, self.intel471_darknet_tlp, self.intel471_id
            )
            if location_content is not None:
                _, loc = location_content
                objects.append(loc)
                x_obj_refs.append(loc)
                if x_actor:
                    r = Relationship(
                        id=PyctiSCR.generate_id(
                            "targets", x_actor, loc["id"], None, None
                        ),
                        relationship_type="targets",
                        source_ref=x_actor,
                        target_ref=loc["id"],
                        created_by_ref=self.intel471_id,
                        object_marking_refs=self.intel471_darknet_tlp,
                    )
                    objects.append(r)
                    x_obj_refs.append(r)
                r = Relationship(
                    id=PyctiSCR.generate_id(
                        "located-at", v["id"], loc["id"], None, None
                    ),
                    relationship_type="located-at",
                    source_ref=v["id"],
                    target_ref=loc["id"],
                    created_by_ref=self.intel471_id,
                    object_marking_refs=self.intel471_darknet_tlp,
                )
                objects.append(r)
                x_obj_refs.append(r)

        # add summary. Breach summaries can carry victim details and
        # other sensitive Intel 471 content, so we log only its length /
        # presence here and keep the full content inside the STIX
        # attachment.
        octi_filelist = []
        if "summary" in breachAlert["data"]["breach_alert"]:
            summary = breachAlert["data"]["breach_alert"]["summary"]
            self.helper.log_debug(
                f"Breach summary attached ({len(summary)} bytes)"
                if summary
                else "Breach summary present but empty"
            )
            octi_filelist.append(
                {
                    "name": "summary.html",
                    "data": _b64(summary),
                    "mime_type": "text/html",
                }
            )

        # report creation
        x_report = Report(
            id=PyctiReport.generate_id(x_title, x_released),
            type="report",
            name=x_title,
            description=x_rep_description,
            published=x_released,
            created_by_ref=self.intel471_id,
            external_references=x_ext_refs,
            confidence=lib.intel2stix.getBreachConfidence(x_confidence["level"]),
            object_marking_refs=self.intel471_darknet_tlp,
            custom_properties={
                "x_opencti_files": octi_filelist,
                "report_types": ["breach_alert"],
            },
            object_refs=x_obj_refs,
            labels=x_labels,
        )
        objects.insert(0, x_report)

        return objects

    def _getActorContent(self, actor: dict) -> []:
        """
        Transforms an actor dictionnary in STIX content (default is Individial Threat Actor)
        Returns a list of all the created STIX objects. Actor content is at the beginning.
        """
        objects = []
        handles = actor.get("handles") or []
        x_name = handles[0] if handles else actor["uid"]
        # ``handles`` may be missing or an empty list — slice safely so we
        # never end up with ``None[1:]``.
        x_aliases = handles[1:]
        links = actor.get("links") or {}
        x_forum_TC = links.get("forumTotalCount", 0)
        x_forum_PMTC = links.get("forumPrivateMessageTotalCount", 0)
        x_forum_PTC = links.get("forumPostTotalCount", 0)
        x_report_TC = links.get("reportTotalCount", 0)
        x_IMS_TC = links.get("instantMessageServerTotalCount", 0)
        x_IMC_TC = links.get("instantMessageChannelTotalCount", 0)
        x_IM_TC = links.get("instantMessageTotalCount", 0)
        x_forums = ""
        x_ext_refs = []
        x_source_ids = []

        # add description and contact info. ``links.forums`` is a *list* of
        # forum entries, each of which may carry its own ``contactInfo``
        # list — the previous code treated it as a dict and the
        # contact-info branch was therefore dead.
        for f in links.get("forums") or []:
            x_forums += f.get("name", "") + " - "
            for c in f.get("contactInfo") or []:
                contact = lib.intel2stix.getTypeValueContent(
                    c, self.intel471_darknet_tlp, self.intel471_id
                )
                if contact and contact[0] == "Object":
                    objects.extend(contact[1])
                    for o in contact[1]:
                        x_source_ids.append(o["id"])
        if x_forums:
            x_forums = x_forums[0:-2]
        if "lastUpdated" in actor:
            lu = actor["lastUpdated"] / 1000
            x_lastupdate = get_date(_stix_timestamp(lu))
        else:
            x_lastupdate = ""
        if "activeFrom" in actor:
            af = actor["activeFrom"] / 1000
            x_active_from = get_date(_stix_timestamp(af))
        else:
            x_active_from = ""
        if "activeUntil" in actor:
            au = actor["activeUntil"] / 1000
            x_active_until = get_date(_stix_timestamp(au))
        else:
            x_active_until = ""
        x_actor_description = (
            f"**Forum total count**: {x_forum_TC}\n\n"
            f"**Forum private message total count**: {x_forum_PMTC}\n\n"
            f"**Forum post total count**: {x_forum_PTC}\n\n"
            f"**Instant message server total count**: {x_IMS_TC}\n\n"
            f"**Instant message channel total count**: {x_IMC_TC}\n\n"
            f"**Instant message total count**: {x_IM_TC}\n\n"
            f"**Report total count**: {x_report_TC}\n\n"
            f"**Forums**: {x_forums}\n\n"
            f"**Active from**: {x_active_from}\n\n"
            f"**Active until**: {x_active_until}\n\n"
            f"**Last update**: {x_lastupdate}\n\n"
        )

        # add report references
        if "reports" in actor["links"]:
            for r in actor["links"]["reports"]:
                x_ext_refs.append(
                    {"source_name": r["subject"], "url": r["portalReportUrl"]}
                )

        # create threat actor
        x_actor = stix2.ThreatActor(
            id=PyctiTAI.generate_id(x_name),
            name=x_name,
            description=x_actor_description,
            aliases=x_aliases,
            created_by_ref=self.intel471_id,
            external_references=x_ext_refs,
            custom_properties={"x_opencti_type": "Threat-Actor-Individual"},
            object_marking_refs=self.intel471_darknet_tlp,
        )
        objects.insert(0, x_actor)

        # add relationships
        for s in x_source_ids:
            objects.append(
                Relationship(
                    id=PyctiSCR.generate_id("related-to", s, x_actor["id"], None, None),
                    relationship_type="related-to",
                    source_ref=s,
                    target_ref=x_actor["id"],
                    created_by_ref=self.intel471_id,
                    object_marking_refs=self.intel471_darknet_tlp,
                )
            )

        return objects

    def _getEntityContent(self, entity: dict) -> ():
        """
        Transforms an entity dictionnary in STIX content.
        Returns a tuple:
        - a list of all the created STIX objects. Entity object comes first, if present.
        - a list of source ids
        - a list of external references
        """
        objects = []
        x_source_ids = []
        x_ext_refs = []

        # add actors
        if "actors" in entity["links"]:
            for a in entity["links"]["actors"]:
                try:
                    url = f"{self.intel471_api_url}/actors/{a['uid']}"
                    self.helper.log_debug(f"Actor URL: {url} / Entity")
                    actor = self._intel471_get_json(url)
                    if actor:
                        # The actor payload contains free-form descriptions
                        # and forum content; log only its presence and the
                        # actor uid here.
                        self.helper.log_debug(
                            f"Actor retrieved: uid={actor.get('uid')}"
                        )
                        actor_objects = self._getActorContent(actor)
                        objects.extend(actor_objects)
                        x_source_ids.append(actor_objects[0]["id"])
                except Exception as e:
                    self.helper.log_debug(f"Error retrieving actor data: {e}")

        # TODO: re-enable the activeFrom / activeTill / lastUpdated
        # description once the Intel 471 payload shape stabilises.

        # add report references
        if "reports" in entity["links"]:
            for r in entity["links"]["reports"]:
                x_ext_refs.append(
                    {"source_name": r["subject"], "url": r["portalReportUrl"]}
                )

        # get entity
        x_entity = lib.intel2stix.getTypeValueContent(
            entity, self.intel471_darknet_tlp, self.intel471_id
        )
        # ``getTypeValueContent`` returns an empty tuple for unsupported
        # entity types — guard against that before indexing.
        if not x_entity:
            self.helper.log_debug(
                f"Entity type not supported by getTypeValueContent: "
                f"{entity.get('type')}"
            )
            return (objects, x_source_ids, x_ext_refs)

        if x_entity[0] == "Object":
            for s in x_source_ids:
                objects.append(
                    Relationship(
                        id=PyctiSCR.generate_id(
                            "related-to", s, x_entity[1][0]["id"], None, None
                        ),
                        relationship_type="related-to",
                        source_ref=s,
                        target_ref=x_entity[1][0]["id"],
                        created_by_ref=self.intel471_id,
                        object_marking_refs=self.intel471_darknet_tlp,
                    )
                )
            objects.insert(0, x_entity[1][0])
            if len(x_entity[1]) > 0:
                objects.extend(x_entity[1][1:])
            return (objects, [x_entity[1][0]["id"]], x_ext_refs)

        # if there is no entity object, the related objects will be attached
        # directly to the incident object
        return (objects, x_source_ids, x_ext_refs)

    def _get_stix_objects(self, alert) -> []:
        """
        Transforms an Intel471 alert into an Incident Stix object, several child objects and relationships
        """
        objects = []

        x_alert = None
        x_name = None
        x_description = None
        x_source = ""

        # general alert informations

        x_uid = alert["uid"]
        x_file = [
            {
                "name": x_uid + ".txt",
                "data": _b64(pprint.pformat(alert)),
                "mime_type": "txt",
            }
        ]
        x_foundtime = _stix_timestamp(alert["foundTime"] / 1000)
        x_watcher_description = ""
        if "watcherUid" in alert:
            # Watcher collection may have failed at startup, or the API may
            # return an alert for a watcher we never enumerated. Fall back
            # to the watcher UID so we do not lose the entire alert.
            x_watcher_description = self.intel471_watchers.get(
                alert["watcherUid"], alert["watcherUid"]
            )
            x_description = (
                f"### Watcher\n\n{x_watcher_description}\n\n"
                f"### Watcher UID\n\n{alert['watcherUid']}"
            )
        else:
            self.helper.log_debug("No watcherUid in alert")
        target_ids = []
        x_ext_refs = []

        # specific informations

        if "post" in alert:
            x_source = "Post"
            mapping_content = self._getPostContent(alert["post"])
            target_ids.append(mapping_content[0]["id"])
            objects.extend(mapping_content)

        if "privateMessage" in alert:
            if not x_source:
                x_source = "Private Message"
            mapping_content = self._getPrivateMessageContent(alert["privateMessage"])
            target_ids.append(mapping_content[0]["id"])
            objects.extend(mapping_content)

        if "instantMessage" in alert:
            if not x_source:
                x_source = "Instant Message"
            mapping_content = self._getInstantMessageContent(alert["instantMessage"])
            target_ids.append(mapping_content[0]["id"])
            objects.extend(mapping_content)

        if "report" in alert:
            if not x_source:
                x_source = "Report"
            url = f"{self.intel471_api_url}/reports/{alert['report']['uid']}"
            full_report = self._intel471_get_json(url)
            if full_report:
                mapping_content = self._getReportContent(full_report)
                target_ids.append(mapping_content[0]["id"])
                objects.extend(mapping_content)
            else:
                self.helper.log_warning(f"Skipping alert {x_uid}: empty body for {url}")

        if "spotReport" in alert:
            if not x_source:
                x_source = "SpotReport"
            mapping_content = self._getSpotReportContent(alert["spotReport"])
            target_ids.append(mapping_content[0]["id"])
            objects.extend(mapping_content)

        if "breachAlert" in alert:
            if not x_source:
                x_source = "Breach"
            mapping_content = self._getBreachAlertContent(alert["breachAlert"])
            target_ids.append(mapping_content[0]["id"])
            objects.extend(mapping_content)

        if "entity" in alert:
            if not x_source:
                x_source = "Entity"
            mapping_content = self._getEntityContent(alert["entity"])
            objects.extend(mapping_content[0])
            target_ids.extend(mapping_content[1])
            x_ext_refs.extend(mapping_content[2])

        if "actor" in alert:
            if not x_source:
                x_source = "Actor"
            mapping_content = self._getActorContent(alert["actor"])
            target_ids.append(mapping_content[0]["id"])
            objects.extend(mapping_content)

        # incident creation
        x_name = f"[{x_source}] [{x_watcher_description}] [{x_uid}]"
        x_alert = Incident(
            id=PyctiIncident.generate_id(x_name, x_foundtime),
            name=x_name,
            description=x_description,
            type="incident",
            object_marking_refs=self.intel471_darknet_tlp,
            created_by_ref=self.intel471_id,
            external_references=x_ext_refs,
            custom_properties={
                "incident_type": "alert",
                "source": x_source,
                "first_seen": x_foundtime,
                "x_opencti_files": x_file,
            },
        )
        objects.append(x_alert)

        # relationships
        if target_ids:
            for t in target_ids:
                x_relationship = Relationship(
                    id=PyctiSCR.generate_id("related-to", x_alert["id"], t, None, None),
                    relationship_type="related-to",
                    source_ref=x_alert["id"],
                    target_ref=t,
                    created_by_ref=self.intel471_id,
                    object_marking_refs=self.intel471_darknet_tlp,
                )
                objects.append(x_relationship)

        return objects

    def _collect_alerts(self, start_time) -> []:
        """
        Collects alerts from Intel471 and returs a bundle of STIX objects.
        """
        self.helper.log_debug(f"Collection started from date: {start_time}")

        # collecting alerts
        self.helper.log_debug("Second step: collecting alerts")
        bundle = []

        fromParam = start_time * 1000
        count = 0

        while True:
            offset = None
            nb = 0

            while True:
                if offset:
                    url = f"{self.intel471_api_url}/alerts?count=100&sort=earliest&from={fromParam}&offset={offset}"
                else:
                    url = f"{self.intel471_api_url}/alerts?count=100&sort=earliest&from={fromParam}"
                self.helper.log_debug("URL: " + url)

                alerts = self._intel471_get_json(url)
                if alerts:
                    if "alerts" in alerts:
                        alert_list = alerts["alerts"]
                        if len(alert_list):
                            self.helper.log_debug(
                                "Nombre alertes: " + str(len(alert_list))
                            )
                            for a in alert_list:
                                count += 1
                                objs = None
                                try:
                                    objs = self._get_stix_objects(a)
                                except Exception as e:
                                    self.helper.log_error(
                                        f"Error retrieving alert: {e}"
                                    )
                                    self.helper.log_error(traceback.format_exc())
                                if objs:
                                    bundle.extend(objs)
                            offset = alert_list[-1]["uid"]
                            nb += len(alert_list)
                            if nb >= 1100:
                                fromParam = int(alert_list[-1]["foundTime"]) + 1
                                break
                        else:
                            break
                    else:
                        break
                else:
                    break
            if nb < 1100:
                break

        return bundle

    def _collect_intelligence(self, since: Optional[datetime] = None) -> list:
        """Collect Intel 471 alerts and return them as STIX 2 objects.

        ``since`` is the timezone-aware UTC :class:`datetime.datetime`
        returned by the base ``ExternalImportConnector`` scheduler (or
        ``None`` on the very first run). It is converted into the
        epoch-seconds value expected by ``_collect_alerts``; when no
        previous ``last_run`` is recorded we fall back to the
        ``INTEL471_DARKNET_INITIAL_HISTORY_ALERTS`` configuration value.
        """
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )
        stix_objects = []

        if since is None:
            start_time = int(self.intel471_initial_history_alerts)
        else:
            start_time = int(since.timestamp())

        self.helper.log_debug(
            f"Start = {start_time} (since={since!r}) / "
            f"intel471_initial_history_alerts = {self.intel471_initial_history_alerts}"
        )

        stix_objects.extend(self._collect_alerts(start_time))

        self.helper.log_info(
            f"{len(stix_objects)} STIX2 objects have been compiled by "
            f"{self.helper.connect_name} connector. "
        )

        return stix_objects


if __name__ == "__main__":
    try:
        connector = Intel471AlertsConnector()
        connector.run()
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        time.sleep(10)
        sys.exit(0)
