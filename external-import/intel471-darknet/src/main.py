import base64
import hashlib
import json
import os
import pprint
import sys
import time
import traceback
import uuid
from datetime import datetime

import lib.intel2stix
import requests
import stix2
from bs4 import BeautifulSoup
from lib.external_import import ExternalImportConnector
from lib.intel2stix import get_date
from pycti.entities.opencti_channel import Channel as PyctiChannel
from pycti.entities.opencti_identity import Identity as PyctiIdentity
from pycti.entities.opencti_incident import Incident as PyctiIncident
from pycti.entities.opencti_report import Report as PyctiReport
from pycti.entities.opencti_stix_core_relationship import (
    StixCoreRelationship as PyctiSCR,
)
from pycti.entities.opencti_threat_actor_individual import (
    ThreatActorIndividual as PyctiTAI,
)
from stix2 import (
    CustomObject,
    CustomObservable,
    Identity,
    Incident,
    Relationship,
    Report,
)
from stix2.canonicalization.Canonicalize import canonicalize


@CustomObservable(
    "media-content",
    [
        ("url", stix2.properties.StringProperty(required=True)),
        ("content", stix2.properties.StringProperty()),
        ("description", stix2.properties.StringProperty()),
        ("publication_date", stix2.properties.TimestampProperty()),
        ("media_category", stix2.properties.StringProperty()),
        ("object_marking_refs", stix2.properties.StringProperty()),
        ("created_by_ref", stix2.properties.ReferenceProperty(valid_types="identity")),
        (
            "x_opencti_files",
            stix2.properties.ListProperty(stix2.properties.DictionaryProperty()),
        ),
    ],
)
class MediaContent:
    @staticmethod
    def generate_id(url):
        url = url.lower().strip()
        data = {"url": url}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "media-content--" + id


@CustomObject(
    "channel",
    [
        ("name", stix2.properties.StringProperty(required=True)),
        ("description", stix2.properties.StringProperty()),
        ("object_marking_refs", stix2.properties.StringProperty()),
        (
            "channel_types",
            stix2.properties.ListProperty(stix2.properties.StringProperty()),
        ),
        ("created_by_ref", stix2.properties.ReferenceProperty(valid_types="identity")),
        (
            "external_references",
            stix2.properties.ListProperty(stix2.properties.DictionaryProperty()),
        ),
    ],
)
class Channel:
    pass


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

        self.intel471_api_url = os.environ.get(
            "INTEL471_API_URL", "https://api.intel471.com/v1"
        )
        self.intel471_api_username = os.environ.get("INTEL471_API_USERNAME")
        self.intel471_api_key = os.environ.get("INTEL471_API_KEY")
        self.intel471_initial_history_alerts = os.environ.get(
            "INTEL471_DARKNET_INITIAL_HISTORY_ALERTS", "0"
        )
        self.intel471_darknet_tlp = self._get_tlp(
            os.environ.get("INTEL471_DARKNET_TLP", "AMBER")
        )
        self.intel471_watchers = {}

        # collecting watchers
        self.helper.log_debug("Collecting watcher info")
        url = f"{self.intel471_api_url}/watcherGroups"
        api_response = requests.get(
            url, auth=(self.intel471_api_username, self.intel471_api_key)
        )
        if api_response.text:
            self.helper.log_debug(
                f"watcherGroups API response text: {api_response.text}"
            )
            try:
                watcher_groups = json.loads(api_response.text)
                if "watcherGroups" in watcher_groups:
                    for wg in watcher_groups["watcherGroups"]:
                        url = f"{self.intel471_api_url}/watcherGroups/{wg['uid']}/watchers"
                        api_response = requests.get(
                            url,
                            auth=(self.intel471_api_username, self.intel471_api_key),
                        )
                        if api_response.text:
                            self.helper.log_debug(
                                f"watcherGroups/UID/watchers API response text: {api_response.text}"
                            )
                            watchers = json.loads(api_response.text)
                            if "watchers" in watchers:
                                for w in watchers["watchers"]:
                                    self.intel471_watchers[w["uid"]] = w["description"]
                            else:
                                self.helper.log_debug(
                                    f"No Watchers in this group: {wg['uid']}"
                                )
                        else:
                            self.helper.log_debug(
                                f"No API response on watcherGroups/{wg['uid']}/watchers endpoint."
                            )
                    self.helper.log_debug(f"Watchers: {self.intel471_watchers}")
                else:
                    self.helper.log_debug("No Watcher Groups in API response.")
            except Exception as e:
                self.helper.log_debug(f"WatchGroups retrieval failed: {e}")
        else:
            self.helper.log_debug("No API response on watcherGroups endpoint.")

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

    def _get_tlp(self, tlp_string):
        result = ""
        if tlp_string == "WHITE" or tlp_string == "CLEAR":
            result = stix2.TLP_RED
        elif tlp_string == "GREEN":
            result = stix2.TLP_GREEN
        elif tlp_string == "AMBER":
            result = stix2.TLP_AMBER
        elif tlp_string == "AMBER_STRICT":
            result = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
        else:
            result = stix2.TLP_RED
        return result

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
            x_lastupdate = get_date(
                datetime.utcfromtimestamp(lu).strftime(
                    stix2.utils._TIMESTAMP_FORMAT_FRAC
                )
            )
        else:
            x_lastupdate = ""
        d = privateMessage["date"] / 1000
        x_date = datetime.utcfromtimestamp(d).strftime(
            stix2.utils._TIMESTAMP_FORMAT_FRAC
        )

        # are there some images?
        octi_filelist = []
        if "images" in privateMessage["links"]:
            forum_imagelist = privateMessage["links"]["images"]
            # self.helper.log_debug(f"Images? {forum_imagelist}")
            for f in forum_imagelist:
                try:
                    imagename = f["hash"]
                    image = requests.get(
                        f["imageOriginal"],
                        auth=(self.intel471_api_username, self.intel471_api_key),
                    )
                    octi_filelist.append(
                        {
                            "name": imagename,
                            "data": base64.b64encode(image.content),
                            "mime_type": "image/*",
                        }
                    )
                except Exception as e:
                    self.helper.log_debug(f"Adding of image failed: {e}")

        # add message textfile
        octi_filelist.append(
            {
                "name": privateMessage["uid"] + "-message.txt",
                "data": base64.b64encode(bytes(pprint.pformat(x_message), "utf-8")),
                "mime_type": "txt",
            }
        )
        octi_filelist.append(
            {
                "name": privateMessage["uid"] + "-json.txt",
                "data": base64.b64encode(
                    bytes(pprint.pformat(privateMessage), "utf-8")
                ),
                "mime_type": "txt",
            }
        )

        # does the sender/receiver already exist in OCTI?
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
            id=MediaContent.generate_id(
                hashlib.md5(bytes(pprint.pformat(privateMessage), "utf-8")).hexdigest()
            ),
            url=hashlib.md5(bytes(pprint.pformat(privateMessage), "utf-8")).hexdigest(),
            content=x_message,
            description=x_mc_description,
            publication_date=x_date,
            media_category="private forum message",
            object_marking_refs=self.intel471_darknet_tlp,
            created_by_ref=x_sender_id,
            x_opencti_files=octi_filelist,
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
            x_lastupdate = get_date(
                datetime.utcfromtimestamp(lu).strftime(
                    stix2.utils._TIMESTAMP_FORMAT_FRAC
                )
            )
        else:
            x_lastupdate = ""
        d = post["date"] / 1000
        x_date = datetime.utcfromtimestamp(d).strftime(
            stix2.utils._TIMESTAMP_FORMAT_FRAC
        )

        # are there some images?
        octi_filelist = []
        if "images" in post["links"]:
            forum_imagelist = post["links"]["images"]
            # self.helper.log_debug(f"Images? {forum_imagelist}")
            for f in forum_imagelist:
                try:
                    imagename = f["hash"]
                    image = requests.get(
                        f["imageOriginal"],
                        auth=(self.intel471_api_username, self.intel471_api_key),
                    )
                    octi_filelist.append(
                        {
                            "name": imagename,
                            "data": base64.b64encode(image.content),
                            "mime_type": "image/*",
                        }
                    )
                except Exception as e:
                    self.helper.log_debug(f"Adding of image failed: {e}")

        # add message textfile
        octi_filelist.append(
            {
                "name": post["uid"] + "-message.txt",
                "data": base64.b64encode(bytes(pprint.pformat(x_message), "utf-8")),
                "mime_type": "txt",
            }
        )
        octi_filelist.append(
            {
                "name": post["uid"] + "-json.txt",
                "data": base64.b64encode(bytes(pprint.pformat(post), "utf-8")),
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
            id=MediaContent.generate_id(post["uid"]),
            url=post["uid"],
            content=x_message,
            description=x_mc_description,
            publication_date=x_date,
            media_category="forum post",
            object_marking_refs=self.intel471_darknet_tlp,
            created_by_ref=x_author_id,
            x_opencti_files=octi_filelist,
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
        x_date = datetime.utcfromtimestamp(d).strftime(
            stix2.utils._TIMESTAMP_FORMAT_FRAC
        )
        lu = instantMessage["last_updated"] / 1000
        x_lastupdate = get_date(
            datetime.utcfromtimestamp(lu).strftime(stix2.utils._TIMESTAMP_FORMAT_FRAC)
        )

        # add message textfile
        octi_filelist = [
            {
                "name": "message.txt",
                "data": base64.b64encode(bytes(pprint.pformat(x_message), "utf-8")),
                "mime_type": "txt",
            }
        ]
        octi_filelist.append(
            {
                "name": "json.txt",
                "data": base64.b64encode(
                    bytes(pprint.pformat(instantMessage), "utf-8")
                ),
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
            id=MediaContent.generate_id(
                hashlib.md5(bytes(pprint.pformat(instantMessage), "utf-8")).hexdigest()
            ),
            url=hashlib.md5(bytes(pprint.pformat(instantMessage), "utf-8")).hexdigest(),
            content=x_message,
            description=x_mc_description,
            publication_date=x_date,
            media_category="instant message",
            object_marking_refs=self.intel471_darknet_tlp,
            created_by_ref=x_author_id,
            x_opencti_files=octi_filelist,
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
        x_doi = get_date(
            datetime.utcfromtimestamp(doi).strftime(stix2.utils._TIMESTAMP_FORMAT_FRAC)
        )
        if "released" in report:
            dr = report["released"] / 1000
        elif "created" in report:
            dr = report["created"] / 1000
        else:
            dr = 0
        x_date = datetime.utcfromtimestamp(dr).strftime(
            stix2.utils._TIMESTAMP_FORMAT_FRAC
        )
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
        x_ext_refs = [{"source_name": "Intel471 Inc.", "url": x_url}]
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
                l = lib.intel2stix.getLocationContent(
                    location, self.intel471_darknet_tlp, self.intel471_id
                )
                objects.append(l[1])
                x_obj_refs.append(l[1])
                if l[0] in ["targets", "located-at"]:
                    for a in x_actors:
                        r = Relationship(
                            id=PyctiSCR.generate_id(l[0], a, l[1]["id"], None, None),
                            relationship_type=l[0],
                            source_ref=a,
                            target_ref=l[1]["id"],
                            created_by_ref=self.intel471_id,
                            object_marking_refs=self.intel471_darknet_tlp,
                        )
                        objects.append(r)
                        x_obj_refs.append(r)
                else:
                    x_rep_description += f"### Threat Actor Origin\n\n{l[1]['region']} - {l[1]['country']}\n\n"

        # add files
        octi_filelist = []
        if "rawText" in report:
            octi_filelist.append(
                {
                    "name": "rawText.html",
                    "data": base64.b64encode(bytes(report["rawText"], "utf-8")),
                    "mime_type": "text/html",
                }
            )
        if "rawTextTranslated" in report:
            octi_filelist.append(
                {
                    "name": "rawTextTranslated.html",
                    "data": base64.b64encode(
                        bytes(report["rawTextTranslated"], "utf-8")
                    ),
                    "mime_type": "text/html",
                }
            )
        if "researcherComments" in report:
            octi_filelist.append(
                {
                    "name": "researcherComments.html",
                    "data": base64.b64encode(
                        bytes(report["researcherComments"], "utf-8")
                    ),
                    "mime_type": "text/html",
                }
            )
        if "executiveSummary" in report:
            octi_filelist.append(
                {
                    "name": "executiveSummary.html",
                    "data": base64.b64encode(
                        bytes(report["executiveSummary"], "utf-8")
                    ),
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
        x_doi = get_date(
            datetime.utcfromtimestamp(doi).strftime(stix2.utils._TIMESTAMP_FORMAT_FRAC)
        )
        r = spotReport["data"]["spot_report"]["spot_report_data"]["released_at"] / 1000
        x_released = datetime.utcfromtimestamp(r).strftime(
            stix2.utils._TIMESTAMP_FORMAT_FRAC
        )
        lu = spotReport["last_updated"] / 1000
        x_lastupdate = get_date(
            datetime.utcfromtimestamp(lu).strftime(stix2.utils._TIMESTAMP_FORMAT_FRAC)
        )

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
                    "data": base64.b64encode(bytes(text, "utf-8")),
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
        x_doi = get_date(
            datetime.utcfromtimestamp(doi).strftime(stix2.utils._TIMESTAMP_FORMAT_FRAC)
        )
        r = breachAlert["data"]["breach_alert"]["released_at"] / 1000
        x_released = datetime.utcfromtimestamp(r).strftime(
            stix2.utils._TIMESTAMP_FORMAT_FRAC
        )
        x_confidence = breachAlert["data"]["breach_alert"]["confidence"]
        x_confidence_int = lib.intel2stix.getBreachConfidence(x_confidence["level"])
        self.helper.log_debug(
            f"Breach Confidence: {x_confidence['level']} aka {x_confidence_int}"
        )
        lu = breachAlert["last_updated"] / 1000
        x_lastupdate = get_date(
            datetime.utcfromtimestamp(lu).strftime(stix2.utils._TIMESTAMP_FORMAT_FRAC)
        )

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
                        r = Relationship(
                            id=PyctiSCR.generate_id(
                                "related-to", e[1][0]["id"], x_actor, None, None
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
            for i in victim["industries"]:
                s = lib.intel2stix.getIndustriesContent(
                    i, self.intel471_darknet_tlp, self.intel471_id
                )
                objects.append(s[0])
                x_obj_refs.append(s[0])
                objects.append(s[1])
                r = Relationship(
                    id=PyctiSCR.generate_id("targets", x_actor, s[0]["id"], None, None),
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
            l = lib.intel2stix.getLocationContent(
                victim, self.intel471_darknet_tlp, self.intel471_id
            )
            objects.append(l[1])
            x_obj_refs.append(l[1])
            r = Relationship(
                id=PyctiSCR.generate_id("targets", x_actor, l[1]["id"], None, None),
                relationship_type="targets",
                source_ref=x_actor,
                target_ref=l[1]["id"],
                created_by_ref=self.intel471_id,
                object_marking_refs=self.intel471_darknet_tlp,
            )
            objects.append(r)
            x_obj_refs.append(r)
            r = Relationship(
                id=PyctiSCR.generate_id("located-at", v["id"], l[1]["id"], None, None),
                relationship_type="located-at",
                source_ref=v["id"],
                target_ref=l[1]["id"],
                created_by_ref=self.intel471_id,
                object_marking_refs=self.intel471_darknet_tlp,
            )
            objects.append(r)
            x_obj_refs.append(r)

        # add summary
        octi_filelist = []
        if "summary" in breachAlert["data"]["breach_alert"]:
            summary = breachAlert["data"]["breach_alert"]["summary"]
            self.helper.log_debug(f"Summary: {summary}")
            octi_filelist.append(
                {
                    "name": "summary.html",
                    "data": base64.b64encode(bytes(summary, "utf-8")),
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
        x_name = actor["handles"][0] if "handles" in actor else actor["uid"]
        x_aliases = actor.get("handles")[1:]
        x_forum_TC = actor["links"]["forumTotalCount"]
        x_forum_PMTC = actor["links"]["forumPrivateMessageTotalCount"]
        x_forum_PTC = actor["links"]["forumPostTotalCount"]
        x_report_TC = actor["links"]["reportTotalCount"]
        x_IMS_TC = actor["links"]["instantMessageServerTotalCount"]
        x_IMC_TC = actor["links"]["instantMessageChannelTotalCount"]
        x_IM_TC = actor["links"]["instantMessageTotalCount"]
        x_forums = ""
        x_ext_refs = []
        x_source_ids = []

        # add description and contact info
        if "forums" in actor["links"]:
            for f in actor["links"]["forums"]:
                x_forums += f["name"] + " - "
                if "contactInfo" in actor["links"]["forums"]:
                    for c in actor["links"]["forums"]["contactInfo"]:
                        contact = lib.intel2stix.getTypeValueContent(
                            c, self.intel471_darknet_tlp, self.intel471_id
                        )
                        if contact[0] == "Object":
                            objects.extend(contact[1])
                            for o in contact[1]:
                                x_source_ids.append(o["id"])
            x_forums = x_forums[0:-2]
        if "lastUpdated" in actor:
            lu = actor["lastUpdated"] / 1000
            x_lastupdate = get_date(
                datetime.utcfromtimestamp(lu).strftime(
                    stix2.utils._TIMESTAMP_FORMAT_FRAC
                )
            )
        else:
            x_lastupdate = ""
        if "activeFrom" in actor:
            af = actor["activeFrom"] / 1000
            x_active_from = get_date(
                datetime.utcfromtimestamp(af).strftime(
                    stix2.utils._TIMESTAMP_FORMAT_FRAC
                )
            )
        else:
            x_active_from = ""
        if "activeUntil" in actor:
            au = actor["activeUntil"] / 1000
            x_active_until = get_date(
                datetime.utcfromtimestamp(au).strftime(
                    stix2.utils._TIMESTAMP_FORMAT_FRAC
                )
            )
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
                    api_response = requests.get(
                        url, auth=(self.intel471_api_username, self.intel471_api_key)
                    )
                    if api_response.text:
                        self.helper.log_debug(
                            f"Actor API Response: {api_response.text}"
                        )
                        actor = json.loads(api_response.text)
                        actor_objects = self._getActorContent(actor)
                        objects.extend(actor_objects)
                        x_source_ids.append(actor_objects[0]["id"])
                except Exception as e:
                    self.helper.log_debug(f"Error retrieving actor data: {e}")

        # TODO add description
        """
        if "activeFrom" in entity:
            af = entity["activeFrom"] / 1000
            x_active_from = get_date(datetime.utcfromtimestamp(af).strftime(stix2.utils._TIMESTAMP_FORMAT_FRAC))
        else:
            x_active_from = ""
        if "activeTill" in entity:
            au = entity["activeTill"] / 1000
            x_active_until = get_date(datetime.utcfromtimestamp(au).strftime(stix2.utils._TIMESTAMP_FORMAT_FRAC))
        else:
            x_active_until = ""
        if "last_updated" in entity: 
            lu = entity["last_updated"] / 1000
            x_lastupdate = get_date(datetime.utcfromtimestamp(lu).strftime(stix2.utils._TIMESTAMP_FORMAT_FRAC))
        else:
            x_lastupdate = ""
        x_ent_description=f"### Active from\n\n{x_active_from}\n\n"\
                f"### Active until\n\n{x_active_until}\n\n"\
                f"### Last update\n\n{x_lastupdate}\n\n"\
        """

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
        result = None
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
            result = (objects, [x_entity[1][0]["id"]], x_ext_refs)
        else:
            # if there is no entity object, the related objects will be attached directly to the incident object
            result = (objects, x_source_ids, x_ext_refs)

        return result

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
                "data": base64.b64encode(bytes(pprint.pformat(alert), "utf-8")),
                "mime_type": "txt",
            }
        ]
        x_foundtime = datetime.utcfromtimestamp(alert["foundTime"] / 1000).strftime(
            stix2.utils._TIMESTAMP_FORMAT_FRAC
        )
        x_watcher_description = ""
        if "watcherUid" in alert:
            x_watcher_description = self.intel471_watchers[alert["watcherUid"]]
            x_description = f"### Watcher\n\n{x_watcher_description}\n\n### Watcher UID\n\n{alert['watcherUid']}"
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
            api_response = requests.get(
                url, auth=(self.intel471_api_username, self.intel471_api_key)
            )
            if api_response.text:
                full_report = json.loads(api_response.text)
            mapping_content = self._getReportContent(full_report)
            target_ids.append(mapping_content[0]["id"])
            objects.extend(mapping_content)

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

                api_response = requests.get(
                    url, auth=(self.intel471_api_username, self.intel471_api_key)
                )
                if api_response.text:
                    alerts = json.loads(api_response.text)
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

    def _collect_intelligence(self, start) -> []:
        """
        Collects alerts from Intel471
        Returns:
            stix_objects: A list of STIX2 objects.
        """
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )
        stix_objects = []

        # ===========================
        # === Add your code below ===
        # ===========================
        self.helper.log_debug("Starting Intel471 alerts collection...")
        self.helper.log_debug(
            "Start = "
            + str(start)
            + " / intel471_initial_history_alerts = "
            + str(self.intel471_initial_history_alerts)
        )

        if start == 0:
            start_time = int(self.intel471_initial_history_alerts)
        else:
            start_time = start

        stix_objects.extend(self._collect_alerts(start_time))

        # ===========================
        # === Add your code above ===
        # ===========================

        self.helper.log_info(
            f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
        )

        # for obj in stix_objects:
        #    self.helper.log_debug(f"Stix Object= {obj}")

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
