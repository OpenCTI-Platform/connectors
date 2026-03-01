import base64
import json
import os
import pprint
import sys
import time
import traceback
import uuid
from datetime import datetime

import requests
import stix2
from bs4 import BeautifulSoup
from lib.external_import import ExternalImportConnector
from pycti.entities.opencti_channel import Channel as PyctiChannel
from pycti.entities.opencti_identity import Identity as PyctiIdentity
from pycti.entities.opencti_incident import Incident as PyctiIncident
from pycti.entities.opencti_stix_core_relationship import (
    StixcoreRelationship as PyctiSCR,
)
from pycti.entities.opencti_threat_actor_individual import (
    ThreatActorIndividual as PyctiTAI,
)
from stix2 import (
    CustomObject,
    CustomObservable,
    DomainName,
    File,
    Identity,
    Incident,
    Relationship,
    ThreatActor,
    UserAccount,
)
from stix2.canonicalization.Canonicalize import canonicalize


@CustomObservable(
    "media-content",
    [
        ("id", stix2.properties.StringProperty(required=True)),
        ("url", stix2.properties.StringProperty(required=True)),
        ("content", stix2.properties.StringProperty()),
        ("description", stix2.properties.StringProperty()),
        ("publication_date", stix2.properties.TimestampProperty()),
        ("media_category", stix2.properties.StringProperty()),
        ("object_marking_refs", stix2.properties.StringProperty()),
        ("created_by_ref", stix2.properties.ReferenceProperty(valid_types="identity")),
        (
            "external_references",
            stix2.properties.ListProperty(stix2.properties.DictionaryProperty()),
        ),
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
        ("id", stix2.properties.StringProperty(required=True)),
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


def get_date(octi_date) -> str:
    d = octi_date.rstrip("Z").split("T")
    return d[0] + " " + d[1]


def sanitizeName(name) -> str:
    result = name
    if len(name) < 2:
        result += "="
    return result


def defang(text) -> str:
    return (
        text.replace("http://", "hxxp://")
        .replace("@", "[at]")
        .replace("www.", "www[.]")
    )


def get_tlp(tlp_string):
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


def generate_file_id(name, sha256, sha1, md5):
    data = {
        "name": name.lower().strip(),
        "hashes": {
            "SHA-256": sha256.lower().strip(),
            "SHA-1": sha1.lower().strip(),
            "MD5": md5.lower().strip(),
        },
    }
    data = canonicalize(data, utf8=False)
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "file--" + id


def generate_domain_name_id(value):
    data = {"value": value}
    data = canonicalize(data, utf8=False)
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "domain-name--" + id


def generate_user_account_id(user_id):
    data = {"user_id": user_id}
    data = canonicalize(data, utf8=False)
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "user-account--" + id


class MandiantAlertsConnector(ExternalImportConnector):
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

        self.mandiant_api_url = os.environ.get(
            "MANDIANT_API_URL", "https://api.intelligence.mandiant.com/v4/dtm"
        )
        if not self.mandiant_api_url:
            self.mandiant_api_url = "https://api.intelligence.mandiant.com/v4/dtm"
        self.mandiant_api_key_id = os.environ.get("MANDIANT_API_V4_KEY_ID")
        self.mandiant_api_key_secret = os.environ.get("MANDIANT_API_V4_KEY_SECRET")
        self.mandiant_darknet_import_start_date = os.environ.get(
            "MANDIANT_DARKNET_IMPORT_START_DATE", "0"
        )
        if not self.mandiant_darknet_import_start_date:
            self.mandiant_darknet_import_start_date = "0"
        self.mandiant_darknet_tlp = get_tlp(
            os.environ.get("MANDIANT_DARKNET_TLP", "AMBER")
        )
        if not self.mandiant_darknet_tlp:
            self.mandiant_darknet_tlp = "AMBER"

        # get author id
        identity_list = self.helper.api.identity.list(
            filters={
                "mode": "and",
                "filters": {
                    "key": "name",
                    "values": "Mandiant",
                    "operator": "eq",
                    "mode": "and",
                },
                "filterGroups": [],
            },
        )
        if len(identity_list) == 0:
            x_author = Identity(
                id=PyctiIdentity.generate_id("Mandiant", "organization"),
                name="Mandiant",
                identity_class="organization",
            )
            self.mandiant_id = x_author["id"]
            self.helper.log_debug(f"x_author_id = {self.mandiant_id}")
        else:
            x_author = identity_list[0]
            self.mandiant_id = x_author["standard_id"]
            self.helper.log_debug(f"x_author_standard_id = {self.mandiant_id}")

    def _getTweetObjects(self, doc: dict, doc_url: str) -> []:
        """
        Transforms a tweet dictionnary in STIX content
        Returns a list of all the created STIX objects. Tweet content is at the beginning.
        """
        objects = []
        x_message = BeautifulSoup(doc.get("body"), "lxml").get_text()
        if "author" in doc and "contact" in doc["author"]:
            x_handle = doc.get("author").get("contact").get("twitter_handle")
            x_url = "https://twitter.com/" + x_handle + "/status/" + doc.get("id_str")
        else:
            x_url = x_handle = ""
        x_actor = (
            doc.get("author").get("identity").get("name")
            if "author" in doc and "identity" in doc["author"]
            else ""
        )
        x_actor_desc = (
            defang(doc.get("author").get("twitter").get("description"))
            if "author" in doc and "twitter" in doc["author"]
            else ""
        )
        x_timestamp = doc.get("timestamp")

        # add files
        octi_filelist = []
        octi_filelist.append(
            {
                "name": doc["__id"] + "-message.txt",
                "data": base64.b64encode(bytes(pprint.pformat(x_message), "utf-8")),
                "mime_type": "txt",
            }
        )
        octi_filelist.append(
            {
                "name": doc["__id"] + "-json.txt",
                "data": base64.b64encode(bytes(pprint.pformat(doc), "utf-8")),
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
                    id=PyctiIdentity.generate_id(sanitizeName(x_actor), "individual"),
                    name=sanitizeName(x_actor),
                    object_marking_refs=self.mandiant_darknet_tlp,
                    identity_class="individual",
                    created_by_ref=self.mandiant_id,
                    external_references=[
                        {"source_name": "Twitter handle", "url": x_handle}
                    ],
                    description=f"**Twitter Author**\n\n{x_actor_desc}",
                )
                x_author_id = x_author["id"]
                objects.append(x_author)
            else:
                x_author = identity_list[0]
                x_author_id = x_author["standard_id"]

        # content creation
        x_mc_description = (
            f"### Author\n\n{x_actor}\n\n" f"### Description\n\n{x_actor_desc}\n\n"
        )
        x_media_content = MediaContent(
            id=MediaContent.generate_id(x_url),
            url=x_url,
            content=x_message,
            description=x_mc_description,
            publication_date=x_timestamp,
            media_category="tweet",
            object_marking_refs=self.mandiant_darknet_tlp,
            created_by_ref=x_author_id if x_author_id else self.mandiant_id,
            external_references=[{"source_name": "Mandiant", "url": doc_url}],
            x_opencti_files=octi_filelist,
        )
        objects.insert(0, x_media_content)

        # relationships
        if x_author_id:
            x_relationship = Relationship(
                id=PyctiSCR.generate_id(
                    "related-to", x_media_content["id"], x_author_id, None, None
                ),
                relationship_type="related-to",
                source_ref=x_media_content["id"],
                target_ref=x_author_id,
                created_by_ref=self.mandiant_id,
                object_marking_refs=self.mandiant_darknet_tlp,
            )
            objects.append(x_relationship)

        return objects

    def _getMessageObjects(self, doc: dict, doc_url: str) -> []:
        """
        Transforms a message dictionnary in STIX content
        Returns a list of all the created STIX objects. Media content is at the beginning.
        """
        objects = []
        x_message = BeautifulSoup(doc.get("body"), "lxml").get_text()
        x_url = doc["message_id"] if "message_id" in doc else doc["__id"]
        x_actor = (
            doc.get("sender").get("identity").get("name")
            if "sender" in doc and "identity" in doc["sender"]
            else ""
        )
        x_messenger = (
            doc.get("channel").get("messenger").get("name")
            if "channel" in doc and "messenger" in doc["channel"]
            else ""
        )
        x_channel_desc = (
            defang(doc.get("channel").get("channel_info").get("description"))
            if "channel" in doc and "channel_info" in doc["channel"]
            else ""
        )
        x_timestamp = doc.get("timestamp")

        # add files
        octi_filelist = []
        octi_filelist.append(
            {
                "name": doc["__id"] + "-message.txt",
                "data": base64.b64encode(bytes(pprint.pformat(x_message), "utf-8")),
                "mime_type": "txt",
            }
        )
        octi_filelist.append(
            {
                "name": doc["__id"] + "-json.txt",
                "data": base64.b64encode(bytes(pprint.pformat(doc), "utf-8")),
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
                    id=PyctiIdentity.generate_id(sanitizeName(x_actor), "individual"),
                    name=sanitizeName(x_actor),
                    object_marking_refs=self.mandiant_darknet_tlp,
                    identity_class="individual",
                    created_by_ref=self.mandiant_id,
                    description="Messenger Author",
                )
                x_author_id = x_author["id"]
                objects.append(x_author)
            else:
                x_author = identity_list[0]
                x_author_id = x_author["standard_id"]

        # channel creation
        channel_id = ""
        if x_channel_desc:
            channel_list = self.helper.api.channel.list(
                filters={
                    "mode": "and",
                    "filters": {
                        "key": "name",
                        "values": x_channel_desc,
                        "operator": "eq",
                        "mode": "and",
                    },
                    "filterGroups": [],
                },
            )
            if len(channel_list) == 0:
                x_channel = Channel(
                    id=PyctiChannel.generate_id(x_channel_desc),
                    name=x_channel_desc,
                    object_marking_refs=self.mandiant_darknet_tlp,
                    created_by_ref=self.mandiant_id,
                    channel_types=[x_messenger],
                )
                self.helper.log_debug("Channel object created.")
                objects.append(x_channel)
                self.helper.log_debug("Channel object added to bundle.")
                channel_id = x_channel["id"]
            else:
                channel_id = channel_list[0]["standard_id"]

        # content creation
        x_mc_description = (
            f"### Channel\n\n{x_channel_desc}\n\n" f"### Messenger\n\n{x_messenger}\n\n"
        )
        x_media_content = MediaContent(
            id=MediaContent.generate_id(x_url),
            url=x_url,
            content=x_message,
            description=x_mc_description,
            publication_date=x_timestamp,
            media_category="message",
            object_marking_refs=self.mandiant_darknet_tlp,
            created_by_ref=x_author_id if x_author_id else self.mandiant_id,
            external_references=[{"source_name": "Mandiant", "url": doc_url}],
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
                created_by_ref=self.mandiant_id,
                object_marking_refs=self.mandiant_darknet_tlp,
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
                created_by_ref=self.mandiant_id,
                object_marking_refs=self.mandiant_darknet_tlp,
            )
            objects.append(x_relationship)

        return objects

    def _getForumPostObjects(self, doc: dict, doc_url: str) -> []:
        """
        Transforms a forum post message dictionnary in STIX content
        Returns a list of all the created STIX objects. Media content is at the beginning.
        """
        objects = []
        x_message = BeautifulSoup(doc.get("body"), "lxml").get_text()
        if "source_url" in doc:
            x_url = doc["source_url"]
        elif "message_id" in doc:
            x_url = doc["message_id"]
        else:
            x_url = doc["__id"]
        x_actor = (
            doc.get("author").get("identity").get("name")
            if "author" in doc and "identity" in doc["author"]
            else ""
        )
        x_forum = doc.get("forum").get("name") if "forum" in doc else ""
        self.helper.log_debug(f"Forum name: {x_forum}")
        x_board = doc.get("board")
        x_timestamp = doc.get("timestamp")

        # add files
        octi_filelist = []
        octi_filelist.append(
            {
                "name": doc["__id"] + "-message.txt",
                "data": base64.b64encode(bytes(pprint.pformat(x_message), "utf-8")),
                "mime_type": "txt",
            }
        )
        octi_filelist.append(
            {
                "name": doc["__id"] + "-json.txt",
                "data": base64.b64encode(bytes(pprint.pformat(doc), "utf-8")),
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
                    id=PyctiIdentity.generate_id(sanitizeName(x_actor), "individual"),
                    name=sanitizeName(x_actor),
                    object_marking_refs=self.mandiant_darknet_tlp,
                    identity_class="individual",
                    created_by_ref=self.mandiant_id,
                    description="Forum Author",
                )
                x_author_id = x_author["id"]
                objects.append(x_author)
            else:
                x_author = identity_list[0]
                x_author_id = x_author["standard_id"]

        # channel creation
        channel_id = ""
        if x_board:
            channel_list = self.helper.api.channel.list(
                filters={
                    "mode": "and",
                    "filters": {
                        "key": "name",
                        "values": x_board,
                        "operator": "eq",
                        "mode": "and",
                    },
                    "filterGroups": [],
                },
            )
            if len(channel_list) == 0:
                x_channel = Channel(
                    id=PyctiChannel.generate_id(x_board),
                    name=x_board,
                    object_marking_refs=self.mandiant_darknet_tlp,
                    created_by_ref=self.mandiant_id,
                    channel_types=[x_forum],
                )
                self.helper.log_debug(f"Channel object created: {x_channel}")
                objects.append(x_channel)
                self.helper.log_debug("Channel object added to bundle.")
                channel_id = x_channel["id"]
            else:
                channel_id = channel_list[0]["standard_id"]

        # content creation
        x_mc_description = (
            f"### Subject\n\n{doc.get('subject')}\n\n"
            f"### Board\n\n{x_board}\n\n"
            f"### Forum\n\n{x_forum}\n\n"
        )
        x_media_content = MediaContent(
            id=MediaContent.generate_id(x_url),
            url=x_url,
            content=x_message,
            description=x_mc_description,
            publication_date=x_timestamp,
            media_category="forum post",
            object_marking_refs=self.mandiant_darknet_tlp,
            created_by_ref=x_author_id if x_author_id else self.mandiant_id,
            external_references=[{"source_name": "Mandiant", "url": doc_url}],
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
                created_by_ref=self.mandiant_id,
                object_marking_refs=self.mandiant_darknet_tlp,
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
                created_by_ref=self.mandiant_id,
                object_marking_refs=self.mandiant_darknet_tlp,
            )
            objects.append(x_relationship)

        return objects

    def _getWebContentObjects(self, doc: dict, doc_url: str) -> []:
        """
        Transforms a web content dictionnary in STIX content
        Returns a list of all the created STIX objects. Web content is at the beginning.
        """
        objects = []
        x_content = doc.get("text")
        x_url = doc.get("inet_location").get("url") if "inet_location" in doc else ""
        x_actor = (
            doc.get("author").get("identity").get("name")
            if "author" in doc and "identity" in doc["author"]
            else ""
        )
        x_timestamp = doc.get("timestamp")

        # add files
        octi_filelist = []
        octi_filelist.append(
            {
                "name": doc["__id"] + "-content.txt",
                "data": base64.b64encode(bytes(pprint.pformat(x_content), "utf-8")),
                "mime_type": "txt",
            }
        )
        octi_filelist.append(
            {
                "name": doc["__id"] + "-json.txt",
                "data": base64.b64encode(bytes(pprint.pformat(doc), "utf-8")),
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
                    id=PyctiIdentity.generate_id(sanitizeName(x_actor), "individual"),
                    name=sanitizeName(x_actor),
                    object_marking_refs=self.mandiant_darknet_tlp,
                    identity_class="individual",
                    created_by_ref=self.mandiant_id,
                    description="Forum Author",
                )
                x_author_id = x_author["id"]
                objects.append(x_author)
            else:
                x_author = identity_list[0]
                x_author_id = x_author["standard_id"]

        # content creation
        x_mc_description = f"### Title\n\n{defang(doc.get('title'))}\n\n"
        x_media_content = MediaContent(
            id=MediaContent.generate_id(x_url),
            url=x_url,
            content=x_content,
            description=x_mc_description,
            publication_date=x_timestamp,
            media_category="web content",
            object_marking_refs=self.mandiant_darknet_tlp,
            created_by_ref=x_author_id if x_author_id else self.mandiant_id,
            external_references=[{"source_name": "Mandiant", "url": doc_url}],
            x_opencti_files=octi_filelist,
        )
        objects.insert(0, x_media_content)

        # relationships
        if x_author_id:
            x_relationship = Relationship(
                id=PyctiSCR.generate_id(
                    "related-to", x_media_content["id"], x_author_id, None, None
                ),
                relationship_type="related-to",
                source_ref=x_media_content["id"],
                target_ref=x_author_id,
                created_by_ref=self.mandiant_id,
                object_marking_refs=self.mandiant_darknet_tlp,
            )
            objects.append(x_relationship)

        return objects

    def _getPasteObjects(self, doc: dict, doc_url: str) -> []:
        """
        Transforms a paste dictionnary in STIX content
        Returns a list of all the created STIX objects. Web content is at the beginning.
        """
        objects = []
        x_content = BeautifulSoup(doc.get("body"), "lxml").get_text()
        if "source_location" in doc and "url" in doc["source_location"]:
            x_url = doc["source_location"]["url"]
        elif "paste_id" in doc:
            x_url = doc["paste_id"]
        else:
            x_url = doc["__id"]
        x_actor = (
            doc.get("author").get("identity").get("name")
            if "author" in doc and "identity" in doc["author"]
            else ""
        )
        x_timestamp = doc.get("timestamp")
        x_service = doc.get("service").get("name") if "service" in doc else ""

        # add files
        octi_filelist = []
        octi_filelist.append(
            {
                "name": doc["__id"] + "-content.txt",
                "data": base64.b64encode(bytes(pprint.pformat(x_content), "utf-8")),
                "mime_type": "txt",
            }
        )
        octi_filelist.append(
            {
                "name": doc["__id"] + "-json.txt",
                "data": base64.b64encode(bytes(pprint.pformat(doc), "utf-8")),
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
                    id=PyctiIdentity.generate_id(sanitizeName(x_actor), "individual"),
                    name=sanitizeName(x_actor),
                    object_marking_refs=self.mandiant_darknet_tlp,
                    identity_class="individual",
                    created_by_ref=self.mandiant_id,
                    description="Paste Author",
                )
                x_author_id = x_author["id"]
                objects.append(x_author)
            else:
                x_author = identity_list[0]
                x_author_id = x_author["standard_id"]

        # channel creation
        channel_id = ""
        if x_service:
            channel_list = self.helper.api.channel.list(
                filters={
                    "mode": "and",
                    "filters": {
                        "key": "name",
                        "values": x_service,
                        "operator": "eq",
                        "mode": "and",
                    },
                    "filterGroups": [],
                },
            )
            if len(channel_list) == 0:
                x_service_url = (
                    doc.get("service").get("inet_location").get("url")
                    if "service" in doc and "inet_location" in doc["service"]
                    else ""
                )
                x_channel = Channel(
                    id=PyctiChannel.generate_id(x_service),
                    name=x_service,
                    object_marking_refs=self.mandiant_darknet_tlp,
                    created_by_ref=self.mandiant_id,
                    external_references=[
                        {"source_name": x_service, "url": x_service_url}
                    ],
                    channel_types="Paste Site",
                )
                self.helper.log_debug("Channel object created.")
                objects.append(x_channel)
                self.helper.log_debug("Channel object added to bundle.")
                channel_id = x_channel["id"]
            else:
                channel_id = channel_list[0]["standard_id"]

        # content creation
        x_mc_description = f"### Title\n\n{defang(doc.get('title'))}\n\n"
        x_media_content = MediaContent(
            id=MediaContent.generate_id(x_url),
            url=x_url,
            content=x_content,
            description=x_mc_description,
            publication_date=x_timestamp,
            media_category="paste",
            object_marking_refs=self.mandiant_darknet_tlp,
            created_by_ref=x_author_id if x_author_id else self.mandiant_id,
            external_references=[{"source_name": "Mandiant", "url": doc_url}],
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
                created_by_ref=self.mandiant_id,
                object_marking_refs=self.mandiant_darknet_tlp,
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
                created_by_ref=self.mandiant_id,
                object_marking_refs=self.mandiant_darknet_tlp,
            )
            objects.append(x_relationship)

        return objects

    def _getShopListingObjects(self, doc: dict, doc_url: str) -> []:
        """
        Transforms a shop listing dictionnary in STIX content
        Returns a list of all the created STIX objects. Web content is at the beginning.
        """
        objects = []
        x_content = BeautifulSoup(
            doc.get("description", "No description"), "lxml"
        ).get_text()
        x_url = doc.get("listing_url").get("url")
        x_id = doc.get("listing_id")
        x_seller = (
            doc.get("seller").get("identity").get("name")
            if "seller" in doc and "identity" in doc["seller"]
            else ""
        )
        x_timestamp = doc.get("timestamp")
        x_shop = doc.get("shop").get("name") if "shop" in doc else ""
        x_description = defang(
            f"### Seller\n\n{x_seller}\n\n"
            f"### Description\n\n{x_content}\n\n"
            f"### Listing ID\n\n{x_id}"
        )

        # add files
        octi_filelist = []
        octi_filelist.append(
            {
                "name": doc["__id"] + "-json.txt",
                "data": base64.b64encode(bytes(pprint.pformat(doc), "utf-8")),
                "mime_type": "txt",
            }
        )

        # create threat actor
        if x_seller:
            x_actor = ThreatActor(
                id=PyctiTAI.generate_id(x_seller),
                name=x_seller,
                description=f"Seller on {x_shop}",
                created_by_ref=self.mandiant_id,
                custom_properties={"x_opencti_type": "Threat-Actor-Individual"},
                object_marking_refs=self.mandiant_darknet_tlp,
            )
            objects.append(x_actor)

        # channel creation
        channel_id = ""
        if x_shop:
            channel_list = self.helper.api.channel.list(
                filters={
                    "mode": "and",
                    "filters": {
                        "key": "name",
                        "values": x_shop,
                        "operator": "eq",
                        "mode": "and",
                    },
                    "filterGroups": [],
                },
            )
            if len(channel_list) == 0:
                x_channel = Channel(
                    id=PyctiChannel.generate_id(x_shop),
                    name=x_shop,
                    object_marking_refs=self.mandiant_darknet_tlp,
                    created_by_ref=self.mandiant_id,
                    external_references=[{"source_name": x_shop, "url": x_url}],
                    channel_types="Shop",
                )
                self.helper.log_debug("Channel object created.")
                objects.append(x_channel)
                self.helper.log_debug("Channel object added to bundle.")
                channel_id = x_channel["id"]
            else:
                channel_id = channel_list[0]["standard_id"]

        # listing creation
        x_media_content = MediaContent(
            id=MediaContent.generate_id(x_id),
            url=x_id,
            content=x_content,
            description=x_description,
            publication_date=x_timestamp,
            media_category="shop listing",
            object_marking_refs=self.mandiant_darknet_tlp,
            created_by_ref=self.mandiant_id,
            external_references=[
                {"source_name": "Mandiant", "url": doc_url},
                {"source_name": "Listing url", "url": x_url},
            ],
            x_opencti_files=octi_filelist,
        )
        objects.insert(0, x_media_content)

        # relationship
        if channel_id:
            x_relationship = Relationship(
                id=PyctiSCR.generate_id(
                    "related-to", x_media_content["id"], channel_id, None, None
                ),
                relationship_type="related-to",
                source_ref=x_media_content["id"],
                target_ref=channel_id,
                created_by_ref=self.mandiant_id,
                object_marking_refs=self.mandiant_darknet_tlp,
            )
            objects.append(x_relationship)
        if x_seller:
            x_relationship = Relationship(
                id=PyctiSCR.generate_id(
                    "related-to", x_media_content["id"], x_actor["id"], None, None
                ),
                relationship_type="related-to",
                source_ref=x_media_content["id"],
                target_ref=x_actor["id"],
                created_by_ref=self.mandiant_id,
                object_marking_refs=self.mandiant_darknet_tlp,
            )
            objects.append(x_relationship)

        return objects

    def _getDomainDiscoveryObjects(self, doc: dict, doc_url: str) -> []:
        """
        Transforms a domain dictionnary in STIX content
        Returns a list of all the created STIX objects. Domain content is at the beginning.
        """
        objects = []
        x_description = ""

        # add resource records and whois in description
        if "rr" in doc:
            x_description += "### Ressource Records\n\n"
            for rr in doc["rr"]:
                rdata = ""
                if "rdata_domain" in rr:
                    rdata = rr.get("rdata_domain")
                elif "rdata_ipv4" in rr:
                    rdata = rr.get("rdata_ipv4")
                if rdata:
                    x_description += f"{rr.get('type')} : {rdata}\n\n"
        if "domain_whois" in doc:
            if "nameservers" in doc["domain_whois"]:
                x_description += "### Nameservers\n\n"
                for ns in doc["domain_whois"]["nameservers"]:
                    x_description += f"{ns}\n\n"
            if "registrar" in doc["domain_whois"]:
                x_description += "### Registrar\n\n"
                x_reg_name = (
                    doc.get("domain_whois").get("registrar").get("identity").get("name")
                    if "identity" in doc["domain_whois"]["registrar"]
                    else ""
                )
                x_reg_site = (
                    doc.get("domain_whois")
                    .get("registrar")
                    .get("contact")
                    .get("website")
                    if "contact" in doc["domain_whois"]["registrar"]
                    else ""
                )
                x_description += f"{x_reg_name}\n"
                x_description += f"{x_reg_site}\n"
        x_description = defang(x_description)

        # add files
        octi_filelist = []
        octi_filelist.append(
            {
                "name": doc["__id"] + "-json.txt",
                "data": base64.b64encode(bytes(pprint.pformat(doc), "utf-8")),
                "mime_type": "txt",
            }
        )
        if "domain_whois" in doc and "raw_text" in doc["domain_whois"]:
            octi_filelist.append(
                {
                    "name": "raw_text.txt",
                    "data": base64.b64encode(
                        bytes(pprint.pformat(doc["domain_whois"]["raw_text"]), "utf-8")
                    ),
                    "mime_type": "txt",
                }
            )

        # domain creation
        x_domain = DomainName(
            id=generate_domain_name_id(doc.get("domain")),
            value=doc.get("domain"),
            custom_properties={
                "description": x_description,
                "created_by_ref": self.mandiant_id,
                "x_opencti_files": octi_filelist,
                "external_references": [{"source_name": "Mandiant", "url": doc_url}],
            },
            object_marking_refs=self.mandiant_darknet_tlp,
        )
        objects.insert(0, x_domain)

        return objects

    def _getCompromisedCredentialsObjects(self, doc: dict, doc_url: str) -> []:
        """
        Transforms a compromised credentials dictionnary in STIX content
        Returns a list of all the created STIX objects. Compromised credential content is at the beginning.
        """
        objects = []
        x_service_url = (
            doc.get("service_account").get("service").get("inet_location").get("url")
            if "service_account" in doc
            and "service" in doc["service_account"]
            and "inet_location" in doc["service_account"]["service"]
            else ""
        )
        x_source_url = doc.get("source_url")

        # add files
        octi_filelist = []
        octi_filelist.append(
            {
                "name": doc["__id"] + "-json.txt",
                "data": base64.b64encode(bytes(pprint.pformat(doc), "utf-8")),
                "mime_type": "txt",
            }
        )

        # create file objecti
        name = doc.get("source_file").get("filename") if "source_file" in doc else ""
        md5 = doc.get("source_file", {}).get("hashes", {}).get("md5", "")
        sha1 = doc.get("source_file", {}).get("hashes", {}).get("sha1", "")
        sha256 = doc.get("source_file", {}).get("hashes", {}).get("sha256", "")

        x_file = File(
            id=generate_file_id(name, sha256, sha1, md5),
            name=name,
            # OpenCTI does not support file sizes > 2³¹. An issue has been posted: https://github.com/OpenCTI-Platform/connectors/issues/2097
            # Next line can be added when issue is resolved.
            # size=doc.get("source_file").get("size") if "source_file" in doc else None,
            hashes={
                "MD5": md5,
                "SHA-1": sha1,
                "SHA-256": sha256,
            },
            custom_properties={"created_by_ref": self.mandiant_id},
            object_marking_refs=self.mandiant_darknet_tlp,
        )
        objects.append(x_file)
        self.helper.log_debug(f"File object: {x_file}")

        # account creation
        x_account = UserAccount(
            account_login=(
                doc.get("service_account").get("login")
                if "service_account" in doc
                else ""
            ),
            custom_properties={
                "created_by_ref": self.mandiant_id,
                "x_opencti_files": octi_filelist,
                "external_references": [
                    {"source_name": "Mandiant", "url": doc_url},
                    {"source_name": "Compromised service", "url": x_service_url},
                    {"source_name": "Source of leak", "url": x_source_url},
                ],
            },
            object_marking_refs=self.mandiant_darknet_tlp,
        )
        objects.insert(0, x_account)

        # relationship
        x_relationship = Relationship(
            id=PyctiSCR.generate_id(
                "related-to", x_account["id"], x_file["id"], None, None
            ),
            relationship_type="related-to",
            source_ref=x_account["id"],
            target_ref=x_file["id"],
            created_by_ref=self.mandiant_id,
            object_marking_refs=self.mandiant_darknet_tlp,
        )
        objects.append(x_relationship)

        return objects

    def _get_stix_objects(self, alert) -> []:
        """
        Transforms a Mandiant alert into an Incident Stix object, several child objects and relationships
        """
        objects = []

        x_alert = None
        x_name = alert.get("title", "No title")
        x_description = f"### Summary\n\n {alert.get('alert_summary')} \n\n"
        x_source = ""

        # general alert informations

        x_id = alert.get("id")
        x_files = [
            {
                "name": x_id + ".txt",
                "data": base64.b64encode(bytes(pprint.pformat(alert), "utf-8")),
                "mime_type": "txt",
            }
        ]
        if "analysis" in alert:
            x_files.append(
                {
                    "name": "analysis.txt",
                    "data": base64.b64encode(
                        bytes(pprint.pformat(alert["analysis"]), "utf-8")
                    ),
                    "mime_type": "txt",
                }
            )

        x_created_at = alert.get("created_at")
        x_description += f"### Monitor ID\n\n{alert.get('monitor_id')}"
        target_ids = []
        x_ext_refs = []

        # specific informations

        match alert["alert_type"]:

            case "Compromised Credentials":
                x_source = "Compromised Credentials"
                mapping_content = self._getCompromisedCredentialsObjects(
                    alert["doc"], alert["doc_url"]
                )

            case "Domain Discovery":
                x_source = "Domain Discovery"
                mapping_content = self._getDomainDiscoveryObjects(
                    alert["doc"], alert["doc_url"]
                )

            case "Forum Post":
                x_source = "Forum Post"
                mapping_content = self._getForumPostObjects(
                    alert["doc"], alert["doc_url"]
                )

            case "Message":
                x_source = "Message"
                mapping_content = self._getMessageObjects(
                    alert["doc"], alert["doc_url"]
                )

            case "Paste":
                x_source = "Paste"
                mapping_content = self._getPasteObjects(alert["doc"], alert["doc_url"])

            case "Shop Listing":
                x_source = "Shop Listing"
                mapping_content = self._getShopListingObjects(
                    alert["doc"], alert["doc_url"]
                )

            case "Tweet":
                x_source = "Tweet"
                mapping_content = self._getTweetObjects(alert["doc"], alert["doc_url"])

            case "Web Content":
                x_source = "Web Content"
                mapping_content = self._getWebContentObjects(
                    alert["doc"], alert["doc_url"]
                )

        if mapping_content:
            target_ids.append(mapping_content[0]["id"])
            objects.extend(mapping_content)

        # incident creation
        x_alert = Incident(
            id=PyctiIncident.generate_id(x_name, x_created_at),
            name=x_name,
            description=x_description,
            type="incident",
            object_marking_refs=self.mandiant_darknet_tlp,
            created_by_ref=self.mandiant_id,
            external_references=x_ext_refs,
            custom_properties={
                "incident_type": "alert",
                "source": x_source,
                "first_seen": x_created_at,
                "x_opencti_files": x_files,
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
                    created_by_ref=self.mandiant_id,
                    object_marking_refs=self.mandiant_darknet_tlp,
                )
                objects.append(x_relationship)

        return objects

    def _collect_alerts(self, start_time) -> []:
        """
        Collects alerts from Mandiant and returs a bundle of STIX objects.
        """
        self.helper.log_debug(f"Collection started from date: {start_time}")

        # collecting alerts
        self.helper.log_debug("Second step: collecting alerts")
        bundle = []

        sinceParam = datetime.utcfromtimestamp(start_time).strftime(
            stix2.utils._TIMESTAMP_FORMAT_FRAC
        )
        count = 0

        url = None

        while True:

            if not url:
                url = f"{self.mandiant_api_url}/alerts?size=25&order=asc&since={sinceParam}"

            self.helper.log_debug("URL: " + url)

            api_response = requests.get(
                url, auth=(self.mandiant_api_key_id, self.mandiant_api_key_secret)
            )
            if api_response.text:
                alerts = json.loads(api_response.text)
                if "alerts" in alerts:
                    alert_list = alerts["alerts"]
                    if len(alert_list):
                        self.helper.log_debug("Nombre alertes: " + str(len(alert_list)))
                        for a in alert_list:
                            count += 1
                            objs = None
                            try:
                                objs = self._get_stix_objects(a)
                            except Exception as e:
                                self.helper.log_error(f"Error retrieving alert: {e}")
                                self.helper.log_error(traceback.format_exc())
                            if objs:
                                bundle.extend(objs)
                    else:
                        break
                else:
                    break
            else:
                break
            if "link" in api_response.headers:
                url = api_response.headers["link"].split(";")[0].lstrip("<").rstrip(">")
                self.helper.log_debug("Next URL: " + url)
            else:
                break

        return bundle

    def _collect_intelligence(self, start) -> []:
        """
        Collects alerts from Mandiant
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
        self.helper.log_debug("Starting Mandiant alerts collection...")
        self.helper.log_debug(
            "Start = "
            + str(start)
            + " / mandiant_darknet_import_start_date = "
            + str(self.mandiant_darknet_import_start_date)
        )

        if start == 0:
            start_time = int(self.mandiant_darknet_import_start_date)
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
        connector = MandiantAlertsConnector()
        connector.run()
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        time.sleep(10)
        sys.exit(0)
