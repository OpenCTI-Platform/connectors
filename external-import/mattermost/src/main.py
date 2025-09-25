import base64
import os
import sys
import time
import uuid
from datetime import datetime

import stix2
from lib.external_import import ExternalImportConnector
from mattermostdriver import Driver
from pycti.entities.opencti_channel import Channel as PyctiChannel
from pycti.entities.opencti_identity import Identity as PyctiIdentity
from pycti.entities.opencti_stix_core_relationship import (
    StixCoreRelationship as PyctiSCR,
)
from stix2 import CustomObject, CustomObservable
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
    ],
)
class Channel:
    pass


class MattermostConnector(ExternalImportConnector):
    def __init__(self):
        """Initialization of the connector"""
        super().__init__()

        self.mattermost_domain = os.environ.get("MATTERMOST_DOMAIN")
        self.mattermost_port = os.environ.get("MATTERMOST_PORT", "8065")
        self.mattermost_protocol = os.environ.get("MATTERMOST_PROTOCOL", "https")
        self.mattermost_basepath = os.environ.get("MATTERMOST_BASEPATH", "/api/v4")
        self.mattermost_token = os.environ.get("MATTERMOST_TOKEN")
        self.mattermost_start_timestamp = int(
            os.environ.get("MATTERMOST_START_TIMESTAMP", "0")
        )
        self.mattermost_channel_ids = os.environ.get("MATTERMOST_CHANNEL_IDS").split(
            sep=","
        )
        self.mattermost_tlp = self._get_tlp(os.environ.get("MATTERMOST_TLP", "AMBER"))
        self.mattermost_verify = (
            True if (os.environ.get("MATTERMOST_VERIFY", "true") == "true") else False
        )
        self.mattermost_auth = (
            None
            if (os.environ.get("MATTERMOST_AUTH", "") == "")
            else os.environ.get("MATTERMOST_AUTH", "")
        )
        self.mattermost_timeout = int(os.environ.get("MATTERMOST_TIMEOUT", "30"))
        self.mattermost_request_timeout = (
            None
            if (os.environ.get("MATTERMOST_REQUEST_TIMEOUT", "") == "")
            else int(os.environ.get("MATTERMOST_REQUEST_TIMEOUT", ""))
        )
        self.mattermost_keepalive = (
            False
            if (os.environ.get("MATTERMOST_KEEPALIVE", "false") == "false")
            else True
        )
        self.mattermost_keepalive_delay = int(
            os.environ.get("MATTERMOST_KEEPALIVE_DELAY", "5")
        )
        self.mattermost_debug = (
            False if (os.environ.get("MATTERMOST_DEBUG", "false") == "false") else True
        )

        self.base_path = os.getcwd()

        # Connect to Mattermost
        self.driver = Driver(
            {
                "url": self.mattermost_domain,
                "token": self.mattermost_token,
                "scheme": self.mattermost_protocol,
                "port": int(self.mattermost_port),
                "basepath": self.mattermost_basepath,
                "verify": self.mattermost_verify,
                "auth": self.mattermost_auth,
                "timeout": self.mattermost_timeout,
                "request_timeout": self.mattermost_request_timeout,
                "keepalive": self.mattermost_keepalive,
                "keepalive_delay": self.mattermost_keepalive_delay,
                "websocket_kw_args": None,
                "debug": self.mattermost_debug,
            }
        )
        self.driver.login()

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

    def _collect_channel_posts(self, channel_id, start_time) -> []:
        """
        Scans a mattermost channel and returns a bundle of STIX objects:
        - the channel if not existing
        - the media contents based on the last created or modified posts
        - the relationships between all those
        """

        self.helper.log_debug(f"Collect channel posts starting from date: {start_time}")

        bundle = []

        channel = self.driver.channels.get_channel(channel_id)
        cn = channel["name"]
        self.helper.log_debug(f"Channel {channel_id} is {cn}")

        team = self.driver.teams.get_team(channel["team_id"])
        tn = team["name"]
        self.helper.log_debug(f"The team is {tn}")

        posts = self.driver.posts.get_posts_for_channel(
            channel_id, params={"since": str(start_time * 1000)}
        )
        l = len(posts["order"])
        self.helper.log_debug(f"Got {l} posts")

        for p in posts["order"]:
            self.helper.log_debug(p)

        x_description = (
            "Purpose: " + channel["purpose"] + "\n\nHeader: " + channel["header"]
        )

        # check channel existence
        channel_list = self.helper.api.channel.list(
            filters={
                "mode": "and",
                "filters": {
                    "key": "name",
                    "values": cn,
                    "operator": "eq",
                    "mode": "and",
                },
                "filterGroups": [],
            },
        )
        self.helper.log_debug(f"Filter: found {len(channel_list)} channels.")
        for c in channel_list:
            self.helper.log_debug(c)

        if len(channel_list) == 0:
            x_channel = Channel(
                id=PyctiChannel.generate_id(channel["name"]),
                name=channel["name"],
                description=x_description,
                object_marking_refs=self.mattermost_tlp,
                channel_types=["Mattermost"],
            )
            self.helper.log_debug("Channel object created.")
            bundle.append(x_channel)
            self.helper.log_debug("Channel object added to bundle.")
            tgt = x_channel["id"]
        else:
            tgt = channel_list[0]["standard_id"]

        self.helper.log_debug(f"after channel test: target_ref: {tgt}")

        link = {}
        included_posts = []

        base_url = (
            self.mattermost_protocol
            + "://"
            + self.mattermost_domain
            + ":"
            + self.mattermost_port
            + "/"
        )

        # posts objects and channel relationships
        for p in posts["order"]:
            # if a deleted post is in the list, ignore it
            if posts["posts"][p]["delete_at"] > 0:
                continue
            included_posts.append(p)
            self.helper.log_debug("Post: " + str(posts["posts"][p]))
            x_url = base_url + team["name"] + "/pl/" + p
            self.helper.log_debug(f"URL: {x_url}")
            x_content = posts["posts"][p]["message"]
            if x_content == "":
                x_content = "(vide)"
            self.helper.log_debug(f"Message: {x_content}")
            ts = posts["posts"][p]["create_at"] / 1000
            x_date = datetime.utcfromtimestamp(ts).strftime(
                stix2.utils._TIMESTAMP_FORMAT_FRAC
            )
            self.helper.log_debug(f"Date: {x_date}")
            x_category = "mattermost"

            # does the author already exist in OCTI?
            email = self.driver.users.get_user(posts["posts"][p]["user_id"])["email"]
            identity_list = self.helper.api.identity.list(
                filters={
                    "mode": "and",
                    "filters": {
                        "key": "name",
                        "values": email,
                        "operator": "eq",
                        "mode": "and",
                    },
                    "filterGroups": [],
                },
            )
            if len(identity_list) == 0:
                x_author = stix2.Identity(
                    id=PyctiIdentity.generate_id(email, "individual"),
                    name=email,
                    object_marking_refs=self.mattermost_tlp,
                    identity_class="individual",
                    description="Auteur Mattermost",
                )
                x_author_id = x_author["id"]
                bundle.append(x_author)
            else:
                x_author = identity_list[0]
                x_author_id = x_author["standard_id"]

            # are there some files?
            octi_filelist = []
            if (
                "file_ids" in posts["posts"][p]
                and "metadata" in posts["posts"][p]
                and "files" in posts["posts"][p]["metadata"]
            ):
                self.helper.log_debug("Files? " + str(posts["posts"][p]))
                mattermost_filelist = posts["posts"][p]["metadata"]["files"]
                for f in mattermost_filelist:
                    try:
                        filename = f["id"] + "_" + f["name"]
                        if not self._file_exist(x_url, filename):
                            mattermost_file = self.driver.files.get_file(f["id"])
                            octi_filelist.append(
                                {
                                    "name": filename,
                                    "data": base64.b64encode(mattermost_file.content),
                                    "mime_type": f["mime_type"],
                                }
                            )
                    except Exception as e:
                        self.helper.log_debug(f"Adding of file failed: {e}")

            # create content and channel relationship
            x_media_content = MediaContent(
                id=MediaContent.generate_id(x_url),
                url=x_url,
                content=x_content,
                description=x_content,
                publication_date=x_date,
                media_category=x_category,
                object_marking_refs=self.mattermost_tlp,
                created_by_ref=x_author_id,
                x_opencti_files=octi_filelist,
            )
            self.helper.log_debug(f"Media content created: {x_media_content}")
            src = x_media_content["id"]
            # link mattermost ID to octi ID
            link[p] = [src, x_url]
            self.helper.log_debug(f"source_ref: {src} /  target_ref: {tgt}")
            x_relationship = stix2.Relationship(
                id=PyctiSCR.generate_id("related-to", src, tgt, None, None),
                relationship_type="related-to",
                source_ref=src,
                target_ref=tgt,
                object_marking_refs=self.mattermost_tlp,
            )
            self.helper.log_debug(f"Relationship created: {x_relationship}")

            # append content objects to bundle
            bundle.append(x_media_content)
            bundle.append(x_relationship)

        # subpost relationships
        for p in included_posts:
            root_mattermost_id = posts["posts"][p]["root_id"]
            self.helper.log_debug(f"Post ID: {p} / Root ID: {root_mattermost_id}")
            if root_mattermost_id:
                root_octi_id = None

                # the root post must be in the bundle so we search for it
                for q in posts["order"]:
                    if q == root_mattermost_id:
                        root_octi_id = link[q][0]
                        self.helper.log_debug(
                            f"Root id of subpost found in the bundle: {root_octi_id}"
                        )

                # create relationship
                if root_octi_id:
                    x_relationship = stix2.Relationship(
                        id=PyctiSCR.generate_id(
                            "related-to", link[p][0], root_octi_id, None, None
                        ),
                        relationship_type="related-to",
                        source_ref=link[p][0],
                        target_ref=root_octi_id,
                        object_marking_refs=self.mattermost_tlp,
                    )
                    bundle.append(x_relationship)
                    self.helper.log_debug("Subpost relationship created and appended.")
                else:
                    self.helper.log_debug(
                        f"Root of subpost {p} not found. Relationship could not be created."
                    )

        return bundle

    def _file_exist(self, url, filename) -> bool:
        result = False
        mediacontent_list = self.helper.api.stix_cyber_observable.list(
            filters={
                "mode": "and",
                "filters": [
                    {"key": "url", "values": url, "operator": "eq", "mode": "and"}
                ],
                "filterGroups": [],
            },
        )
        if len(mediacontent_list) == 1:
            mediacontent = self.helper.api.stix_cyber_observable.read(
                id=mediacontent_list[0]["id"], withFiles=True
            )
            self.helper.log_debug(f"File exist? Media content: {mediacontent}")
            self.helper.log_debug(f"File exist? Filename : {filename}")
            if "importFiles" in mediacontent:
                for f in mediacontent["importFiles"]:
                    if f["name"] == filename:
                        result = True
        return result

    def _collect_intelligence(self, start) -> []:
        """Collects intelligence from mattermost channels
        Returns:
            stix_objects: A list of STIX2 objects."""
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )
        stix_objects = []

        # ===========================
        # === Add your code below ===
        # ===========================
        self.helper.log_debug("Starting Mattermost collection...")
        self.helper.log_debug(
            "Start = "
            + str(start)
            + " / mattermost_start_timestamp = "
            + str(self.mattermost_start_timestamp)
        )

        if start == 0:
            start_time = self.mattermost_start_timestamp
        else:
            start_time = start

        for i in self.mattermost_channel_ids:
            stix_objects.extend(self._collect_channel_posts(i, start_time))

        # ===========================
        # === Add your code above ===
        # ===========================

        self.helper.log_info(
            f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
        )

        for obj in stix_objects:
            self.helper.log_debug(f"Stix Object: {obj}")

        return stix_objects


if __name__ == "__main__":
    try:
        connector = MattermostConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
