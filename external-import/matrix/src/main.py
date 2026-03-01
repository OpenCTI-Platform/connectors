import asyncio
import base64
import os
import sys
import time
import traceback
import uuid
from datetime import datetime

import stix2
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
from pycti import OpenCTIConnectorHelper
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


class MatrixConnector:
    def __init__(self):
        """Initialization of the connector"""
        # super().__init__()
        self.update_existing_data = True
        self.helper = OpenCTIConnectorHelper({})
        self.matrix_device_name = os.environ.get("MATRIX_DEVICE_NAME", "octi_bot")
        self.matrix_server = os.environ.get(
            "MATRIX_SERVER", "https://matrix.agent.tchap.gouv.fr"
        )
        self.matrix_password = os.environ.get("MATRIX_PASSWORD")
        self.matrix_user_id = os.environ.get("MATRIX_USER_ID")
        self.matrix_debug = (
            False if (os.environ.get("MATRIX_DEBUG", "false") == "false") else True
        )
        self.matrix_tlp = get_tlp(os.environ.get("MATRIX_TLP", "AMBER"))
        self.helper.log_debug(
            f"Init MatrixConnector for user {self.matrix_user_id} /password {self.matrix_password} to {self.matrix_server}"
        )
        self.client_config = AsyncClientConfig(
            store=store.SqliteMemoryStore,
            max_limit_exceeded=0,
            max_timeouts=0,
            store_sync_tokens=True,
            encryption_enabled=True,
        )
        self.e2ee_connected = False
        self.bundle = []

    def send_bundle(self):
        now = datetime.utcfromtimestamp(int(time.time()))
        friendly_name = f"{self.helper.connect_name} run @ " + now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        self.helper.log_debug(f"friendly name:{friendly_name} now:{now}")
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        if self.bundle:
            bundle = stix2.Bundle(objects=self.bundle, allow_custom=True).serialize()

            self.helper.log_info(
                f"Sending {len(self.bundle)} STIX objects to OpenCTI..."
            )
            self.helper.send_stix2_bundle(
                bundle,
                update=self.update_existing_data,
                work_id=work_id,
            )
        timestamp = int(time.time())
        message = (
            f"{self.helper.connect_name} connector successfully run, storing last_run as "
            + str(timestamp)
        )
        self.helper.log_debug(
            f"Grabbing current state and update it with last_run: {timestamp}"
        )
        self.helper.log_info(message)
        current_state = self.helper.get_state()
        if current_state:
            current_state["last_run"] = timestamp
        else:
            current_state = {"last_run": timestamp}
        self.helper.set_state(current_state)
        self.helper.api.work.to_processed(work_id, message)
        self.bundle = []

    async def download_mxc(self, url: str):
        self.helper.log_debug(f"Encrypted file url: {url}")
        response = await self.client.download(mxc=url)
        if hasattr(response, "body"):
            # self.helper.log_debug(f"File content: {response.body}")
            return response.body
        else:
            self.helper.log_debug(f"Error: No file content.\n response = {response}")
            return b""

    async def event_callback(self, room, event):  # noqa
        """Handle events in rooms."""
        try:
            self.helper.log_debug("In event_callback routine...")
            self.helper.log_debug(
                f"Room :{room.room_id} Display name: {room.display_name} "
            )
            self.helper.log_debug(
                f"Event received:{event} / Event ID: {event.event_id} / TS: {event.server_timestamp}"
            )
            self.helper.log_debug(f"Event source: {event.source}")

            mc_id = thread_id = None
            author = event.sender
            room_id = room.room_id
            room_name = room.display_name
            x_date = datetime.utcfromtimestamp(event.server_timestamp // 1000).strftime(
                stix2.utils._TIMESTAMP_FORMAT_FRAC
            )

            # check channel existence

            channel_list = self.helper.api.channel.list(
                filters={
                    "mode": "and",
                    "filters": {
                        "key": "name",
                        "values": room_id,
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
                    id=PyctiChannel.generate_id(room_id),
                    name=room_id,
                    description=room_name,
                    object_marking_refs=self.matrix_tlp,
                    channel_types=["Matrix"],
                )
                self.helper.log_debug("Channel object created.")
                self.bundle.append(x_channel)
                self.helper.log_debug("Channel object added to bundle.")
                ch_id = x_channel["id"]
            else:
                ch_id = channel_list[0]["standard_id"]

            # check author existence

            identity_list = self.helper.api.identity.list(
                filters={
                    "mode": "and",
                    "filters": {
                        "key": "name",
                        "values": author,
                        "operator": "eq",
                        "mode": "and",
                    },
                    "filterGroups": [],
                },
            )
            if len(identity_list) == 0:
                x_author = stix2.Identity(
                    id=PyctiIdentity.generate_id(author, "individual"),
                    name=author,
                    object_marking_refs=self.matrix_tlp,
                    identity_class="individual",
                    description="Auteur Matrix",
                )
                x_author_id = x_author["id"]
                self.bundle.append(x_author)
            else:
                x_author = identity_list[0]
                x_author_id = x_author["standard_id"]

            # check thread existence

            if (
                "m.relates_to" in event.source["content"]
                and event.source["content"]["m.relates_to"]["rel_type"] == "m.thread"
            ):
                mediacontent_list = self.helper.api.stix_cyber_observable.list(
                    filters={
                        "mode": "and",
                        "filters": [
                            {
                                "key": "url",
                                "values": event.source["content"]["m.relates_to"][
                                    "event_id"
                                ],
                                "operator": "eq",
                                "mode": "and",
                            }
                        ],
                        "filterGroups": [],
                    },
                )
                if len(mediacontent_list) == 1:
                    thread_id = mediacontent_list[0]["standard_id"]

            # collect new media content

            if isinstance(event, RoomMessageText) or isinstance(
                event, RoomMessageNotice
            ):
                self.helper.log_debug("In RoomMessageText")
                # check if it is an update
                if (
                    "m.new_content" in event.source["content"]
                    and event.source["content"]["m.relates_to"]["rel_type"]
                    == "m.replace"
                ):
                    x_url = event.source["content"]["m.relates_to"]["event_id"]
                    x_description = event.body + "\n\n[updated]"
                else:
                    x_url = event.event_id
                    x_description = event.body
                x_media_content = MediaContent(
                    id=MediaContent.generate_id(x_url),
                    url=x_url,
                    content=event.body,
                    description=x_description,
                    publication_date=x_date,
                    media_category="matrix",
                    object_marking_refs=self.matrix_tlp,
                    created_by_ref=x_author_id,
                )
                self.helper.log_debug(f"Media content created: {x_media_content}")
                mc_id = x_media_content["id"]

            elif (
                isinstance(event, RoomEncryptedImage)
                or isinstance(event, RoomEncryptedFile)
                or isinstance(event, RoomEncryptedAudio)
                or isinstance(event, RoomEncryptedVideo)
            ):
                self.helper.log_debug("In RoomEncrypted")
                # download and decrypt file content
                media_data = await self.download_mxc(event.url)
                media_data_decrypted = None
                try:
                    media_data_decrypted = crypto.attachments.decrypt_attachment(
                        media_data,
                        event.source["content"]["file"]["key"]["k"],
                        event.source["content"]["file"]["hashes"]["sha256"],
                        event.source["content"]["file"]["iv"],
                    )
                except KeyError as e:  # EAFP: Unencrypted media produces KeyError
                    self.helper.log_info(f"KeyError while trying to decrypt image: {e}")

                if media_data_decrypted:
                    x_media_content = MediaContent(
                        id=MediaContent.generate_id(event.event_id),
                        url=event.event_id,
                        content=event.source["content"]["body"],
                        description=event.source["content"]["body"],
                        publication_date=x_date,
                        media_category="matrix",
                        object_marking_refs=self.matrix_tlp,
                        created_by_ref=x_author_id,
                        x_opencti_files=[
                            {
                                "name": event.source["content"]["body"],
                                "data": base64.b64encode(media_data_decrypted),
                                "mime_type": event.source["content"]["info"][
                                    "mimetype"
                                ],
                            }
                        ],
                    )
                    self.helper.log_debug(f"Media content created: {x_media_content}")
                    mc_id = x_media_content["id"]

            elif (
                isinstance(event, RoomMessageImage)
                or isinstance(event, RoomMessageFile)
                or isinstance(event, RoomMessageAudio)
                or isinstance(event, RoomMessageVideo)
            ):
                self.helper.log_debug("In RoomMessage")
                # download file content
                media_data = await self.download_mxc(event.url)
                if media_data:
                    x_media_content = MediaContent(
                        id=MediaContent.generate_id(event.event_id),
                        url=event.event_id,
                        content=event.source["content"]["body"],
                        description=event.source["content"]["body"],
                        publication_date=x_date,
                        media_category="matrix",
                        object_marking_refs=self.matrix_tlp,
                        created_by_ref=x_author_id,
                        x_opencti_files=[
                            {
                                "name": event.source["content"]["body"],
                                "data": base64.b64encode(media_data),
                                "mime_type": event.source["content"]["info"][
                                    "mimetype"
                                ],
                            }
                        ],
                    )
                    self.helper.log_debug(f"Media content created: {x_media_content}")
                    mc_id = x_media_content["id"]

            # relationships and bundle
            if mc_id:
                self.bundle.append(x_media_content)
                x_relationship = stix2.Relationship(
                    id=PyctiSCR.generate_id("related-to", mc_id, ch_id, None, None),
                    relationship_type="related-to",
                    source_ref=mc_id,
                    target_ref=ch_id,
                    object_marking_refs=self.matrix_tlp,
                )
                self.bundle.append(x_relationship)
                if thread_id:
                    x_relationship = stix2.Relationship(
                        id=PyctiSCR.generate_id(
                            "related-to", mc_id, thread_id, None, None
                        ),
                        relationship_type="related-to",
                        source_ref=mc_id,
                        target_ref=thread_id,
                        object_marking_refs=self.matrix_tlp,
                    )
                    self.bundle.append(x_relationship)
                self.send_bundle()
            else:
                self.bundle = []

        except BaseException:
            self.helper.log_debug(traceback.format_exc())

    async def run_client(self):
        self.helper.log_debug("Creating Matrix client...")
        self.client = AsyncClient(
            homeserver=self.matrix_server,
            user=self.matrix_user_id,
            config=self.client_config,
        )
        self.helper.log_debug("Login...")
        await self.client.login(
            password=self.matrix_password,
            device_name=self.matrix_device_name,
            token=None,
        )
        self.client.load_store()
        self.helper.log_debug("Keys upload...")
        if self.client.should_upload_keys:
            await self.client.keys_upload()
        self.client.add_event_callback(
            self.event_callback,
            (
                RoomMessageText,
                RoomMessageImage,
                RoomMessageAudio,
                RoomMessageFile,
                RoomEncryptedImage,
                RoomEncryptedFile,
                RoomEncryptedAudio,
                RoomEncryptedVideo,
                RoomMessageNotice,
                RoomMessageUnknown,
                RoomMessageVideo,
                UnknownEvent,
            ),
        )
        self.helper.log_debug("Looking for device keys...")

        await self.client.sync_forever(
            full_state=True,
        )


if __name__ == "__main__":
    try:
        connector = MatrixConnector()
        asyncio.get_event_loop().run_until_complete(connector.run_client())
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
