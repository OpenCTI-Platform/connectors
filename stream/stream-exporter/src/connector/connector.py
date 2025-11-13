import io
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from json.decoder import JSONDecodeError
from pathlib import Path
from queue import Queue

import yaml
from minio import Minio
from pycti import OpenCTIConnectorHelper, get_config_variable

from .metrics import Metrics


class UploadFailed(Exception):
    """Exception raised when the upload of the file failed."""

    def __init__(self, name: str):
        super().__init__(f"File {name} was not uploaded to minio.")


class StreamExporterConnector:
    """Stream Exporter connector."""

    def __init__(
        self,
    ) -> None:
        # Instantiate the connector helper from config
        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"

        config = (
            yaml.load(open(config_file_path, encoding="utf8"), Loader=yaml.FullLoader)
            if config_file_path.is_file()
            else {}
        )

        # Minio client does not support concurrent insert
        self.consumer_count: int = 1

        queue_size = get_config_variable(
            "QUEUE_SIZE",
            ["queue", "size"],
            config,
            default=1_000,
        )

        # Buffer to write the events
        self.buffer: bytes = b""
        self.lock = threading.Lock()

        self.queue = Queue(maxsize=queue_size)

        self.helper = OpenCTIConnectorHelper(config)

        self.metrics = Metrics(self.helper.connect_name)

        minio_endpoint = get_config_variable(
            "MINIO_ENDPOINT", ["minio", "endpoint"], config
        )
        minio_port = get_config_variable(
            "MINIO_PORT", ["minio", "port"], config, isNumber=True
        )
        self.minio_bucket = get_config_variable(
            "MINIO_BUCKET", ["minio", "bucket"], config
        )
        self.minio_folder = get_config_variable(
            "MINIO_FOLDER", ["minio", "folder"], config
        )
        minio_access_key = get_config_variable(
            "MINIO_ACCESS_KEY", ["minio", "access_key"], config
        )
        minio_secret_key = get_config_variable(
            "MINIO_SECRET_KEY", ["minio", "secret_key"], config
        )
        minio_secure = get_config_variable("MINIO_SECURE", ["minio", "secure"], config)
        minio_cert_check = get_config_variable(
            "MINIO_CERT_CHECK", ["minio", "cert_check"], config, default="true"
        )

        # Bulk config
        self.write_every = get_config_variable(
            "WRITE_EVERY_SEC",
            ["write", "every_sec"],
            config,
            isNumber=True,
            default=900,
        )

        self.helper.log_info(f"Queue size: {queue_size}")

        self.helper.log_info(f"Minio endpoint: {minio_endpoint}:{minio_port}")
        self.helper.log_info(f"Folder to save the stream: {self.minio_folder}")

        # Check if we have a `last_written_msg_id` saved, if so, set it as the `start_from`.
        state = self.helper.get_state() or {}
        if "last_written_msg_id" in state:
            state["start_from"] = state["last_written_msg_id"]
            self.helper.set_state(state)

            self.metrics.state(state["start_from"])
            self.metrics.state_last_written(state["last_written_msg_id"])
            self.metrics.state_recover_until(state["recover_until"])

            self.helper.log_info(f"Setting start_from date: {state}")
        else:
            self.helper.set_state(None)
            self.helper.log_info("Resetting state, fetching from beginning")

        self.minio_client = Minio(
            f"{minio_endpoint}:{minio_port}",
            minio_access_key,
            minio_secret_key,
            secure=minio_secure,
            cert_check=minio_cert_check,
        )
        self.helper.log_info(f"Minio: {self.minio_client._base_url}")

        # Create the bucket if it does not exist.
        self.helper.log_info(f"Minio bucket to use: {self.minio_bucket}")
        if not self.minio_client.bucket_exists(self.minio_bucket):
            self.minio_client.make_bucket(self.minio_bucket)
            self.helper.log_info(f"Minio bucket {self.minio_bucket} created")
        self.helper.log_info("Stream exporter connector initialized")

        self.helper.log_info(f"Writing events every {self.write_every} seconds")
        self.write_events()

    def register_producer(self):
        self.helper.listen_stream(self.produce)

    def produce(self, msg):
        self.queue.put(msg)

    def start_consumers(self):
        self.helper.log_info(f"starting {self.consumer_count} consumer threads")
        with ThreadPoolExecutor() as executor:
            for _ in range(self.consumer_count):
                executor.submit(self.consume)

    def consume(self):
        # ensure the process stop when there is an issue while
        # processing message
        try:
            self._consume()
        except Exception as e:
            self.helper.log_error("an error occurred while consuming messages")
            self.helper.log_error(str(e))
            import traceback

            traceback.print_exc()
            os._exit(1)  # exit the current process, killing all threads

    def _consume(self):
        while True:
            # Possible fields of events: `event`, `data`, `id`, `retry`
            # (ref: https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events)
            msg = self.queue.get()

            try:
                payload = json.loads(msg.data)
            except JSONDecodeError as e:
                self.helper.log_error(f"Invalid json {msg.data}: {e}")
                continue

            payload["id"] = msg.id
            payload["type"] = msg.event

            # In case of an initial message, the type of the event is not defined and must be set to 'create'
            if "type" not in payload:
                payload["type"] = "create"

            self.helper.log_debug(
                f"Received event: {msg.id} ({msg.event=}): {msg.data}"
            )

            # Retrieve the reverse patch in case of ID change
            if msg.event == "update":
                payload = self._reverse_patch(payload)

            # Add opencti files if any
            payload["data"] = self._add_opencti_files(payload["data"])
            self.helper.log_debug(f"Payload sent: {payload}")

            data = json.dumps(payload).encode("utf-8") + b"\n"

            self.metrics.msg(msg.event)
            self.metrics.state(msg.id)

            with self.lock:
                self.buffer += data

    def _reverse_patch(self, event) -> dict:
        """Reverse patch the id if necessary.

        In case of update, if the path: /id changes, need to use the reverse patch.
        The value of the previous operation is set into the `previous_standard` field.

        Parameters
        ----------
        event : dict
            Full event.

        Returns
        -------
        dict
            Event, with the reverse patch if needed.
        """
        patch = [
            p
            for p in event.get("context", {}).get("reverse_patch", [])
            if p.get("path", "") == "/id"
        ]
        match length := len(patch):
            case 1:
                self.helper.log_debug(f"Reverse patch with /id: {patch[0]}")
                event["previous_standard"] = patch[0]["value"]
            case _ if length > 1:
                self.helper.log_error(f"Wrong number of patches operation: {patch}")
        return event

    def _add_opencti_files(self, data) -> dict:
        """Add the content of the files, if any.

        The returned payload contains the files, which makes it possible
        to re-create them on the destination.

        Parameters
        ----------
        data : dict
            Payload of the event.

        Returns
        -------
        dict
            Payload of the event, with the content of the files.
        """
        files = self.helper.api.get_attribute_in_extension("files", data)
        files_with_content = []

        if files is not None and len(files) > 0:
            for file in files:
                self.helper.log_debug(f"Fetching file {file}")

                file_uri = file["uri"][file["uri"].index("storage/get") :]
                url = os.path.join(self.helper.opencti_url, file_uri)

                file_data = self.helper.api.fetch_opencti_file(
                    url, binary=True, serialize=True
                )
                file["data"] = file_data
                files_with_content.append(file)

            data["files"] = files_with_content

        return data

    def write_events(self):
        with self.lock:
            self.helper.log_info("Writing events")

            if not self.buffer:
                self.helper.log_info(
                    f"No event, running again in {self.write_every} seconds"
                )
                threading.Timer(self.write_every, self.write_events).start()
                return

            state = self.helper.get_state()

            # Update the file count to be able to check the order when re-importing
            # and save it in the state to avoid losing it when restarting.
            state["file_count"] = state.get("file_count", 0) + 1
            object_path = f"{self.minio_folder}/stream_{round(time.time() * 1000)}_{state['file_count']}.json"

            try:
                res = self.minio_client.put_object(
                    self.minio_bucket,
                    object_path,
                    data=io.BytesIO(self.buffer),
                    length=len(self.buffer),
                )
            except Exception as exc:
                # Fail to upload the file, stopping connector.
                self.metrics.write_error()
                raise UploadFailed(object_path) from exc

            self.helper.log_debug(f"Result of minio: {res}")
            self.metrics.write()

            # Set `last_written_msg_id` with the current message id.
            # This is to avoid losing messages in case the connector crashed and the `ListenStream` process has already change the state.
            state["last_written_msg_id"] = state["start_from"]
            self.metrics.state_last_written(state["last_written_msg_id"])
            self.metrics.state_recover_until(state["recover_until"])

            self.helper.set_state(state)

            self.helper.log_debug(f"New state: {state}")
            self.helper.log_info(
                f"Events (len={len(self.buffer)}) stored at {object_path}"
            )

            self.buffer = b""

        threading.Timer(self.write_every, self.write_events).start()

    def start(self):
        self.register_producer()
        self.start_consumers()


def check_helper(helper: OpenCTIConnectorHelper) -> None:
    if (
        helper.connect_live_stream_id is None
        or helper.connect_live_stream_id == "ChangeMe"
    ):
        helper.log_error("missing Live Stream ID")
        sys.exit(1)
