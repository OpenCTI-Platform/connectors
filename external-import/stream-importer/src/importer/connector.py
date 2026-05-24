import base64
import json
import os
from collections import namedtuple

import pika
from minio import Minio
from minio.commonconfig import CopySource
from minio.error import S3Error
from pika.exceptions import ChannelClosedByBroker, NackError, UnroutableError

from .lib.external_import import ExternalImportConnector
from .metrics import Metrics
from .utils import create_mq_ssl_context

Event = namedtuple("Event", "path entries")


class WrongFileOrder(Exception):
    """Exception raised when the file order is wrong."""

    def __init__(self, name: str, expected_file_number: int):
        super().__init__(
            f"File {name} is not in correct order, should be number {expected_file_number}."
        )


class StreamImporterConnector(ExternalImportConnector):
    """StreamImporterConnector read events from minio and sent them to RabbitMQ.

    The events are transformed to be sent to RabbitMQ for ingestion by OpenCTI.
    Once processed, the files are moved to another bucket.
    """

    def __init__(self):
        """Initialization of the connector"""
        super().__init__()

        self.metrics = Metrics(
            self.helper.connect_name,
            os.environ.get("METRICS_NAMESPACE"),
            os.environ.get("METRICS_SUBSYTEM"),
        )

        minio_endpoint = os.environ.get("MINIO_ENDPOINT")

        minio_port = os.environ.get("MINIO_PORT")
        # Extract the bucket and the path for the source and the destination.
        self.minio_src_bucket, self.minio_src_path = (
            os.environ.get("MINIO_SRC_PATH").split("/", 1)
            if "/" in os.environ.get("MINIO_SRC_PATH")
            else (os.environ.get("MINIO_SRC_PATH"), "")
        )
        self.minio_src_recurse = str_to_bool(
            os.environ.get("MINIO_SRC_RECURSE", default="false")
        )
        self.minio_dst_bucket, self.minio_dst_path = (
            os.environ.get("MINIO_DST_PATH").split("/", 1)
            if "/" in os.environ.get("MINIO_DST_PATH")
            else (os.environ.get("MINIO_DST_PATH"), "")
        )
        minio_access_key = os.environ.get("MINIO_ACCESS_KEY")
        minio_secret_key = os.environ.get("MINIO_SECRET_KEY")
        minio_secure = str_to_bool(os.environ.get("MINIO_SECURE", default="true"))
        minio_cert_check = str_to_bool(
            os.environ.get("MINIO_CERT_CHECK", default="true")
        )
        self.perfect_sync = str_to_bool(os.environ.get("PERFECT_SYNC", default="false"))
        self.helper.log_info(f"Perfect synchronization: {self.perfect_sync}")

        self.helper.log_info(f"Minio endpoint: {minio_endpoint}:{minio_port}")
        self.helper.log_info(
            f"Bucket to fetch the stream: {self.minio_src_bucket}/{self.minio_src_path}"
        )
        self.helper.log_info(
            f"Bucket to put processed files: {self.minio_dst_bucket}/{self.minio_dst_path}"
        )

        self.minio_client = Minio(
            f"{minio_endpoint}:{minio_port}",
            minio_access_key,
            minio_secret_key,
            secure=minio_secure,
            cert_check=minio_cert_check,
        )
        self.helper.log_info(f"Minio: {self.minio_client._base_url}")

        # Create the destination bucket if it does not exist.
        if not self.minio_client.bucket_exists(self.minio_dst_bucket):
            self.minio_client.make_bucket(self.minio_dst_bucket)
            self.helper.log_info(f"Minio bucket {self.minio_dst_bucket} created")

        self.helper.log_info("Stream importer connector initialized")

    def _collect_intelligence(self):
        """Collects intelligence from channels

        Collect files from minio, process them and send them to RabbitMQ.
        """
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )
        # Read objects from minio, each object contains multiple events.
        for obj in self.minio_client.list_objects(
            self.minio_src_bucket,
            prefix=self.minio_src_path,
            recursive=self.minio_src_recurse,
        ):
            # Skip directories.
            if obj.object_name.endswith("/"):
                continue

            self.metrics.read()
            file_number = int(obj.object_name.split("_")[-1].split(".")[0])
            state = self.helper.get_state() or {}
            expected_file_number = state.get("file_count", 0) + 1

            # If the file_number is higher, some files are missing.
            if file_number > expected_file_number:
                self.metrics.import_down()
                raise WrongFileOrder(obj.object_name, expected_file_number)

            # If the file_number is lower, it's probably a file already processed.
            # If it exists in the destination, it's removed from the source.
            # If it does not exist in the destination, raises an error.
            if file_number < expected_file_number:
                if not self._object_exists(
                    self.minio_dst_bucket,
                    os.path.join(self.minio_dst_path, obj.object_name),
                ):
                    self.metrics.import_down()
                    raise WrongFileOrder(obj.object_name, expected_file_number)

                self.metrics.file_already_processed()
                self.helper.log_warning(
                    f"File {obj.object_name} already processed, discarding"
                )

                self.minio_client.remove_object(
                    self.minio_src_bucket,
                    obj.object_name,
                )

                continue

            try:
                response = self.minio_client.get_object(
                    obj.bucket_name,
                    obj.object_name,
                )
                # Read data from response
                self.send_event(Event(obj.object_name, response.data.decode()))

                # Update the state
                state["file_count"] = expected_file_number
                self.helper.set_state(state)
            except json.decoder.JSONDecodeError as e:
                self.metrics.import_down()
                self.helper.log_error(
                    f"File {obj.object_name} is malformatted, not processing: {e}"
                )
            finally:
                response.close()
                response.release_conn()

    def _object_exists(self, bucket_name: str, object_name: str) -> bool:
        """
        Return True if `object_name` exists in `bucket_name`, False otherwise.
        """
        try:
            self.minio_client.stat_object(bucket_name, object_name)
            return True
        except S3Error as err:
            # ``minio-py`` populates ``S3Error.code`` with the textual S3
            # error code (e.g. ``"NoSuchKey"`` for a missing object,
            # ``"NoSuchBucket"`` for a missing bucket); the HTTP status
            # is exposed separately via ``err.response.status``. The
            # earlier ``err.code == "404"`` branch was therefore dead
            # code (``code`` is never a numeric string) — kept only the
            # ``NoSuchKey`` check, which is the actual signal a stat on
            # a missing object surfaces. Anything else (permission
            # error, ``NoSuchBucket`` from a misconfigured destination,
            # network problem) should bubble up so the operator sees
            # the real failure instead of being silently treated as a
            # missing-file false negative.
            if err.code == "NoSuchKey":
                return False
            raise

    def send_event(self, event: Event) -> None:
        """Send an event to RabbitMQ.

        Once the event is sent, the file is moved to another bucket.

        Parameters
        ----------
        event : tuple[Path, str]
            Event as a tuple with the first element being the path of the file and the second the content (not encoded).
        """
        self.helper.log_info(f"Processing events from {event.path}")
        pika_credentials = pika.PlainCredentials(
            self.helper.connector_config["connection"]["user"],
            self.helper.connector_config["connection"]["pass"],
        )
        pika_parameters = pika.ConnectionParameters(
            host=self.helper.connector_config["connection"]["host"],
            port=self.helper.connector_config["connection"]["port"],
            virtual_host=self.helper.connector_config["connection"]["vhost"],
            credentials=pika_credentials,
            ssl_options=(
                pika.SSLOptions(
                    create_mq_ssl_context(self.helper.config),
                    self.helper.connector_config["connection"]["host"],
                )
                if self.helper.connector_config["connection"]["use_ssl"]
                else None
            ),
        )
        pika_connection = pika.BlockingConnection(pika_parameters)
        channel = pika_connection.channel()
        try:
            channel.confirm_delivery()
        except Exception as err:  # pylint: disable=broad-except
            self.metrics.send_error()
            self.helper.connector_logger.warning(str(err))
            channel.close()
            pika_connection.close()
            return

        for e in event.entries.split("\n"):
            self._send_event(
                channel,
                e,
            )
            self.metrics.send()
        channel.close()
        pika_connection.close()

        # The event is processed, the file can be moved (well, copied and deleted...).
        self.minio_client.copy_object(
            self.minio_dst_bucket,
            os.path.join(self.minio_dst_path, event.path),
            CopySource(self.minio_src_bucket, event.path),
        )
        self.minio_client.remove_object(
            self.minio_src_bucket,
            event.path,
        )
        self.helper.log_info(
            f"File {event.path} moved to {os.path.join(self.minio_dst_bucket, self.minio_dst_path)}"
        )

    # Hard cap on the number of times :meth:`_send_event` will retry a
    # publish that the broker NACKed or returned as unroutable before
    # giving up and dropping the event. The previous shape recursed
    # unconditionally on every ``NackError`` / ``UnroutableError``,
    # which would blow Python's recursion limit (~1000) when the broker
    # kept rejecting the same message (e.g. a misconfigured exchange,
    # a missing binding, or persistent publisher-confirms NACKs).
    _MAX_PUBLISH_RETRIES = 3

    def _send_event(self, channel, event: str, attempt: int = 1) -> None:
        """Send the content of the event to RabbitMQ.

        Parameters
        ----------
        channel : pike.BlockingChannel
            Channel to send the event to.
        event : str
            Content of the event, as string.
        attempt : int
            1-based retry counter used to bound the recursive retry on
            ``NackError`` / ``UnroutableError``. Defaults to 1 for the
            first attempt; the helper recurses with ``attempt + 1`` and
            gives up once it exceeds :attr:`_MAX_PUBLISH_RETRIES`.
        """
        if not event:
            self.helper.log_debug("Event is empty, skipping")
            return

        event_parsed = json.loads(event)
        self.helper.log_debug(f"Event parsed: {event_parsed}")

        message = {
            "type": "event",
            "synchronized": self.perfect_sync,
            "update": True,
            "previous_standard": event_parsed.get("previous_standard", None),
            "applicant_id": self.helper.applicant_id,
            "content": base64.b64encode(event.encode("utf-8")).decode("utf-8"),
        }

        self.helper.log_debug(f"Message to push: {json.dumps(message)}")

        # Send the message
        try:
            channel.basic_publish(
                exchange=self.helper.connector_config["push_exchange"],
                routing_key=self.helper.connector_config["push_routing"],
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2, content_encoding="utf-8"  # make message persistent
                ),
            )
            self.helper.connector_logger.debug("Event has been sent")
            self.helper.metric.inc("bundle_send")
        except ChannelClosedByBroker as err:
            # ``ChannelClosedByBroker`` is raised when the RabbitMQ broker
            # closes the channel itself (most commonly because the message
            # exceeds the broker-side ``max_message_size``). The channel
            # is now permanently closed, so the previous catch-and-recurse
            # pattern used for ``UnroutableError`` / ``NackError`` would
            # have looped forever on the very same closed channel — every
            # subsequent ``basic_publish`` would re-raise the same
            # exception. Just record the metric, log the error, and drop
            # this event so the outer per-file loop in :meth:`send_event`
            # can open a fresh channel for the next file.
            self.metrics.send_error()
            self.helper.connector_logger.error(
                f"Unable to send bundle ({type(err).__name__}): {err}; "
                "channel is closed, skipping retry."
            )
        except (NackError, UnroutableError) as err:
            # ``NackError`` is raised when the broker NACKs a publisher-
            # confirmed message; ``UnroutableError`` when a ``mandatory``
            # publish has no matching queue binding. Both can be
            # transient (broker memory pressure, a binding being created
            # concurrently) so we retry once or twice, but the previous
            # shape recursed unconditionally — which on a persistent
            # configuration error (wrong exchange, missing binding,
            # broker rejecting every confirm) would exhaust Python's
            # recursion limit and crash the connector with a
            # ``RecursionError`` instead of just dropping the offending
            # event and moving on. Bound the retry, then drop+log on
            # the same shape as the ``ChannelClosedByBroker`` branch.
            self.metrics.send_error()
            if attempt >= self._MAX_PUBLISH_RETRIES:
                self.helper.connector_logger.error(
                    f"Unable to send bundle ({type(err).__name__}): {err}; "
                    f"exhausted {self._MAX_PUBLISH_RETRIES} retries, dropping event."
                )
                return
            self.helper.connector_logger.error(
                f"Unable to send bundle ({type(err).__name__}): {err}, "
                f"retrying (attempt {attempt + 1}/{self._MAX_PUBLISH_RETRIES})..."
            )
            self._send_event(channel, event, attempt=attempt + 1)


def str_to_bool(val):
    """Convert a string representation of truth to true or false.
    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return True
    if val in ("n", "no", "f", "false", "off", "0"):
        return False
    raise ValueError(f"invalid truth value {val!r}")
