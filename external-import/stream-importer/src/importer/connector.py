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

        # Historical typo: the env var was read as ``METRICS_SUBSYTEM``
        # (missing the second ``S``) while the README has always
        # advertised ``METRICS_SUBSYSTEM``. Any operator following the
        # README would have had their setting silently ignored. Keep
        # the misspelled name as a fallback so we don't break a
        # deployment that happened to follow the code, but prefer the
        # documented ``METRICS_SUBSYSTEM`` when both are set so the
        # README is finally truthful.
        self.metrics = Metrics(
            self.helper.connect_name,
            os.environ.get("METRICS_NAMESPACE"),
            os.environ.get("METRICS_SUBSYSTEM", os.environ.get("METRICS_SUBSYTEM")),
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
        # Reject the unsafe ``src bucket == dst bucket AND dst_path is
        # empty`` configuration up front. The ``bucket_exists`` /
        # ``make_bucket`` plumbing below cannot defend this case
        # because the source bucket already exists by construction, so
        # the connector would otherwise proceed past startup and at
        # the end of :meth:`send_event` call
        # ``copy_object(bucket, key, CopySource(bucket, key))``
        # followed by ``remove_object(bucket, key)`` — copying the
        # object onto itself and then deleting it, which is silent
        # data loss on every processed file. A non-empty
        # ``minio_dst_path`` is the only way to disambiguate source
        # from destination keys in a single bucket; the
        # ``_collect_intelligence`` listing loop also relies on that
        # prefix to skip already-moved files when
        # ``MINIO_SRC_RECURSE=true`` (see the ``dst_prefix`` guard
        # there). Failing fast with a clear ``ValueError`` here keeps
        # the operator's misconfiguration loud at startup instead of
        # turning into silent attrition on every run.
        if self.minio_src_bucket == self.minio_dst_bucket and not self.minio_dst_path:
            raise ValueError(
                "Unsafe MinIO configuration: MINIO_SRC_PATH and "
                "MINIO_DST_PATH resolve to the same bucket "
                f"({self.minio_src_bucket!r}) with no destination "
                "subfolder. Set MINIO_DST_PATH to a distinct bucket "
                "or to a non-empty subfolder under "
                f"{self.minio_src_bucket!r} (e.g. "
                f"{self.minio_src_bucket}/processed)."
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
        # When the source and destination share the same bucket AND the
        # destination is a subfolder under the source prefix, a
        # ``MINIO_SRC_RECURSE=true`` listing descends into the
        # destination subtree too and surfaces every already-moved
        # file. Without the skip below those files would be:
        #
        # * fed back into the ``file_number < expected_file_number``
        #   branch (every destination file has been processed so its
        #   number is lower than the cursor) and then probed via
        #   ``_object_exists`` with a *duplicated* destination prefix
        #   (``os.path.join(dst_path, obj.object_name)`` where
        #   ``obj.object_name`` already starts with ``dst_path``) —
        #   the probe fails and ``WrongFileOrder`` is raised even
        #   though the file IS in the destination, and
        # * if the cursor happens to align, re-copied into an even
        #   deeper nested destination key
        #   (``dst_path/dst_path/filename``) by the move at the end
        #   of :meth:`send_event`.
        #
        # Compute the destination prefix as ``dst_path + "/"`` so a
        # configured value like ``"processed"`` is matched against
        # ``"processed/sync_1.json"`` rather than the false-positive
        # ``"processed_v2/...":`` shape. The empty ``dst_path`` /
        # same-bucket case cannot be defended by a prefix check (the
        # bucket root has no prefix to match against), but it is
        # already rejected at startup by the explicit
        # ``src_bucket == dst_bucket and not dst_path`` guard in
        # :meth:`__init__` — the listing loop here is therefore
        # guaranteed to see a non-empty ``dst_prefix`` whenever src
        # and dst buckets coincide.
        dst_prefix = (
            self.minio_dst_path.rstrip("/") + "/" if self.minio_dst_path else ""
        )
        src_dst_same_bucket = self.minio_src_bucket == self.minio_dst_bucket
        # Read objects from minio, each object contains multiple events.
        for obj in self.minio_client.list_objects(
            self.minio_src_bucket,
            prefix=self.minio_src_path,
            recursive=self.minio_src_recurse,
        ):
            # Skip directories.
            if obj.object_name.endswith("/"):
                continue

            # Skip recursive-listing hits that are already in the
            # destination subtree of the same bucket (see the
            # ``dst_prefix`` rationale above).
            if (
                src_dst_same_bucket
                and dst_prefix
                and obj.object_name.startswith(dst_prefix)
            ):
                self.helper.log_debug(
                    f"Skipping {obj.object_name}: already under destination "
                    f"prefix {dst_prefix}"
                )
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

            # ``response`` is initialised here (not inside the
            # ``try``) so the ``finally`` cleanup never crashes with
            # ``UnboundLocalError``. ``minio_client.get_object`` can
            # raise ``S3Error`` / network errors that the ``except``
            # block below does NOT catch — they fall through to the
            # ``finally`` first, and without the explicit ``None``
            # seed the close / release call would mask the real
            # failure with an attribute error on an undefined name.
            response = None
            try:
                response = self.minio_client.get_object(
                    obj.bucket_name,
                    obj.object_name,
                )
                # Read data from response. ``send_event`` returns
                # ``True`` only when every entry in the file was
                # successfully published to RabbitMQ AND the file was
                # subsequently moved to the destination bucket — we
                # only advance the state cursor in that case so a
                # partial publish (broker NACK, channel closed by
                # broker, etc.) gets retried on the next scan cycle
                # rather than silently losing the unsent entries
                # behind an advanced ``file_count``.
                if self.send_event(Event(obj.object_name, response.data.decode())):
                    state["file_count"] = expected_file_number
                    self.helper.set_state(state)
            except json.decoder.JSONDecodeError as e:
                self.metrics.import_down()
                self.helper.log_error(
                    f"File {obj.object_name} is malformatted, not processing: {e}"
                )
            finally:
                # Guard both calls so a failure before ``response`` is
                # assigned does not crash the cleanup. ``release_conn``
                # was added in newer ``urllib3`` releases and may not
                # exist on every response object minio-py returns —
                # treat it as best-effort so a missing attribute does
                # not turn a successful publish into a failed one.
                if response is not None:
                    try:
                        response.close()
                    finally:
                        if hasattr(response, "release_conn"):
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

    def send_event(self, event: Event) -> bool:
        """Send an event to RabbitMQ.

        Once every entry in the event has been successfully published,
        the file is moved to the destination bucket and ``True`` is
        returned. When any entry fails to publish — either because the
        broker closed the channel (``ChannelClosedByBroker``) or the
        bounded retry loop exhausted for a NACK / unroutable response
        — ``False`` is returned and the source file is left in place
        so the next scan cycle can retry it; the state cursor in
        :meth:`_collect_intelligence` is guarded on this return value
        so a partial publish does not silently advance the cursor
        past the unsent entries.

        Parameters
        ----------
        event : Event
            ``Event`` namedtuple (``Event = namedtuple("Event", "path entries")``)
            where ``path`` is the MinIO object key (a ``str``, not
            ``pathlib.Path``) and ``entries`` is the raw file content
            as a string (one JSON event per line, decoded from the
            ``minio_client.get_object(...)`` response). The previous
            docstring shape (``tuple[Path, str]``) was historical and
            never matched the actual call site in
            :meth:`_collect_intelligence`, which constructs the value
            with ``Event(obj.object_name, response.data.decode())``.

        Returns
        -------
        bool
            ``True`` if every entry was published AND the file was
            moved to the destination bucket; ``False`` on any publish
            failure (channel closed / retry exhausted) so the caller
            can hold the state cursor.
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
        # ``channel`` is initialised to ``None`` so the ``finally``
        # cleanup below works even if ``pika_connection.channel()``
        # itself raises (``finally`` would otherwise fail with
        # ``UnboundLocalError`` and mask the real broker failure).
        channel = None
        # Track per-entry success so the file is only moved (and the
        # ``sent_messages_total`` counter only incremented) when every
        # entry actually went through. The previous shape incremented
        # ``metrics.send()`` unconditionally — even when
        # ``_send_event`` had dropped the event after a
        # ``ChannelClosedByBroker`` or after exhausting the bounded
        # NACK / unroutable retry — which inflated the Prometheus
        # success counter against the actual broker state. On the
        # first publish failure we also break the loop: subsequent
        # ``basic_publish`` calls on a closed channel raise
        # ``pika.exceptions.ChannelWrongStateError`` (NOT caught in
        # ``_send_event``), so the previous "keep iterating" shape
        # could crash the connector on the second entry rather than
        # fail cleanly on the first one.
        all_ok = True
        # Wrap the publish flow in ``try / finally`` so the broker
        # channel and TCP connection are always released — even when
        # an unexpected exception escapes ``_send_event`` (e.g.
        # ``json.JSONDecodeError`` on a malformed entry, or any
        # ``pika`` exception not caught in the helper's branches). The
        # previous shape kept ``channel.close()`` / ``pika_connection.close()``
        # as straight-line statements after the loop, so a single bad
        # entry leaked both the channel and the underlying TCP
        # connection and eventually exhausted the broker's per-client
        # connection cap on a connector that runs every few minutes.
        try:
            channel = pika_connection.channel()
            try:
                channel.confirm_delivery()
            except Exception as err:  # pylint: disable=broad-except
                self.metrics.send_error()
                self.helper.connector_logger.warning(str(err))
                return False

            for e in event.entries.split("\n"):
                # ``file.split("\n")`` always yields a trailing empty
                # string when the source file ends in ``\n`` and may
                # include blank / whitespace-only lines from a broken
                # upstream writer. Filter them here so they are never
                # passed to ``_send_event`` — counted as a no-op, they
                # used to make the helper return ``True`` which then
                # incremented ``sent_messages_total`` for a message
                # the broker never actually received.
                if not e.strip():
                    continue
                if self._send_event(channel, e):
                    self.metrics.send()
                else:
                    all_ok = False
                    self.helper.connector_logger.warning(
                        f"Publish failed for an entry in {event.path}; "
                        "stopping iteration on this file so the channel "
                        "state cannot crash subsequent publishes."
                    )
                    break
        finally:
            # Both calls are best-effort: the broker may have already
            # closed the channel (``ChannelClosedByBroker``) and a
            # redundant close raises ``ChannelWrongStateError``;
            # ``pika_connection.close()`` can also raise (e.g. on a
            # broken TCP socket) and we do not want a teardown
            # failure to mask the real publish outcome (``all_ok``)
            # the caller is about to act on. Either way the
            # underlying socket is released by ``pika`` when the
            # ``BlockingConnection`` object goes out of scope, so a
            # swallowed close-time exception does not leak the
            # connection.
            if channel is not None:
                try:
                    channel.close()
                except Exception:  # pylint: disable=broad-except
                    pass
            try:
                pika_connection.close()
            except Exception:  # pylint: disable=broad-except
                pass

        if not all_ok:
            # Leave the source file in place AND skip the state-cursor
            # advance (in ``_collect_intelligence``) so the next scan
            # cycle reprocesses this file. Without this branch the
            # file would be moved to the destination bucket and the
            # ``file_count`` cursor advanced past it, silently losing
            # the unsent entries forever.
            self.helper.connector_logger.warning(
                f"File {event.path} had publish failures; leaving it "
                "in the source bucket so the next scan cycle can retry."
            )
            return False

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
        return True

    # Hard cap on the number of times :meth:`_send_event` will retry a
    # publish that the broker NACKed or returned as unroutable before
    # giving up and dropping the event. The previous shape recursed
    # unconditionally on every ``NackError`` / ``UnroutableError``,
    # which would blow Python's recursion limit (~1000) when the broker
    # kept rejecting the same message (e.g. a misconfigured exchange,
    # a missing binding, or persistent publisher-confirms NACKs).
    _MAX_PUBLISH_RETRIES = 3

    def _send_event(self, channel, event: str, attempt: int = 1) -> bool:
        """Send the content of the event to RabbitMQ.

        The caller in :meth:`send_event` is responsible for filtering
        out empty / whitespace-only entries before calling this
        helper, so the body assumes ``event`` is a non-empty payload
        and does not short-circuit on falsy input. A defensive empty
        skip used to live here, but it returned ``True`` and the
        caller incremented ``sent_messages_total`` unconditionally
        on a truthy return — inflating the success counter for every
        trailing blank line produced by ``file.split("\\n")``.
        Filtering at the caller and assuming non-empty input here
        keeps the counter aligned with the number of actual messages
        the broker confirmed.

        Parameters
        ----------
        channel : pika.adapters.blocking_connection.BlockingChannel
            Channel to send the event to.
        event : str
            Content of the event, as string. MUST be non-empty;
            empty / whitespace-only entries are filtered by the
            caller in :meth:`send_event`.
        attempt : int
            1-based retry counter used to bound the recursive retry on
            ``NackError`` / ``UnroutableError``. Defaults to 1 for the
            first attempt; the helper recurses with ``attempt + 1`` and
            gives up once it exceeds :attr:`_MAX_PUBLISH_RETRIES`.

        Returns
        -------
        bool
            ``True`` when the publish was confirmed by the broker;
            ``False`` when the publish was dropped on a permanently
            closed channel (``ChannelClosedByBroker``) or after
            exhausting the bounded NACK / unroutable retry. The
            caller in :meth:`send_event` uses this to gate both the
            ``metrics.send()`` increment and the destination-bucket
            file move so the success counter and the per-file
            "moved" semantic always match the actual broker state.
        """
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

        # ``mandatory=True`` is required for ``UnroutableError`` to
        # ever surface here: ``pika`` only raises it when a
        # publisher-confirmed publish (we enabled
        # ``channel.confirm_delivery()`` above) carries ``mandatory``
        # AND the broker cannot route the message to a queue. Without
        # ``mandatory`` the broker silently discards an unroutable
        # message and still ACKs the publish — the ``UnroutableError``
        # branch below would be dead code and a missing-binding
        # misconfiguration would manifest as silent data loss with
        # every per-entry publish ticking ``sent_messages_total`` for
        # a message that never reached a queue. Pairing
        # ``mandatory=True`` with the bounded NACK / unroutable retry
        # below means a transient binding-being-created race retries
        # cleanly, and a persistent missing-binding situation drops
        # the event AFTER exhausting the retry budget — surfacing as
        # a loud ``Unable to send bundle (UnroutableError)`` error
        # and holding the source file in place so the operator can
        # fix the binding and the next scan cycle resumes from the
        # same cursor.
        try:
            channel.basic_publish(
                exchange=self.helper.connector_config["push_exchange"],
                routing_key=self.helper.connector_config["push_routing"],
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2, content_encoding="utf-8"  # make message persistent
                ),
                mandatory=True,
            )
            self.helper.connector_logger.debug("Event has been sent")
            self.helper.metric.inc("bundle_send")
            return True
        except ChannelClosedByBroker as err:
            # ``ChannelClosedByBroker`` is raised when the RabbitMQ broker
            # closes the channel itself (most commonly because the message
            # exceeds the broker-side ``max_message_size``). The channel
            # is now permanently closed, so the previous catch-and-recurse
            # pattern used for ``UnroutableError`` / ``NackError`` would
            # have looped forever on the very same closed channel — every
            # subsequent ``basic_publish`` would re-raise the same
            # exception. Record the metric, log the error, and return
            # ``False`` so the caller in :meth:`send_event` breaks the
            # per-entry loop (subsequent publishes on the now-closed
            # channel would otherwise raise
            # ``pika.exceptions.ChannelWrongStateError`` and crash the
            # connector) and skips both the success counter and the
            # destination-bucket move for this file.
            self.metrics.send_error()
            self.helper.connector_logger.error(
                f"Unable to send bundle ({type(err).__name__}): {err}; "
                "channel is closed, skipping retry."
            )
            return False
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
            # the same shape as the ``ChannelClosedByBroker`` branch
            # and return ``False`` so the caller's success counter and
            # destination move stay aligned with reality.
            self.metrics.send_error()
            if attempt >= self._MAX_PUBLISH_RETRIES:
                self.helper.connector_logger.error(
                    f"Unable to send bundle ({type(err).__name__}): {err}; "
                    f"exhausted {self._MAX_PUBLISH_RETRIES} retries, dropping event."
                )
                return False
            self.helper.connector_logger.error(
                f"Unable to send bundle ({type(err).__name__}): {err}, "
                f"retrying (attempt {attempt + 1}/{self._MAX_PUBLISH_RETRIES})..."
            )
            return self._send_event(channel, event, attempt=attempt + 1)


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
