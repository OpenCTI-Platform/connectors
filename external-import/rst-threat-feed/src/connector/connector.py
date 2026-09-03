"""RST Threat Feed external-import connector."""

import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from pycti import OpenCTIConnectorHelper

from connector.converter_to_stix import ConverterToStix
from connector.feed_converter import FeedType, feed_converter
from connector.settings import ConnectorSettings
from rst_threat_feed_client import MitreTtpDownloader, ThreatFeedClient

_OPENCTI_RETRY_MIN_DELAY_S = 1


class RSTThreatFeed:
    def __init__(
        self, *, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper

        feed = self.config.rst_threat_feed
        self._downloader_config = {
            "baseurl": str(feed.baseurl).rstrip("/"),
            "apikey": feed.apikey,
            "contimeout": int(feed.contimeout),
            "readtimeout": int(feed.readtimeout),
            "retry": int(feed.retry),
            "ssl_verify": bool(feed.ssl_verify),
            "proxy": feed.proxy or "",
            "latest": str(feed.latest),
        }
        self._feed_flags = {
            FeedType.IP: bool(feed.ip),
            FeedType.DOMAIN: bool(feed.domain),
            FeedType.URL: bool(feed.url),
            FeedType.HASH: bool(feed.hash),
        }
        self._min_score_import = int(feed.min_score_import)
        self._min_score_detection = {
            "IPv4-Addr": int(feed.min_score_detection_ip),
            "Domain-Name": int(feed.min_score_detection_domain),
            "Url": int(feed.min_score_detection_url),
            "StixFile": int(feed.min_score_detection_hash),
        }
        self._only_new = bool(feed.only_new)
        self._only_attributed = bool(feed.only_attributed)
        self._keep_named_vulns = bool(feed.keep_named_vulns)
        self._create_custom_ttps = bool(feed.create_custom_ttps)
        self._create_mitre_ttps = bool(feed.create_mitre_ttps)
        self._max_retries = int(feed.max_retries)
        self._retry_delay = int(feed.retry_delay)
        self._retry_backoff_multiplier = float(feed.retry_backoff_multiplier)
        self._opencti_batch_size = max(1, int(feed.opencti_batch_size))
        self.update_existing_data = bool(self.config.connector.update_existing_data)

        self.mitre_downloader = MitreTtpDownloader(self._downloader_config)
        self.mitre_ttp_mapping = self.mitre_downloader.load_ttp_mapping()
        self.converter = ConverterToStix(
            helper=self.helper,
            min_score_detection=self._min_score_detection,
            create_custom_ttps=self._create_custom_ttps,
            create_mitre_ttps=self._create_mitre_ttps,
        )

    def feed_enabled(self, ioc_type: str) -> bool:
        if ioc_type not in self._feed_flags:
            raise ValueError(
                f"Only {list(self._feed_flags)} values supported, got {ioc_type}"
            )
        return self._feed_flags[ioc_type]

    def _publish_connector_info(self, *, mark_last_run: bool) -> None:
        helper = self.helper
        try:
            duration_period_s = self.config.connector.duration_period.total_seconds()
            try:
                helper.check_connector_buffering()
            except Exception:
                helper.connector_info.queue_threshold = float(
                    helper.connect_queue_threshold
                )
            if mark_last_run:
                helper.last_run_datetime()
            helper.next_run_datetime(duration_period_s)
            helper.force_ping()
        except Exception as exc:
            helper.connector_logger.warning(
                f"Failed to publish connector status to OpenCTI UI: {exc}"
            )

    def process_message(self) -> None:
        timestamp = int(time.time())
        self._publish_connector_info(mark_last_run=False)

        try:
            self.mitre_downloader.download_mitre_ttps()
            self.mitre_ttp_mapping = self.mitre_downloader.load_ttp_mapping()
        except Exception as exc:
            self.helper.connector_logger.error(
                f"Failed to update MITRE TTP mappings: {exc}"
            )

        for ioc_feed_type in (
            FeedType.IP,
            FeedType.DOMAIN,
            FeedType.URL,
            FeedType.HASH,
        ):
            if self.feed_enabled(ioc_feed_type):
                self._process_feed(ioc_feed_type, timestamp)

        current_state = self.helper.get_state() or {}
        current_state["last_run"] = timestamp
        self.helper.set_state(current_state)
        self._publish_connector_info(mark_last_run=True)

        if self.helper.connect_run_and_terminate:
            self.helper.connector_logger.info("Connector stopped")
            self.helper.force_ping()
            sys.exit(0)

    def run(self) -> None:
        self.helper.connector_logger.info("Starting RST Threat Feed connector")
        self.helper.connector_logger.info(
            f"OpenCTI batch size: {self._opencti_batch_size}, "
            f"CONNECTOR_UPDATE_EXISTING_DATA={self.update_existing_data}"
        )
        enabled = [name for name, on in self._feed_flags.items() if on]
        self.helper.connector_logger.info(f"Enabled feeds: {enabled}")

        duration_period_s = self.config.connector.duration_period.total_seconds()
        self.helper.connector_logger.info(
            f"Scheduled execution period: {duration_period_s}s"
        )
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=duration_period_s,
        )

    def _process_feed(self, feed_type: str, timestamp: int) -> None:
        file_path: Optional[str] = None
        try:
            client = ThreatFeedClient(self._downloader_config)
            result = client.get_feed(feed_type)
            if result.get("status") != "ok":
                self.helper.connector_logger.error(
                    f"Failed to download {feed_type} feed: {result}"
                )
                return

            file_path = result["message"]
            stix_objects = self._create_stix_objects(file_path, feed_type)
            if not stix_objects:
                self.helper.connector_logger.info(
                    f"[{feed_type}] no STIX objects to send"
                )
                return
            self._batch_send(stix_objects, timestamp, feed_type)
        except Exception as exc:
            self.helper.connector_logger.error(
                f"Error processing {feed_type} feed. Error: {exc}"
            )
        finally:
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError as exc:
                    self.helper.connector_logger.warning(
                        f"Failed to remove temp feed file {file_path}: {exc}"
                    )

    def _create_stix_objects(self, filepath: str, feed_type: str) -> List[Any]:
        self.helper.connector_logger.info(f"Parsing IOCs from {filepath}")
        iocs, threats, mapping = feed_converter(
            filepath,
            feed_type,
            self._min_score_import,
            self._only_new,
            self._only_attributed,
            self._keep_named_vulns,
            self._create_mitre_ttps,
            self._create_custom_ttps,
            self.mitre_ttp_mapping,
        )
        self.helper.connector_logger.info(
            f"Parsed IOCs: {len(iocs)}, Threats: {len(threats)}, "
            f"Mappings: {len(mapping)}"
        )
        return self.converter.create_stix_objects(iocs, threats, mapping)

    def _batch_send(
        self, stix_objects: List[Any], timestamp: int, feed_type: str
    ) -> bool:
        if not stix_objects:
            return True

        ordered = self._order_stix_objects(stix_objects)
        foundation, remainder = self._partition_foundation(ordered)
        batch_size = self._opencti_batch_size

        if not remainder:
            return self._batch_send_one(foundation, timestamp, feed_type)

        foundation_budget = min(len(foundation), max(0, batch_size - 1))
        foundation_prefix = foundation[:foundation_budget]
        payload_budget = max(1, batch_size - len(foundation_prefix))

        if len(remainder) <= payload_budget and len(foundation) <= batch_size:
            return self._batch_send_one(foundation + remainder, timestamp, feed_type)

        total_chunks = (len(remainder) + payload_budget - 1) // payload_budget
        for chunk_idx, offset in enumerate(range(0, len(remainder), payload_budget)):
            payload = remainder[offset : offset + payload_budget]
            chunk = foundation_prefix + payload
            self.helper.connector_logger.info(
                f"[{feed_type}] OpenCTI push chunk "
                f"{chunk_idx + 1}/{total_chunks} "
                f"({len(chunk)} object(s))"
            )
            if not self._batch_send_one(chunk, timestamp, feed_type):
                return False
        return True

    @classmethod
    def _partition_foundation(
        cls, stix_objects: List[Any]
    ) -> Tuple[List[Any], List[Any]]:
        """Author organization + marking defs only (not sector identities)."""
        foundation: List[Any] = []
        remainder: List[Any] = []
        for obj in stix_objects:
            obj_type, _ = cls._stix_type_and_id(obj)
            if obj_type == "marking-definition":
                foundation.append(obj)
                continue
            if obj_type == "identity":
                identity_class = getattr(obj, "identity_class", None)
                if identity_class == "organization":
                    foundation.append(obj)
                else:
                    remainder.append(obj)
                continue
            remainder.append(obj)
        return foundation, remainder

    @classmethod
    def _order_stix_objects(cls, stix_objects: List[Any]) -> List[Any]:
        """
        Dependency-safe order for OpenCTI ingestion:

        author identities → markings → sector identities → entities → relationships
        """
        authors: List[Any] = []
        markings: List[Any] = []
        other_identities: List[Any] = []
        entities: List[Any] = []
        relationships: List[Any] = []
        seen: Dict[str, bool] = {}

        for obj in stix_objects:
            obj_type, oid = cls._stix_type_and_id(obj)
            if oid and oid in seen:
                continue
            if oid:
                seen[oid] = True

            if obj_type == "identity":
                identity_class = getattr(obj, "identity_class", None)
                if identity_class == "organization":
                    authors.append(obj)
                else:
                    other_identities.append(obj)
            elif obj_type == "marking-definition":
                markings.append(obj)
            elif obj_type == "relationship":
                relationships.append(obj)
            else:
                entities.append(obj)

        return authors + markings + other_identities + entities + relationships

    def _sleep_before_retry(self, delay_s: int) -> int:
        sleep_s = max(_OPENCTI_RETRY_MIN_DELAY_S, int(delay_s))
        self.helper.connector_logger.info(f"Retrying in {sleep_s} seconds...")
        time.sleep(sleep_s)
        next_delay = int(sleep_s * self._retry_backoff_multiplier) or sleep_s
        return max(_OPENCTI_RETRY_MIN_DELAY_S, next_delay)

    @staticmethod
    def _is_retryable_upload_error(exc: BaseException) -> bool:
        return isinstance(
            exc,
            (
                ConnectionError,
                OSError,
                TimeoutError,
                requests.exceptions.RequestException,
            ),
        )

    def _mark_work_failed(
        self, work_id: Optional[str], feed_type: str, exc: BaseException
    ) -> None:
        if not work_id:
            return
        try:
            self.helper.api.work.to_processed(
                work_id,
                f"[{feed_type}] upload failed: {exc}",
                in_error=True,
            )
        except Exception as close_ex:
            self.helper.connector_logger.warning(
                f"[{feed_type}] failed to mark work {work_id} in_error: {close_ex}"
            )

    def _batch_send_one(
        self, stix_objects: List[Any], timestamp: int, feed_type: str
    ) -> bool:
        now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        friendly_name = (
            f"RST Threat Feed [{feed_type}] @ {now.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.helper.connector_logger.debug(
            f"[{feed_type}] start uploading {len(stix_objects)} object(s)"
        )

        max_retries = max(1, int(self._max_retries))
        retry_delay = self._retry_delay

        for attempt in range(max_retries):
            work_id: Optional[str] = None
            try:
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                self.helper.send_stix2_bundle(
                    self.helper.stix2_create_bundle(stix_objects),
                    update=self.update_existing_data,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )
                self.helper.connector_logger.info(
                    f"[{feed_type}] sent bundle of {len(stix_objects)} object(s)"
                )
                self.helper.api.work.to_processed(
                    work_id,
                    f"Sent bundle of {len(stix_objects)} object(s) for {feed_type}",
                )
                return True

            except Exception as exc:
                self._mark_work_failed(work_id, feed_type, exc)
                if self._is_retryable_upload_error(exc):
                    self.helper.connector_logger.error(
                        f"[{feed_type}] push attempt {attempt + 1}/{max_retries} "
                        f"failed: {exc}"
                    )
                    if attempt < max_retries - 1:
                        retry_delay = self._sleep_before_retry(retry_delay)
                        continue
                    self.helper.connector_logger.error(
                        f"[{feed_type}] failed to upload bundle after "
                        f"{max_retries} attempts."
                    )
                    return False

                self.helper.connector_logger.error(
                    f"[{feed_type}] unexpected error during upload: {exc}"
                )
                raise

        return False

    @staticmethod
    def _stix_type_and_id(obj: Any) -> Tuple[Optional[str], Optional[str]]:
        obj_type = getattr(obj, "type", None)
        obj_id = getattr(obj, "id", None)
        if isinstance(obj_type, str) and obj_type:
            return obj_type, str(obj_id) if obj_id else None
        try:
            payload = json.loads(obj.serialize())
        except Exception:
            return None, None
        if not isinstance(payload, dict):
            return None, None
        oid = payload.get("id")
        return payload.get("type"), str(oid) if oid else None
