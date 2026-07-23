from __future__ import annotations

import itertools
import time
from datetime import datetime, timezone
from traceback import format_exc
from typing import Any

from client.api_client import build_ti_adapter
from connector.logging_config import setup_file_logging
from connector.settings import (
    INITIATE_WORK_DELAY_SEC,
    MAX_ERROR_TRUNCATE_LEN,
    ConfigConnector,
)
from connector.utils import ExternalImportHelper
from pycti import OpenCTIConnectorHelper
from support.mitre_mapper import get_mitre_mapper


class ExternalImportConnector:
    def __init__(self) -> None:
        self.cfg = ConfigConnector()
        self.helper = OpenCTIConnectorHelper({})
        self._setup_file_logging()
        self.helper.connector_logger.info("Initializing ExternalImportConnector")

        current_state = self.helper.get_state()

        self.interval = ExternalImportHelper.validation_interval(
            cfg=self.cfg, helper=self.helper
        )
        self.update_existing_data = (
            ExternalImportHelper.validation_update_existing_data(
                cfg=self.cfg, helper=self.helper
            )
        )
        self.ttl = None

        self.IGNORE_NON_MALWARE_DDOS = False
        self.IGNORE_NON_INDICATOR_THREAT_REPORTS = False
        self.IGNORE_NON_INDICATOR_THREATS = False
        self.INTRUSION_SET_INSTEAD_OF_THREAT_ACTOR = False

        self.proxies = {
            "proxy_ip": self.cfg.ti_api_proxy_ip,
            "proxy_port": self.cfg.ti_api_proxy_port,
            "proxy_protocol": self.cfg.ti_api_proxy_protocol,
            "proxy_username": self.cfg.ti_api_proxy_username,
            "proxy_password": self.cfg.ti_api_proxy_password,
        }

        self.enabled_collections = [
            slashed
            for name, slashed in ConfigConnector.COLLECTION_MAP.items()
            if self.cfg.get_collection_settings(name, "enable") is True
        ]
        self.helper.connector_logger.info(
            f"Enabled collections: {self.enabled_collections}"
        )

        self.ti_adapter = build_ti_adapter(
            ti_creds_dict={
                "api_key": self.cfg.ti_api_token,
                "username": self.cfg.ti_api_username,
            },
            proxies=self.proxies,
            config_obj=self.cfg,
            api_url=self.cfg.ti_api_url,
            enabled_collections=self.enabled_collections,
            collection_mapping_config=self.cfg.collection_mapping_config,
            collections_last_sequence_updates=current_state,
        )
        self.helper.connector_logger.info("Initialized TI Adapter")

        self.MITRE_MAPPER = None
        self.helper.connector_logger.info(
            "ExternalImportConnector initialization complete"
        )

    def _setup_file_logging(self) -> None:
        setup_file_logging(self.helper, self.cfg.get_file_logging_config())

    def _collect_intelligence(
        self,
        collection: str,
        ttl: int | None,
        event: dict[str, Any],
        mitre_mapper: dict[str, str],
        config: ConfigConnector,
        flag_intrusion_set_instead_of_threat_actor: bool = False,
    ) -> list[Any]:
        raise NotImplementedError

    def check_generator(self, generator: Any, collection: str) -> bool:
        if not generator:
            self.helper.connector_logger.warning(
                f"No generator for collection: {collection}"
            )
            return False
        return True

    def check_enable(self, enable: Any, collection: str) -> bool:
        if not enable:
            self.helper.connector_logger.warning(f"Collection disabled: {collection}")
            return False
        return True

    def extra_pre_processing(self, collection: str, portion: Any) -> Any:
        if collection == "attacks/ddos" and self.IGNORE_NON_MALWARE_DDOS:
            return portion.parse_portion(
                filter_map=[("malware", [])],
                check_existence=True,
                use_alternative_parser=True,
            )
        if (
            collection in ["apt/threat", "hi/threat"]
            and self.IGNORE_NON_INDICATOR_THREAT_REPORTS
        ):
            # Keep only threat reports that actually carry indicators.
            parsed = portion.parse_portion(use_alternative_parser=True)
            if not isinstance(parsed, list):
                return parsed
            kept: list[dict[str, Any]] = []
            for item in parsed:
                if not isinstance(item, dict):
                    continue
                inds = item.get("indicators")
                if isinstance(inds, list) and len(inds) > 0:
                    kept.append(item)
            return kept
        if (
            collection in ["apt/threat", "hi/threat"]
            and self.IGNORE_NON_INDICATOR_THREATS
        ):
            return portion.parse_portion(
                filter_map=[("indicators", [])],
                check_existence=True,
                use_alternative_parser=True,
            )
        return portion.parse_portion(use_alternative_parser=True)

    @staticmethod
    def _is_transient_network_error(exc: BaseException) -> bool:
        """True if ``exc`` (or any exception in its cause chain) is a transient
        upstream connectivity failure rather than a real processing error.

        Matched by class name to avoid importing urllib3/requests internals.
        """
        transient_names = {
            "ConnectionError",
            "ConnectionResetError",
            "ProtocolError",
            "RemoteDisconnected",
            "MaxRetryError",
            "ReadTimeout",
            "ReadTimeoutError",
            "Timeout",
            "ChunkedEncodingError",
            "IncompleteRead",
        }
        seen: set[int] = set()
        cur: BaseException | None = exc
        while cur is not None and id(cur) not in seen:
            seen.add(id(cur))
            if type(cur).__name__ in transient_names:
                return True
            cur = cur.__cause__ or cur.__context__
        return False

    def get_formatted_utcfromtimestamp(self, date: float | int) -> str:
        fmt = (
            self.cfg.get_extra_settings_by_name("time_output_format")
            or "%Y-%m-%d %H:%M:%S"
        )
        try:
            return datetime.fromtimestamp(date, tz=timezone.utc).strftime(str(fmt))
        except Exception:
            return datetime.fromtimestamp(date, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

    def set_or_update_state(
        self,
        timestamp: int | None = None,
        prepared_data: dict[str, Any] | None = None,
    ) -> None:
        current_state = self.helper.get_state() or {}
        if timestamp:
            current_state["last_run"] = timestamp
        if prepared_data:
            current_state.update(prepared_data)
        self.helper.set_state(current_state)

    def get_last_run(self, current_state: dict[str, Any] | None) -> int | None:
        if current_state is not None and "last_run" in current_state:
            last_run = current_state["last_run"]
            self.helper.connector_logger.info(
                f"{self.helper.connect_name} last run: "
                f"{self.get_formatted_utcfromtimestamp(last_run)}"
            )
            return last_run
        self.helper.connector_logger.info(f"{self.helper.connect_name} has never run")
        return None

    def _process(self) -> None:
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")
        timestamp = int(time.time())
        try:
            current_state = self.helper.get_state()
            self.get_last_run(current_state=current_state)
            self.helper.connector_logger.info(f"{self.helper.connect_name} will run!")
            try:
                self._run_once(current_state=current_state, timestamp=timestamp)
            except Exception:
                self.helper.connector_logger.error(format_exc())
            self.set_or_update_state(timestamp=timestamp)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.helper.metric.inc("error_count")
            self.helper.metric.state("stopped")
            self.helper.connector_logger.error(format_exc())

    def run(self) -> None:
        self.helper.connector_logger.info(
            f"Starting {self.helper.connect_name} connector..."
        )
        self.helper.schedule_iso(
            message_callback=self._process,
            duration_period=self.interval,
        )

    def _run_once(self, current_state: dict[str, Any] | None, timestamp: int) -> None:
        # TIAdapter keeps the state dict by reference; refresh each run or cursors stall.
        self.ti_adapter._collections_last_sequence_updates = current_state or {}
        data = self.ti_adapter.create_generators(sleep_amount=1)

        self.MITRE_MAPPER = get_mitre_mapper(self.ti_adapter, self.helper)
        self.helper.connector_logger.info("MITRE mapper initialized")

        for data_item in data:
            self._process_collection(data_item=data_item, timestamp=timestamp)

    def _process_collection(self, data_item: Any, timestamp: int) -> None:
        prepared_data = data_item[1]
        collection = data_item[0][0]
        generator = data_item[0][1]
        collection_key = collection.replace("/", "_")

        # ── Pre-checks BEFORE creating a Work in OpenCTI ───────────────────
        # initiate_work() creates a permanent record in the OpenCTI UI under
        # the connector's page; if we then close it 100ms later with "no data"
        # the customer still sees a flicker of one Work row per ISO tick per
        # collection (30 collections × every tick = a lot of noise).
        # We do all skip-checks BEFORE initiate_work and only commit the Work
        # once we know there's something to ship.

        if not self.check_generator(generator=generator, collection=collection):
            return

        enable = self.cfg.get_collection_settings(collection_key, "enable")
        if not self.check_enable(enable=enable, collection=collection):
            return

        # Peek the first portion. If the upstream API returns nothing for this
        # collection (no new events since the stored sequpdate cursor), the
        # generator is exhausted on the first next() — we skip creating a
        # Work entirely. The OpenCTI UI stays clean: only ticks with real
        # data appear in the connector's work history.
        try:
            first_portion = next(generator)
        except StopIteration:
            self.helper.connector_logger.info(
                f"{collection}: no new data — skipping Work creation"
            )
            return
        except Exception:
            # Pre-peek failure is recoverable — we just skip this collection
            # for this cycle and try again on the next interval. Use
            # ``warning`` (not ``error``) so monitoring stays signal-rich
            # and alerts fire only on persistent crashes.
            self.helper.connector_logger.warning(
                f"{collection}: generator failed during pre-peek; "
                f"skipping this cycle\n{format_exc()}"
            )
            return
        generator = itertools.chain([first_portion], generator)

        friendly_name = (
            f"{self.helper.connect_name} - {collection} run @ "
            f"{self.get_formatted_utcfromtimestamp(date=timestamp)}"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        self.helper.connector_logger.info(
            "Work started", {"work_id": work_id, "collection": collection}
        )

        time.sleep(INITIATE_WORK_DELAY_SEC)

        try:
            # TTL is optional; downstream mappers default to 365 days when None.
            ttl_raw = self.cfg.get_collection_settings(collection_key, "ttl")
            try:
                self.ttl = int(ttl_raw) if ttl_raw is not None else None
            except (TypeError, ValueError):
                self.helper.connector_logger.warning(
                    "Invalid TTL for collection; falling back to None",
                    {"collection": collection, "ttl_raw": str(ttl_raw)},
                )
                self.ttl = None

            # Boolean extra_settings: env vars arrive as strings; coerce explicitly
            # because both "true" and "false" are truthy in plain Python.
            self.INTRUSION_SET_INSTEAD_OF_THREAT_ACTOR = (
                self.cfg.get_extra_settings_bool(
                    "intrusion_set_instead_of_threat_actor"
                )
            )
            self.IGNORE_NON_INDICATOR_THREAT_REPORTS = self.cfg.get_extra_settings_bool(
                "ignore_non_indicator_threat_reports"
            )
            self.IGNORE_NON_MALWARE_DDOS = self.cfg.get_extra_settings_bool(
                "ignore_non_malware_ddos"
            )
            self.IGNORE_NON_INDICATOR_THREATS = self.cfg.get_extra_settings_bool(
                "ignore_non_indicator_threats"
            )

            for portion in generator:
                self._process_portion(
                    collection=collection,
                    prepared_data=prepared_data,
                    portion=portion,
                    work_id=work_id,
                )

            message = (
                f"{self.helper.connect_name} - {collection} "
                f"successfully run, storing last_run as {timestamp}"
            )
            self.helper.api.work.to_processed(work_id, message, in_error=False)
            self.helper.connector_logger.info(
                "Work completed",
                {"work_id": work_id, "collection": collection},
            )
        except Exception as exc:
            err_text = format_exc()
            if len(err_text) > MAX_ERROR_TRUNCATE_LEN:
                err_text = err_text[:MAX_ERROR_TRUNCATE_LEN] + "\n... (truncated)"
            if self._is_transient_network_error(exc):
                # Transient upstream drop (RemoteDisconnected / reset / read
                # timeout). The sequpdate cursor is persisted per-portion, so
                # the next run resumes where this one stopped — not a real
                # failure. Close the Work as a warning, not a red error.
                self.helper.connector_logger.warning(
                    "Collection import interrupted by a transient network "
                    "error; will resume next run",
                    {"collection": collection, "work_id": work_id},
                )
                interrupted_message = (
                    f"{self.helper.connect_name} - {collection} interrupted by "
                    "a transient network error (will resume next run)"
                )
                try:
                    self.helper.api.work.to_processed(
                        work_id, interrupted_message, in_error=False
                    )
                except Exception:
                    self.helper.connector_logger.warning(
                        "Could not report interrupted work to OpenCTI API",
                        {"work_id": work_id},
                    )
                return
            self.helper.connector_logger.error(
                "Collection import failed (other collections will still run)",
                {"collection": collection, "work_id": work_id},
            )
            fail_message = (
                f"{self.helper.connect_name} - {collection} failed:\n{err_text}"
            )
            try:
                self.helper.api.work.to_processed(work_id, fail_message, in_error=True)
            except Exception:
                self.helper.connector_logger.error(
                    "Could not report failed work to OpenCTI API",
                    {"work_id": work_id},
                )

    @staticmethod
    def _event_hint(event: Any) -> str:
        """Best-effort upstream id of an event for error/skip log lines."""
        if isinstance(event, dict):
            for value in event.values():
                if isinstance(value, dict) and value.get("id"):
                    return str(value["id"])[:128]
            if event.get("id"):
                return str(event["id"])[:128]
        return "unknown"

    def _process_portion(
        self,
        collection: str,
        prepared_data: dict[str, Any],
        portion: Any,
        work_id: str,
    ) -> None:
        parsed_portion = self.extra_pre_processing(
            collection=collection, portion=portion
        )
        size = len(parsed_portion)
        sent = 0
        empty = 0
        failed = 0

        for count, event in enumerate(parsed_portion, 1):
            event_id = self._event_hint(event)
            self.helper.connector_logger.info(
                f"Parsing {count}/{size} | collection={collection} "
                f"| event_id={event_id}"
            )
            # One malformed event must not abort the whole collection run:
            # log it loudly with its upstream id and keep processing. The
            # sequpdate cursor advances per portion, so the failure is
            # recorded here — not retried silently forever.
            try:
                bundle_objects = self._collect_intelligence(
                    collection=collection,
                    ttl=self.ttl,
                    event=event,
                    mitre_mapper=self.MITRE_MAPPER,
                    config=self.cfg,
                    flag_intrusion_set_instead_of_threat_actor=(
                        self.INTRUSION_SET_INSTEAD_OF_THREAT_ACTOR
                    ),
                )
                if bundle_objects is None:
                    bundle_objects = []
                elif not isinstance(bundle_objects, list):
                    bundle_objects = list(bundle_objects)

                if bundle_objects:
                    bundle = OpenCTIConnectorHelper.stix2_create_bundle(bundle_objects)
                    self.helper.connector_logger.info(
                        f"Sending {len(bundle_objects)} STIX objects " f"to OpenCTI..."
                    )
                    self.helper.send_stix2_bundle(
                        bundle,
                        update=self.update_existing_data,
                        work_id=work_id,
                        cleanup_inconsistent_bundle=True,
                    )
                    sent += 1
                else:
                    empty += 1
                    self.helper.connector_logger.warning(
                        f"{collection}: event produced no STIX objects "
                        f"(skipped) | event_id={event_id}"
                    )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                # Transient connectivity drops keep the old semantics:
                # abort the portion so the run resumes from the stored
                # cursor instead of skipping data the platform never saw.
                if self._is_transient_network_error(exc):
                    raise
                failed += 1
                self.helper.metric.inc("error_count")
                self.helper.connector_logger.error(
                    f"{collection}: event failed to convert/send and was "
                    f"skipped | event_id={event_id}\n{format_exc()}"
                )

        self.helper.connector_logger.info(
            f"{collection}: portion done | events={size} sent={sent} "
            f"empty={empty} failed={failed} seqUpdate={portion.sequpdate}"
        )
        prepared_data[collection].update({"sequpdate": portion.sequpdate})
        self.set_or_update_state(prepared_data=prepared_data)
