"""OpenCTI Splunk connector orchestration."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from typing import Any

from pycti import OpenCTIConnectorHelper
from splunk_connector.client import SplunkClient
from splunk_connector.converter_to_stix import ConverterToStix
from splunk_connector.importers import IdentitiesImporter, IncidentsImporter, IndicatorsImporter
from splunk_connector.importers.base import BaseImporter
from splunk_connector.settings import ConnectorSettings


class SplunkConnector:
    """External import connector for Splunk and Splunk Enterprise Security."""

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper) -> None:
        self.config = config
        self.helper = helper
        token = self.config.splunk.token.get_secret_value()
        self.client = SplunkClient(
            base_url=str(self.config.splunk.base_url),
            token=token,
            verify_ssl=self.config.splunk.verify_ssl,
            timeout_seconds=self.config.splunk.timeout_seconds,
            owner=self.config.splunk.owner,
            app=self.config.splunk.app,
            es_api_prefix=self.config.splunk.es_api_prefix,
        )
        self.converter = ConverterToStix(
            tlp_level=self.config.splunk.tlp_level,
            confidence=self.config.splunk.confidence,
        )
        self.importers = self._build_importers()

    def _build_importers(self) -> list[BaseImporter]:
        scopes = set(self.config.splunk.scopes)
        importers: list[BaseImporter] = []
        if self.config.splunk.import_indicators and "indicator" in scopes:
            importers.append(IndicatorsImporter(self.config, self.client, self.converter))
        if self.config.splunk.import_identities and "identity" in scopes:
            importers.append(IdentitiesImporter(self.config, self.client, self.converter))
        if self.config.splunk.import_incidents and "incident" in scopes:
            importers.append(IncidentsImporter(self.config, self.client, self.converter))
        return importers

    def process_message(self) -> None:
        self.helper.connector_logger.info(
            "[SPLUNK] Starting connector run",
            {"connector_name": self.helper.connect_name},
        )
        if not self.importers:
            self.helper.connector_logger.warning("[SPLUNK] No enabled importers")
            return

        try:
            now = datetime.now(UTC)
            state = self._load_state()
            new_state = state.copy()
            failures: list[str] = []

            for importer in self.importers:
                if not importer.should_run(new_state, now):
                    self.helper.connector_logger.info(
                        "[SPLUNK] Skipping dataset; interval has not elapsed",
                        {"dataset": importer.state_key},
                    )
                    continue
                try:
                    self._run_importer(importer, new_state)
                except Exception as exc:
                    failures.append(f"{importer.state_key}: {exc}")
                    continue

            new_state["last_run"] = datetime.now(UTC).isoformat()
            self.helper.set_state(new_state)
            if failures:
                raise RuntimeError(
                    "One or more Splunk importers failed: " + "; ".join(failures)
                )
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[SPLUNK] Connector stopped")
            sys.exit(0)
        except Exception as exc:
            self.helper.connector_logger.error(
                "[SPLUNK] Connector internal error",
                {"error": str(exc)},
            )
            raise

    def _run_importer(self, importer: BaseImporter, state: dict[str, Any]) -> None:
        work_id = self._initiate_work(importer.name)
        try:
            stix_objects, dataset_state = importer.collect(state)
            total_sent = self._send_objects(importer.name, work_id, stix_objects)
            dataset_state["objects_sent"] = total_sent
            state[importer.state_key] = dataset_state
            self.helper.set_state(state)
            message = (
                f"{self.helper.connect_name} {importer.name} successfully imported "
                f"{total_sent} STIX objects"
            )
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(
                "[SPLUNK] Dataset import complete",
                {"dataset": importer.state_key, "objects_sent": total_sent},
            )
        except Exception as exc:
            self.helper.connector_logger.error(
                "[SPLUNK] Dataset import failed",
                {"dataset": importer.state_key, "error": str(exc)},
            )
            raise

    def _send_objects(self, dataset_name: str, work_id: str, stix_objects: list[Any]) -> int:
        if not stix_objects:
            self.helper.connector_logger.info(
                "[SPLUNK] No STIX objects to send",
                {"dataset": dataset_name},
            )
            return 0

        common_objects = self.converter.common_objects()
        batch_size = self.config.splunk.batch_size
        total_sent = 0
        for index in range(0, len(stix_objects), batch_size):
            batch = stix_objects[index : index + batch_size]
            bundle = self.helper.stix2_create_bundle(batch + common_objects)
            bundles_sent = self.helper.send_stix2_bundle(
                bundle,
                work_id=work_id,
                cleanup_inconsistent_bundle=True,
            )
            total_sent += len(batch)
            self.helper.connector_logger.info(
                "[SPLUNK] Sent STIX bundle",
                {
                    "dataset": dataset_name,
                    "objects": len(batch),
                    "bundles_sent": len(bundles_sent),
                },
            )
        return total_sent

    def _initiate_work(self, importer_name: str) -> str:
        friendly_name = (
            f"{self.helper.connect_name}/{importer_name} run @ "
            f"{datetime.now(UTC).isoformat()}"
        )
        return self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)

    def _load_state(self) -> dict[str, Any]:
        current_state = self.helper.get_state()
        return current_state if isinstance(current_state, dict) else {}

    def run(self) -> None:
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
