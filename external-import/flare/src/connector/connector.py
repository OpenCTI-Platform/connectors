from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

from connector.converter_to_stix import FlareToStixMapper
from connector.settings import ConnectorSettings
from flare_client.api_client import FlareClient
from pycti import OpenCTIConnectorHelper


class FlareConnector:
    def __init__(
        self,
        config: ConnectorSettings,
        helper: OpenCTIConnectorHelper,
        flare_client: FlareClient,
        mapper: FlareToStixMapper,
    ) -> None:
        self.config = config
        self.helper = helper
        self.flare_client = flare_client
        self.mapper = mapper

    def run(self) -> None:
        self.helper.connector_logger.debug(
            "Scheduling Flare Connector",
            {"duration_period": str(self.config.connector.duration_period)},
        )
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

    def process_message(self) -> None:
        try:
            current_state = self.helper.get_state()
            last_run_raw = (current_state or {}).get("last_run")
            if not isinstance(last_run_raw, str):
                from_date = datetime.now(timezone.utc) - timedelta(
                    days=self.config.flare.lookback_days
                )
                self.helper.connector_logger.info(
                    "First run - syncing events from lookback period",
                    {"lookback_days": self.config.flare.lookback_days},
                )
            else:
                last_run = datetime.fromisoformat(last_run_raw)
                from_date = last_run
                self.helper.connector_logger.info(
                    "Incremental sync",
                    {"from_date": from_date.isoformat()},
                )

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, "Flare sync"
            )
            self.helper.connector_logger.info(
                "Work initiated",
                {"work_id": work_id},
            )

            events = self.flare_client.get_events(
                from_date,
                event_types=self.config.flare.event_types,
                event_actions=self.config.flare.event_actions,
            )
            imported_count = self.process_events(events, work_id)
            self.helper.set_state({"last_run": datetime.now(timezone.utc).isoformat()})

            message = f"Sync completed. Imported {imported_count} events."
            self.helper.connector_logger.info(
                "Sync completed",
                {"imported_count": imported_count},
            )
            self.helper.api.work.to_processed(work_id, message)

        except Exception as e:
            self.helper.connector_logger.error(
                "Import failed",
                {"error": str(e), "type": type(e).__name__},
            )
            # Work will remain in "In Progress" or be marked as failed
            raise

    def process_events(
        self, events: Iterator[dict[str, Any]], work_id: str | None
    ) -> int:
        processed_count = 0

        for event in events:
            try:
                uid = event.get("data", {}).get("uid")
                self.helper.connector_logger.debug(
                    "Processing event",
                    {"event_index": processed_count, "uid": uid},
                )

                incident, related_indicators = self.mapper.map_event_to_incident(event)
                self.helper.connector_logger.debug(
                    "Mapped event to incident",
                    {
                        "incident_name": incident.name,
                        "related_objects_count": len(related_indicators),
                    },
                )

                bundle_objects = [
                    self.mapper.author,
                    self.mapper.tlp_level,
                    incident,
                ] + related_indicators

                bundle = self.helper.stix2_create_bundle(bundle_objects)
                self.helper.connector_logger.debug(
                    "Created STIX bundle",
                    {"bundle_objects_count": len(bundle_objects)},
                )

                if bundle is None:
                    self.helper.connector_logger.error(
                        "STIX bundle creation failed",
                        {"uid": uid},
                    )
                    continue

                self.helper.send_stix2_bundle(
                    bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                processed_count += 1
                self.helper.connector_logger.debug(
                    "Imported event",
                    {"event_index": processed_count, "incident_name": incident.name},
                )

            except Exception as e:
                uid = event.get("data", {}).get("uid")
                self.helper.connector_logger.error(
                    "Error importing event",
                    {"uid": uid, "error": str(e), "type": type(e).__name__},
                )

        return processed_count
