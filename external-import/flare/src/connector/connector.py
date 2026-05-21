from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

from pycti import OpenCTIConnectorHelper
from pydantic import TypeAdapter

from connector.converter_to_stix import FlareToStixMapper
from connector.settings import ConnectorSettings
from flare_client.api_client import FlareClient

_td_adapter: TypeAdapter[timedelta] = TypeAdapter(timedelta)


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
        td = _td_adapter.validate_python(self.config.connector_duration_period)
        self.helper.connector_logger.debug(
            f"Scheduling Flare Connector using duration period: "
            f"{self.config.connector_duration_period}"
        )
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=td.total_seconds(),
        )

    def process_message(self) -> None:
        work_id = None
        try:
            current_state = self.helper.get_state()

            if current_state is None or "last_run" not in current_state:
                from_date = datetime.now(timezone.utc) - timedelta(
                    days=self.config.flare_lookback_days
                )
                self.helper.connector_logger.info(
                    f"First run - syncing events from last {self.config.flare_lookback_days} days"
                )
            else:
                last_run = datetime.fromisoformat(current_state["last_run"])
                from_date = last_run
                self.helper.connector_logger.info(f"Incremental sync from {from_date}")

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, "Flare sync"
            )
            self.helper.connector_logger.info(f"Work initiated: {work_id}")

            events = self.flare_client.get_events(
                from_date,
                event_types=self.config.flare_event_types,
                event_actions=self.config.flare_event_actions,
            )
            imported_count = self.process_events(events, work_id)

            self.helper.set_state({"last_run": datetime.now(timezone.utc).isoformat()})

            message = f"Sync completed. Imported {imported_count} events."
            self.helper.connector_logger.info(message)
            if work_id:
                self.helper.api.work.to_processed(work_id, message)

        except Exception as e:
            self.helper.connector_logger.error(f"Error during sync: {e}")
            if work_id:
                self.helper.api.work.to_processed(work_id, str(e), in_error=True)

    def process_events(
        self, events: Iterator[dict[str, Any]], work_id: str | None
    ) -> int:
        processed_count = 0

        for event in events:
            try:
                self.helper.connector_logger.debug(
                    f"Processing event {processed_count}: {event.get('id')}"
                )

                incident, related_indicators = self.mapper.map_event_to_incident(event)
                self.helper.connector_logger.debug(
                    f"Mapped to incident: {incident.name}, "
                    f"with {len(related_indicators)} related objects"
                )

                bundle_objects = [
                    self.mapper.author,
                    incident,
                ] + related_indicators

                bundle = self.helper.stix2_create_bundle(bundle_objects)
                self.helper.connector_logger.debug(
                    f"Created bundle with {len(bundle_objects)} objects"
                )

                if bundle is None:
                    self.helper.connector_logger.error(
                        f"Stix bundle creation failed for event {event.get('id')}"
                    )
                    continue

                self.helper.send_stix2_bundle(
                    bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                processed_count += 1
                self.helper.connector_logger.debug(
                    f"Imported event {processed_count}: {incident.name}"
                )

            except Exception as e:
                self.helper.connector_logger.error(
                    f"Error importing event {event.get('id')}: {e}"
                )

        return processed_count
