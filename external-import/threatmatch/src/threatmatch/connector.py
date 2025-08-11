import sys
import traceback
from datetime import UTC, datetime
from typing import Any

from pycti import OpenCTIConnectorHelper
from threatmatch.client import ThreatMatchClient
from threatmatch.config import ConnectorSettings
from threatmatch.converter import Converter


class Connector:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        config: ConnectorSettings,
        converter: Converter,
    ) -> None:
        self.helper = helper
        self.config = config
        self.converter = converter
        self.start_datetime = datetime.now(tz=UTC)  # redefined in _process()
        self.work_id = None

    def _get_stix_objects(self, client, item_type, item_id):
        stix_objects = client.get_stix_objects(item_type, item_id)
        self.helper.connector_logger.info(
            f"Found {len(stix_objects)} STIX objects from {item_type} {item_id}'"
        )
        return stix_objects

    def _get_all_content_group_id(self, taxii_groups: list[dict[str, Any]]) -> str:
        id_by_group = {group["name"]: group["id"] for group in taxii_groups}
        if all_content_group_id := id_by_group.get("All content"):
            return all_content_group_id
        raise ValueError(
            "No 'All content' group found in TAXII groups, only %s" % id_by_group.keys()
        )

    def _get_indicators(
        self,
        client: ThreatMatchClient,
        group_id: str,
        modified_after: str,
    ) -> dict:
        self.helper.connector_logger.info(
            f"Fetching indicators modified after {modified_after} from group {group_id}."
        )
        data = client.get_taxii_objects(group_id, "indicator", modified_after)
        indicators = data.get("objects", [])
        if data.get("more") and indicators:
            return indicators + self._get_indicators(
                client=client,
                group_id=group_id,
                modified_after=indicators[-1]["modified"],
            )
        return indicators

    def _collect_intelligence(self, last_run: datetime) -> list[dict[str, Any]]:
        import_from_date = (
            last_run.strftime("%Y-%m-%d %H:%M")
            if last_run
            else self.config.threatmatch.import_from_date
        )

        stix_objects = []

        with ThreatMatchClient(
            helper=self.helper,
            base_url=self.config.threatmatch.url.encoded_string(),
            client_id=self.config.threatmatch.client_id,
            client_secret=self.config.threatmatch.client_secret,
        ) as client:
            if self.config.threatmatch.import_profiles:
                profile_ids = client.get_profile_ids(import_from_date=import_from_date)
                self.helper.connector_logger.info(
                    f"Found {len(profile_ids)} profiles to import since {import_from_date}, fetching STIX objects..."
                )
                for profile_id in profile_ids:
                    stix_objects.extend(
                        self._get_stix_objects(client, "profiles", profile_id)
                    )
            if self.config.threatmatch.import_alerts:
                alert_ids = client.get_alert_ids(import_from_date=import_from_date)
                self.helper.connector_logger.info(
                    f"Found {len(alert_ids)} alerts to import since {import_from_date}, fetching STIX objects..."
                )
                for alert_id in alert_ids:
                    stix_objects.extend(
                        self._get_stix_objects(client, "alerts", alert_id)
                    )
            if self.config.threatmatch.import_iocs:
                stix_objects.extend(
                    self._get_indicators(
                        client=client,
                        group_id=self._get_all_content_group_id(
                            client.get_taxii_groups()
                        ),
                        modified_after=(
                            datetime.strptime(
                                import_from_date, "%Y-%m-%d %H:%M"
                            ).isoformat(timespec="milliseconds")
                            + "Z"
                        ),
                    )
                )
            self.helper.connector_logger.info(
                f"Found {len(stix_objects)} STIX objects to process since {import_from_date}."
            )
        return stix_objects

    @property
    def state(self) -> dict[str, Any]:
        return self.helper.get_state() or {}

    def _get_last_run(self) -> datetime | None:
        if last_run := self.state.get("last_run"):
            last_run = (
                datetime.fromtimestamp(last_run, tz=UTC)  # For retro compatibility
                if isinstance(last_run, float | int)
                else datetime.fromisoformat(last_run)
            )
        self.helper.connector_logger.info(
            (
                "Connector last run: "
                + (last_run.isoformat(timespec="seconds") if last_run else "never")
            ),
        )
        return last_run

    def _process_data(self):
        last_run = self._get_last_run()

        if stix_objects := self._collect_intelligence(last_run):

            self.work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                "ThreatMatch run @ "
                + self.start_datetime.isoformat(timespec="seconds"),
            )
            processed_stix_object = [
                processed_stix_object
                for stix_object in stix_objects
                for processed_stix_object in self.converter.process(stix_object)
            ]
            bundle = self.helper.stix2_create_bundle(
                items=[self.converter.author, self.converter.tlp_marking]
                + processed_stix_object
            )
            self.helper.send_stix2_bundle(bundle, work_id=self.work_id)

        self.helper.set_state(
            {"last_run": self.start_datetime.isoformat(timespec="seconds")}
        )

    def _process(self):
        self.start_datetime = datetime.now(tz=UTC)
        try:
            self.helper.connector_logger.info("Running connector...")
            self._process_data()
            self.helper.connector_logger.info("Connector successfully ran")
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stop")
            sys.exit(0)
        except Exception as e:
            traceback.print_exc()
            self.helper.connector_logger.error(str(e))
        finally:
            if self.work_id:
                self.helper.api.work.to_processed(self.work_id, "")

    def run(self):
        self.helper.connector_logger.info("Connector starting...")
        self.helper.schedule_process(
            message_callback=self._process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
