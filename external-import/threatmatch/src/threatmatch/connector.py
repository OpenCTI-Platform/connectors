import json
import sys
import traceback
from datetime import UTC, datetime
from typing import Any

from bs4 import BeautifulSoup
from pycti import OpenCTIConnectorHelper
from threatmatch.client import ThreatMatchClient
from threatmatch.config import ConnectorSettings


class Connector:
    def __init__(self, helper: OpenCTIConnectorHelper, config: ConnectorSettings):
        self.helper = helper
        self.config = config
        self.start_datetime = datetime.now(tz=UTC)  # redefined in _process()
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Security Alliance",
            description="Security Alliance is a cyber threat intelligence product and services company, formed in 2007.",
        )

    def _get_stix_objects(self, client, item_type, item_id):
        stix_objects = client.get_stix_objects(item_type, item_id)
        self.helper.connector_logger.info(
            f"Found {len(stix_objects)} STIX objects from {item_type} {item_id}'"
        )
        for stix_object in stix_objects:
            if "description" in stix_object and stix_object["description"]:
                stix_object["description"] = BeautifulSoup(
                    stix_object["description"], "html.parser"
                ).get_text()
        return stix_objects

    def _process_bundle(self, work_id, stix_objects):
        if len(stix_objects) > 0:
            final_objects = []
            for stix_object in stix_objects:
                if "error" in stix_object:
                    continue
                if "created_by_ref" not in stix_object:
                    stix_object["created_by_ref"] = self.identity["standard_id"]
                if "object_refs" in stix_object and stix_object["type"] not in [
                    "report",
                    "note",
                    "opinion",
                    "observed-data",
                ]:
                    del stix_object["object_refs"]
                    pass
                final_objects.append(stix_object)
            final_bundle = {"type": "bundle", "objects": final_objects}
            final_bundle_json = json.dumps(final_bundle)
            self.helper.send_stix2_bundle(final_bundle_json, work_id=work_id)

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

    def _collect_intelligence(self, last_run: datetime, work_id: str) -> None:
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
            self._process_bundle(work_id, stix_objects)

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
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            "ThreatMatch run @ " + self.start_datetime.isoformat(timespec="seconds"),
        )

        self._collect_intelligence(last_run, work_id)

        self.helper.set_state(
            {"last_run": self.start_datetime.isoformat(timespec="seconds")}
        )
        self.helper.api.work.to_processed(
            work_id,
            "Connector successfully run, storing last_run as "
            + self.start_datetime.isoformat(timespec="seconds"),
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

    def run(self):
        self.helper.connector_logger.info("Connector starting...")
        self.helper.schedule_process(
            message_callback=self._process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
