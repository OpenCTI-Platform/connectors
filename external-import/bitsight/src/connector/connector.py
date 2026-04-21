import sys
from datetime import datetime, timezone

from bitsight_client import BitSightClient
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class BitSightConnector:
    """
    BitSight external import connector.

    Fetches actionable alerts from the Cybersixgill API and converts them
    to STIX bundles for ingestion into OpenCTI.

    Flow:
        1. Authenticate (bearer token, 30 min validity)
        2. List monitored organisations (multi-tenant)
        3. Fetch recent alerts per organisation
        4. Get full detail for each alert
        5. Optionally get supplementary alert content
        6. Convert alerts to STIX and send to OpenCTI
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.client = BitSightClient(
            helper=self.helper,
            client_id=self.config.bitsight.client_id,
            client_secret=self.config.bitsight.client_secret,
        )
        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level=self.config.bitsight.tlp_level,
        )

    def _collect_intelligence(self) -> list:
        """
        Collect intelligence from BitSight API and convert into STIX objects.

        :return: List of STIX objects
        """
        stix_objects = []

        # Step 2 - Get organisations (multi-tenant)
        organizations = self.client.get_organizations()
        if not organizations:
            self.helper.connector_logger.info(
                "[CONNECTOR] No organisations found or single-tenant mode. "
                "Fetching alerts without org filter."
            )
            organizations = [None]

        for org in organizations:
            org_id = org.get("organization_id") if isinstance(org, dict) else None
            org_name = (
                org.get("name", "unknown")
                if isinstance(org, dict)
                else "single-tenant"
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Processing organisation",
                {"org_id": org_id, "org_name": org_name},
            )

            # Step 3 - List recent alerts
            alerts_response = self.client.get_alerts(org_id=org_id)
            if not alerts_response:
                self.helper.connector_logger.info(
                    "[CONNECTOR] No alerts found for organisation",
                    {"org_id": org_id},
                )
                continue

            alerts = alerts_response if isinstance(alerts_response, list) else []

            for alert in alerts:
                alert_id = alert.get("id")
                if not alert_id:
                    continue

                # Step 4 - Get alert detail
                alert_detail = self.client.get_alert_detail(
                    alert_id=alert_id, org_id=org_id
                )
                if not alert_detail:
                    continue

                # Step 5 - Get supplementary content (best-effort)
                alert_content = self.client.get_alert_content(
                    alert_id=alert_id, org_id=org_id
                )
                if alert_content:
                    alert_detail["extra_content"] = alert_content

                # Convert to STIX
                incident = self.converter_to_stix.create_incident_from_alert(
                    alert_detail
                )
                if incident:
                    stix_objects.append(incident)

        # Add author and TLP marking for consistency
        if stix_objects:
            stix_objects.append(self.converter_to_stix.author)
            stix_objects.append(self.converter_to_stix.tlp_marking)

        return stix_objects

    def process_message(self) -> None:
        """Connector main process to collect intelligence."""
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            now = datetime.now()
            current_timestamp = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": current_state["last_run"]},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            friendly_name = "BitSight alerts feed"
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            stix_objects = self._collect_intelligence()

            if stix_objects:
                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_objects_bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )
                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": {str(len(bundles_sent))}},
                )

            # Store last run
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
            last_run_datetime = datetime.fromtimestamp(
                current_timestamp, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S")
            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(last_run_datetime)
            )
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """Start the connector and schedule periodic runs."""
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

