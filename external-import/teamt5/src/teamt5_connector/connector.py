import sys
from datetime import datetime, timezone

import stix2
from pycti import Identity as pyctiIdentity
from pycti import MarkingDefinition, OpenCTIConnectorHelper
from stix2 import Identity

from teamt5_connector.settings import ConnectorSettings
from teamt5_services import Teamt5Client
from .IndicatorBundleHandler import IndicatorBundleHandler
from .ReportHandler import ReportHandler


class TeamT5Connector:

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """

        self.config = config
        self.helper = helper
        self.client = Teamt5Client(self.helper, self.config)

        self.author = Identity(
            id=pyctiIdentity.generate_id(self.config.connector.name, "organization"),
            name=self.config.connector.name,
            identity_class="organization",
        )

        self.tlp_ref = self._create_tlp_marking(self.config.teamt5.tlp_level.lower())

        self.report_hanlder = ReportHandler(
            self.client, helper, config, self.author, self.tlp_ref
        )
        self.indicator_bundle_handler = IndicatorBundleHandler(
            self.client, helper, config, self.author, self.tlp_ref
        )

    def process_message(self) -> None:

        self.helper.connector_logger.info(f"{self.config.connector.name}: Starting Run")

        try:
            now = datetime.now(tz=timezone.utc)
            current_timestamp = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.connector_logger.info(
                    "Connector last run", {"last_run_datetime": last_run}
                )
                last_run_timestamp = int(
                    datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S").timestamp()
                )

            # If the connector has never run, we should retrieve from the timestamp specified in configs
            else:
                self.helper.connector_logger.info("Connector has never run...")
                last_run_timestamp = int(
                    self.config.teamt5.first_run_retrieval_timestamp
                )

            # For each handler (Reports and IOC Bundles) retrieve bundle references and push to OpenCTI
            for handler in [self.report_hanlder, self.indicator_bundle_handler]:
                self.helper.connector_logger.info(
                    f"Retrieving {handler.name} references from after: {datetime.fromtimestamp(last_run_timestamp)}"
                )
                retrieved_bundle_refs = handler.retrieve_bundle_references(
                    last_run_timestamp
                )

                if retrieved_bundle_refs:

                    self.helper.connector_logger.info(
                        f"Retrieval complete. {len(retrieved_bundle_refs)} new {handler.name} references found."
                    )
                    work_name = f"Creating {handler.name}s from TeamT5"
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, work_name
                    )
                    num_pushed = handler.push_objects(work_id, retrieved_bundle_refs)
                    push_message = f"Connector Pushed {num_pushed} {handler.name}s"
                    self.helper.connector_logger.info(push_message)
                    self.helper.api.work.to_processed(work_id, push_message)

                else:
                    self.helper.connector_logger.info(f"No new {handler.name}s found")

            current_state = self.helper.get_state()
            current_state_datetime = now.isoformat(timespec="seconds")
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
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def _create_tlp_marking(self, level: str) -> stix2.MarkingDefinition:
        """
        Returns a STIX2 Marking Defintion corresponding to the TLP level defined
        in the connector's configuration. A marking of 'clear/white is returned if
        the specified marking is invalid.

        :param level: Configured string reflecting the desired TLP level.
        :return: A Marking Definition for the desired TLP Marking.
        """
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        if level not in mapping:
            self.helper.connector_logger.info(
                f"Invalid TLP Marking: {level} defaulting to TLP_WHITE / clear"
            )
            return mapping["clear"]

        return mapping[level]

    def run(self) -> None:
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
