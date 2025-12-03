import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List
from urllib.parse import urljoin

import stix2
from pycti import Identity, MarkingDefinition, OpenCTIConnectorHelper

from .client_api import CrowdSecClient
from .config_loader import CrowdSecConfig
from .converter_to_stix import CrowdSecBuilder
from .utils import get_ip_version, handle_none_cti_value, handle_observable_description


class CrowdSecImporter:
    """
    Specifications of the external import connector

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.

    ---

    Attributes
        - `config (CrowdSecConfig())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

        - `converter_to_stix (ConnectorConverter(helper))`:
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to encapsulate the main process in a scheduler
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ
        - `self.helper.set_state()` is used to set state

    """

    BATCH_SIZE = 100
    CTI_URL = "https://app.crowdsec.net/cti/"

    def __init__(self, config: CrowdSecConfig, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper
        self.client = CrowdSecClient(self.helper, self.config)
        self.tlp_marking = self._create_tlp_marking(level=self.config.tlp_level.lower())
        # Initialize CrowdSec entity
        self.crowdsec_ent = None
        self.crowdsec_ent_name = "CrowdSec"
        self.crowdsec_ent_desc = "Curated Threat Intelligence Powered by the Crowd"
        self.organisation = self.get_or_create_crowdsec_ent()
        self.author = self.create_author()
        # Initialize seen labels to avoid duplicates label creation
        self.seen_labels = set()
        self.errors = []

    def get_or_create_crowdsec_ent(self) -> Identity:
        if getattr(self, "crowdsec_ent", None) is not None:
            return self.crowdsec_ent
        crowdsec_ent = self.helper.api.stix_domain_object.get_by_stix_id_or_name(
            name=self.crowdsec_ent_name
        )
        if not crowdsec_ent:
            self.crowdsec_ent = self.helper.api.identity.create(
                type="Organization",
                name=self.crowdsec_ent_name,
                description=self.crowdsec_ent_desc,
            )
        else:
            self.crowdsec_ent = crowdsec_ent
        return self.crowdsec_ent

    def create_author(self) -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(
                name=self.crowdsec_ent_name, identity_class="organization"
            ),
            name=self.crowdsec_ent_name,
            identity_class="organization",
            description=self.crowdsec_ent_desc,
            external_references=[
                stix2.ExternalReference(
                    source_name="Crowdsec CTI",
                    url=self.CTI_URL,
                    description="Explore the CrowdSec Threat Intelligence, and get a full report of IPs.",
                )
            ],
        )
        return author

    @staticmethod
    def _create_tlp_marking(level):
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
        return mapping[level]

    @staticmethod
    def format_duration(seconds: int) -> str:
        return str(timedelta(seconds=seconds))

    def _enrich_ip(
        self,
        ip: str,
        cti_data: Dict,
        batch_labels: List,
        stix_objects: List,
    ) -> bool:
        ip_version = get_ip_version(ip)
        if ip_version not in [4, 6]:
            message = f"IP {ip} is not a valid IPv4 or IPv6 address"
            self.helper.log_error(message)
            self.errors.append(message)
            return False
        # Preparing the bundle to be sent to OpenCTI worker
        bundle_objects = []
        # Early return if last enrichment was less than some configured time
        database_observable = self.helper.api.stix_cyber_observable.read(
            filters={
                "mode": "and",
                "filters": [
                    {
                        "key": "value",
                        "values": [ip],
                    }
                ],
                "filterGroups": [],
            }
        )

        if database_observable:
            tlp = "TLP:WHITE"
            for marking_definition in database_observable["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    tlp = marking_definition["definition"]

            if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.config.max_tlp):
                self.helper.log_info(
                    f"Skipping enrichment for IP {ip}: "
                    f"Observable TLP ({tlp}) is greater than MAX TLP ({self.config.max_tlp})"
                )
                return False
        ip_timestamp = int(time.time())
        handle_description = handle_observable_description(
            ip_timestamp, database_observable
        )
        time_since_last_enrichment = handle_description["time_since_last_enrichment"]
        min_delay = self.config.min_delay_between_enrichments
        if time_since_last_enrichment != -1 and time_since_last_enrichment < min_delay:
            message = (
                f"Last enrichment was less than {min_delay} seconds ago, "
                f"skipping enrichment for IP: {ip}"
            )
            self.helper.log_info(message)
            # Skipping the enrichment for this IP
            return False

        description = None
        if self.config.last_enrichment_date_in_description:
            description = handle_description["description"]

        # Retrieve specific data from CTI
        self.helper.log_debug(f"CTI data for {ip}: {cti_data}")
        reputation = cti_data.get("reputation", "")
        mitre_techniques = handle_none_cti_value(cti_data.get("mitre_techniques", []))
        cves = handle_none_cti_value(cti_data.get("cves", []))

        indicator = None
        builder = CrowdSecBuilder(
            self.helper,
            self.config,
            cti_data=cti_data,
            organisation=self.organisation,
        )
        cti_external_reference = {
            "source_name": "CrowdSec CTI",
            "url": urljoin(self.CTI_URL, ip),
            "description": "CrowdSec CTI url for this IP",
        }

        labels = builder.handle_labels()
        for label in labels:
            label_tuple = (label["value"], label["color"])
            if label_tuple not in self.seen_labels:
                self.seen_labels.add(label_tuple)
                batch_labels.append(label)

        stix_observable = builder.upsert_observable(
            ip_version=ip_version,
            description=description,
            labels=labels,
            markings=[self.tlp_marking] if self.tlp_marking else None,
            external_references=[cti_external_reference],
            update=True if database_observable else False,
        )
        self.helper.log_debug(f"STIX Observable created/updated: {stix_observable}")
        # Start Bundle creation wby adding observable
        builder.add_to_bundle([stix_observable])
        observable_id = stix_observable["id"]
        # Initialize external reference for sightings
        sighting_ext_refs = [cti_external_reference]
        # Handle reputation
        if reputation in self.config.indicator_create_from:
            pattern = (
                f"[ipv4-addr:value = '{ip}']"
                if ip_version == 4
                else f"[ipv6-addr:value = '{ip}']"
            )
            indicator = builder.add_indicator_based_on(
                observable_id,
                stix_observable,
                pattern,
                markings=[self.tlp_marking] if self.tlp_marking else None,
            )
        # Handle mitre_techniques
        attack_patterns = []
        for mitre_technique in mitre_techniques:
            mitre_external_reference = builder.create_external_ref_for_mitre(
                mitre_technique
            )
            sighting_ext_refs.append(mitre_external_reference)
            # Create attack pattern
            if self.config.attack_pattern_create_from_mitre:
                attack_pattern = builder.add_attack_pattern_for_mitre(
                    mitre_technique=mitre_technique,
                    markings=[self.tlp_marking] if self.tlp_marking else None,
                    indicator_id=(indicator.id if indicator else None),
                    observable_id=observable_id,
                    external_references=[mitre_external_reference],
                )
                attack_patterns.append(attack_pattern.id)
        # Handle CVEs
        if self.config.vulnerability_create_from_cve:
            for cve in cves:
                # Create vulnerability
                builder.add_vulnerability_from_cve(
                    cve,
                    markings=[self.tlp_marking] if self.tlp_marking else None,
                    observable_id=observable_id,
                )
        # Handle target countries
        builder.handle_target_countries(
            attack_patterns=attack_patterns,
            markings=[self.tlp_marking] if self.tlp_marking else None,
            observable_id=(
                observable_id
                if self.config.create_targeted_countries_sightings
                else None
            ),
            indicator_id=(indicator.id if indicator else None),
        )
        # Add note
        if self.config.create_note:
            builder.add_note(
                observable_id=stix_observable.id,
                markings=[self.tlp_marking] if self.tlp_marking else None,
            )
        # Create sightings relationship between CrowdSec organisation and observable
        if self.config.create_sighting:
            builder.add_sighting(
                observable_id=stix_observable.id,
                markings=[self.tlp_marking] if self.tlp_marking else None,
                sighting_ext_refs=sighting_ext_refs,
                indicator=indicator if indicator else None,
            )

        bundle_objects.extend(builder.get_bundle())
        stix_objects.extend(bundle_objects)
        return True

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CrowdSec CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Get the current state
            now = datetime.now()
            current_timestamp = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                self.helper.connector_logger.info(
                    "[CrowdSec CONNECTOR] Connector last run",
                    {"last_run_datetime": last_run},
                )
            else:
                self.helper.connector_logger.info(
                    "[CrowdSec CONNECTOR] Connector has never run..."
                )

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = f"CrowdSec CTI import connector run @ {now}"

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CrowdSec CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Retrieve CrowdSec IPS from Smoke Search CTI API
            ip_list = self.client.get_entities()

            ip_count = len(ip_list)
            self.helper.log_info(f"Total IPs count: {ip_count}")
            counter = 0
            ip_items = list(ip_list.items())
            total_batch_count = (ip_count + self.BATCH_SIZE - 1) // self.BATCH_SIZE
            start_enrichment_time = time.time()

            enrichments_count = 0
            enrichment_threshold = self.config.enrichment_threshold_per_import
            exit_batch_loop = False
            # Loop through the IPs and send it as STIX objects bundle in batches
            for i in range(0, ip_count, self.BATCH_SIZE):
                if exit_batch_loop:
                    break
                batch = ip_items[i : i + self.BATCH_SIZE]
                batch_start_time = time.time()
                batch_index = i // self.BATCH_SIZE + 1
                self.helper.log_info(
                    f"Processing batch {batch_index}/{total_batch_count} with {len(batch)} IPs"
                )
                # Preparing the bundle to be sent to OpenCTI worker
                stix_objects = []
                batch_labels = []
                for ip, cti_data in batch:
                    try:
                        if enrichments_count >= enrichment_threshold:
                            self.helper.log_info(
                                f"Enrichment threshold reached: {enrichment_threshold}"
                            )
                            exit_batch_loop = True
                            break
                        counter += 1
                        # Enrich IP
                        if self._enrich_ip(
                            ip,
                            cti_data,
                            batch_labels,
                            stix_objects,
                        ):
                            enrichments_count += 1
                    except Exception as e:
                        message = f"Error processing IP {ip}: {str(e)}"
                        self.helper.log_error(message)
                        self.errors.append(message)
                # Create labels with colors (not possible to set colors in a bundle object)
                if batch_labels:
                    try:
                        for label in batch_labels:
                            self.helper.api.label.read_or_create_unchecked(
                                value=label["value"], color=label["color"]
                            )
                    except Exception as e:
                        message = f"Error creating labels: {str(e)}"
                        self.helper.log_error(message)
                        self.errors.append(message)
                batch_end_time = time.time()
                batch_time_taken = batch_end_time - batch_start_time
                time_from_enrichment_start = batch_end_time - start_enrichment_time

                self.helper.log_info(
                    f"Processing batch {batch_index}/{total_batch_count} "
                    f"took {batch_time_taken:.4f} seconds"
                )
                # Calculate the remaining processing time every 5 batches for progress updates
                if batch_index % 5 == 0 and enrichments_count > 0:
                    # Estimate time remaining based on two scenarios:
                    # 1. If enrichment threshold > IP count: estimate based on remaining batches
                    # 2. If enrichment threshold <= IP count: estimate based on remaining enrichments to reach the threshold
                    remaining_time = (
                        (time_from_enrichment_start / batch_index)
                        * (total_batch_count - batch_index)
                        if enrichment_threshold > ip_count
                        else (time_from_enrichment_start / enrichments_count)
                        * (enrichment_threshold - enrichments_count)
                    )
                    self.helper.log_info(
                        (
                            "Elapsed time since start of enrichment: "
                            f"{self.format_duration(int(time_from_enrichment_start))} / "
                            "Estimated time remaining: "
                            f"{self.format_duration(int(remaining_time))}"
                        )
                    )
                    self.helper.log_info(
                        (
                            f"Current number of enrichments: {enrichments_count}. "
                            f"Enrichment threshold: {enrichment_threshold}. "
                            f"Total IPs count: {ip_count}"
                        )
                    )
                if len(stix_objects):
                    try:
                        bundle_start_time = time.time()
                        self.helper.log_info(
                            f"Start sending {len(stix_objects)} bundles to OpenCTI"
                        )
                        # Ensure a consistent bundle by adding the author and TLP marking
                        stix_objects.append(self.author)
                        stix_objects.append(self.tlp_marking)
                        stix_objects_bundle = self.helper.stix2_create_bundle(
                            stix_objects
                        )
                        # Sending the bundle
                        self.helper.send_stix2_bundle(
                            stix_objects_bundle,
                            update=self.config.update_existing_data,
                            work_id=work_id,
                            cleanup_inconsistent_bundle=True,
                        )
                        bundle_end_time = time.time()
                        bundle_time_taken = bundle_end_time - bundle_start_time
                        self.helper.log_info(
                            f"Sending bundles took {bundle_time_taken:.4f} seconds"
                        )
                    except Exception as e:
                        message = f"Error sending bundles: {str(e)}"
                        self.helper.log_error(message)
                        self.errors.append(message)

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            current_state = self.helper.get_state()
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
                "[CrowdSec CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )
