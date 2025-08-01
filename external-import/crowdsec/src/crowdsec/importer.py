# -*- coding: utf-8 -*-
"""CrowdSec external import module."""
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List
from urllib.parse import urljoin

import stix2
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Identity

from .builder import CrowdSecBuilder
from .client import CrowdSecClient
from .constants import CTI_API_URL, CTI_URL
from .helper import (
    clean_config,
    get_ip_version,
    handle_none_cti_value,
    handle_observable_description,
)


class CrowdSecImporter:
    BATCH_SIZE = 100

    def __init__(self):
        self.crowdsec_ent = None
        # Instantiate the connector helper from config
        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"
        self.config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(self.config)
        self.crowdsec_ent_name = "CrowdSec"
        self.crowdsec_ent_desc = "Curated Threat Intelligence Powered by the Crowd"
        self.crowdsec_cti_key = clean_config(
            get_config_variable("CROWDSEC_KEY", ["crowdsec", "key"], self.config)
        )
        self.crowdsec_api_version = clean_config(
            get_config_variable(
                "CROWDSEC_API_VERSION",
                ["crowdsec", "api_version"],
                self.config,
                default="v2",
            )
        )
        self.enrichment_threshold_per_import = get_config_variable(
            "CROWDSEC_ENRICHMENT_THRESHOLD_PER_IMPORT",
            ["crowdsec", "enrichment_threshold_per_import"],
            self.config,
            default=2000,
            isNumber=True,
        )
        self.max_tlp = clean_config(
            get_config_variable(
                "CROWDSEC_MAX_TLP",
                ["crowdsec", "max_tlp"],
                self.config,
                default="TLP:AMBER",
            )
        )
        self.create_note = get_config_variable(
            "CROWDSEC_CREATE_NOTE",
            ["crowdsec", "create_note"],
            self.config,
            default=True,
        )
        self.create_sighting = get_config_variable(
            "CROWDSEC_CREATE_SIGHTING",
            ["crowdsec", "create_sighting"],
            self.config,
            default=True,
        )
        self.vulnerability_create_from_cve = get_config_variable(
            "CROWDSEC_VULNERABILITY_CREATE_FROM_CVE",
            ["crowdsec", "vulnerability_create_from_cve"],
            self.config,
            default=True,
        )
        tlp_config = clean_config(
            get_config_variable(
                "CROWDSEC_TLP",
                ["crowdsec", "tlp"],
                self.config,
                default=None,
            )
        )
        self.tlp = getattr(stix2, tlp_config) if tlp_config else None
        self.min_delay_between_enrichments = get_config_variable(
            "CROWDSEC_MIN_DELAY_BETWEEN_ENRICHMENTS",
            ["crowdsec", "min_delay_between_enrichments"],
            self.config,
            default=86400,
            isNumber=True,
        )
        self.last_enrichment_date_in_description = get_config_variable(
            "CROWDSEC_LAST_ENRICHMENT_DATE_IN_DESCRIPTION",
            ["crowdsec", "last_enrichment_date_in_description"],
            self.config,
            default=True,
        )
        self.create_targeted_countries_sightings = get_config_variable(
            "CROWDSEC_CREATE_TARGETED_COUNTRIES_SIGHTINGS",
            ["crowdsec", "create_targeted_countries_sightings"],
            self.config,
            default=False,
        )
        raw_indicator_create_from = clean_config(
            get_config_variable(
                "CROWDSEC_INDICATOR_CREATE_FROM",
                ["crowdsec", "indicator_create_from"],
                self.config,
                default="malicious,suspicious,known",
            )
        )
        self.indicator_create_from = raw_indicator_create_from.split(",")

        self.attack_pattern_create_from_mitre = get_config_variable(
            "CROWDSEC_ATTACK_PATTERN_CREATE_FROM_MITRE",
            ["crowdsec", "attack_pattern_create_from_mitre"],
            self.config,
            default=True,
        )
        self.interval = get_config_variable(
            "CROWDSEC_IMPORT_INTERVAL",
            ["crowdsec", "import_interval"],
            self.config,
            True,
            24,
        )
        self.helper.log_error("test1")
        self.query = get_config_variable(
            "CROWDSEC_IMPORT_QUERY",
            ["crowdsec", "import_query"],
            self.config,
            False,
            'behaviors.label:"SSH Bruteforce"',
        )
        self.helper.log_error("test2")
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            self.config,
        )
        if self.crowdsec_api_version != "v2":
            raise Exception(
                f"CrowdSec api version '{self.crowdsec_api_version}' is not supported "
            )
        else:
            self.api_base_url = "https://admin.api.crowdsec.net/v1/integrations/685c054a0e6230feeb849ee8/content"
        self.client = CrowdSecClient(
            helper=self.helper,
            url=f"{CTI_API_URL}{self.crowdsec_api_version}/smoke/search",
            api_key=self.crowdsec_cti_key,
        )
        self.errors = []
        self.seen_labels = set()

    def get_interval(self):
        """Get the interval in seconds."""
        return int(self.interval) * 60 * 60

    @staticmethod
    def format_duration(seconds: int) -> str:
        return str(timedelta(seconds=seconds))

    @staticmethod
    def convert_seconds(seconds):
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        return f"{days} days {hours} hours {minutes} mins {secs} secs"

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

    def _enrich_ip(
        self,
        ip: str,
        cti_data: Dict,
        batch_labels: List,
        batch_bundle_objects: List,
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

            if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
                self.helper.log_info(
                    f"Skipping enrichment for IP {ip}: "
                    f"Observable TLP ({tlp}) is greater than MAX TLP ({self.max_tlp})"
                )
                return False
        ip_timestamp = int(time.time())
        handle_description = handle_observable_description(
            ip_timestamp, database_observable
        )
        time_since_last_enrichment = handle_description["time_since_last_enrichment"]
        min_delay = self.min_delay_between_enrichments
        if time_since_last_enrichment != -1 and time_since_last_enrichment < min_delay:
            message = (
                f"Last enrichment was less than {min_delay} seconds ago, "
                f"skipping enrichment for IP: {ip}"
            )
            self.helper.log_info(message)
            # Skipping the enrichment for this IP
            return False

        description = None
        if self.last_enrichment_date_in_description:
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
            organisation=self.get_or_create_crowdsec_ent(),
        )
        cti_external_reference = {
            "source_name": "CrowdSec CTI",
            "url": urljoin(CTI_URL, ip),
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
            markings=[self.tlp] if self.tlp else None,
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
        if reputation in self.indicator_create_from:
            pattern = (
                f"[ipv4-addr:value = '{ip}']"
                if ip_version == 4
                else f"[ipv6-addr:value = '{ip}']"
            )
            indicator = builder.add_indicator_based_on(
                observable_id,
                stix_observable,
                pattern,
                markings=[self.tlp] if self.tlp else None,
            )
        # Handle mitre_techniques
        attack_patterns = []
        for mitre_technique in mitre_techniques:
            mitre_external_reference = builder.create_external_ref_for_mitre(
                mitre_technique
            )
            sighting_ext_refs.append(mitre_external_reference)
            # Create attack pattern
            if self.attack_pattern_create_from_mitre:
                attack_pattern = builder.add_attack_pattern_for_mitre(
                    mitre_technique=mitre_technique,
                    markings=[self.tlp] if self.tlp else None,
                    indicator_id=(indicator.id if indicator else None),
                    observable_id=observable_id,
                    external_references=[mitre_external_reference],
                )
                attack_patterns.append(attack_pattern.id)
        # Handle CVEs
        if self.vulnerability_create_from_cve:
            for cve in cves:
                # Create vulnerability
                builder.add_vulnerability_from_cve(
                    cve,
                    markings=[self.tlp] if self.tlp else None,
                    observable_id=observable_id,
                )
        # Handle target countries
        builder.handle_target_countries(
            attack_patterns=attack_patterns,
            markings=[self.tlp] if self.tlp else None,
            observable_id=(
                observable_id if self.create_targeted_countries_sightings else None
            ),
            indicator_id=(indicator.id if indicator else None),
        )
        # Add note
        if self.create_note:
            builder.add_note(
                observable_id=stix_observable.id,
                markings=[self.tlp] if self.tlp else None,
            )
        # Create sightings relationship between CrowdSec organisation and observable
        if self.create_sighting:
            builder.add_sighting(
                observable_id=stix_observable.id,
                markings=[self.tlp] if self.tlp else None,
                sighting_ext_refs=sighting_ext_refs,
                indicator=indicator if indicator else None,
            )

        bundle_objects.extend(builder.get_bundle())
        batch_bundle_objects.extend(bundle_objects)
        return True

    def run(self) -> None:
        self.helper.log_info("CrowdSec external import running ...")
        while True:
            try:
                # Get the current timestamp and check
                current_state = self.helper.get_state() or {}
                now = datetime.now(timezone.utc).replace(microsecond=0)
                last_run_state = current_state.get("last_run", 0)
                last_run = datetime.fromtimestamp(
                    last_run_state, tz=timezone.utc
                ).replace(microsecond=0)
                if last_run.year == 1970:
                    self.helper.log_info("CrowdSec import has never run")
                else:
                    self.helper.log_info(f"Connector last run: {last_run}+00:00")

                # If the last_run is old enough, run the connector
                if (now - last_run).total_seconds() > self.get_interval():
                    # Initiate the run
                    self.helper.log_info("CrowdSec import connector will run!")
                    # Flag current run as last run to avoid multiple concurrent runs
                    run_start_timestamp = int(time.time())
                    self.helper.set_state({"last_run": run_start_timestamp})
                    friendly_name = f"CrowdSec import connector run @ {now}"
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        # Retrieve CrowdSec IPS from Smoke Search API
                        ip_list: Dict[str, Dict] = self.client.get_searched_ips(
                            since=self.interval,
                            query=self.query,
                            enrichment_threshold=self.enrichment_threshold_per_import,
                        )
                        ip_count = len(ip_list)
                        self.helper.log_info(f"Total IPs count: {ip_count}")
                        counter = 0
                        ip_items = list(ip_list.items())
                        total_batch_count = (
                            ip_count + self.BATCH_SIZE - 1
                        ) // self.BATCH_SIZE
                        start_enrichment_time = time.time()
                        # Initialize seen labels to avoid duplicates label creation
                        self.seen_labels = set()
                        self.errors = []
                        enrichments_count = 0
                        enrichment_threshold = self.enrichment_threshold_per_import
                        exit_batch_loop = False
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
                            batch_bundle_objects = []
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
                                        batch_bundle_objects,
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
                            time_from_enrichment_start = (
                                batch_end_time - start_enrichment_time
                            )

                            self.helper.log_info(
                                f"Processing batch {batch_index}/{total_batch_count} "
                                f"took {batch_time_taken:.4f} seconds"
                            )
                            if batch_index % 5 == 0 and enrichments_count > 0:
                                remaining_time = (
                                    (time_from_enrichment_start / batch_index)
                                    * (total_batch_count - batch_index)
                                    if enrichment_threshold > ip_count
                                    else (
                                        time_from_enrichment_start / enrichments_count
                                    )
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
                            if batch_bundle_objects:
                                try:
                                    bundle_start_time = time.time()
                                    self.helper.log_info(
                                        f"Start sending {len(batch_bundle_objects)} bundles to OpenCTI"
                                    )
                                    # bundle = stix2.Bundle(batch_bundle_objects, allow_custom=True)
                                    # bundle_json = bundle.serialize()
                                    bundle_json = self.helper.stix2_create_bundle(
                                        batch_bundle_objects
                                    )
                                    # Sending the bundle
                                    self.helper.send_stix2_bundle(
                                        bundle_json,
                                        update=self.update_existing_data,
                                        work_id=work_id,
                                    )
                                    bundle_end_time = time.time()
                                    bundle_time_taken = (
                                        bundle_end_time - bundle_start_time
                                    )
                                    self.helper.log_info(
                                        f"Sending bundles took {bundle_time_taken:.4f} seconds"
                                    )
                                except Exception as e:
                                    message = f"Error sending bundles: {str(e)}"
                                    self.helper.log_error(message)
                                    self.errors.append(message)

                        # Store the current run_start_timestamp as a last run
                        self.helper.set_state({"last_run": run_start_timestamp})
                        message = (
                            f"CrowdSec import connector successfully run. "
                            f"Total number of enrichments: {enrichments_count}. "
                            f"last_run stored as {str(run_start_timestamp)}."
                        )
                        self.helper.log_info(message)
                        for error in self.errors:
                            self.helper.api.work.to_processed(
                                work_id, error, in_error=True
                            )
                        self.helper.api.work.to_processed(work_id, message)
                        time_from_run_start = int(time.time()) - run_start_timestamp
                        next_run_in = self.get_interval() - time_from_run_start
                        if next_run_in > 0:
                            self.helper.log_info(
                                f"Next run in: {self.convert_seconds(next_run_in)}"
                            )
                    except Exception as e:
                        message = f"Error running CrowdSec import connector: {str(e)}"
                        self.helper.api.work.to_processed(
                            work_id, message, in_error=True
                        )
                        self.helper.log_error(str(e))

                    time.sleep(60)
                else:
                    # wait for next run
                    next_run = last_run + timedelta(seconds=self.get_interval())
                    self.helper.log_info(
                        f"Connector will not run, next run at: {next_run}+00:00"
                    )
                    time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("CrowdSec import connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)
