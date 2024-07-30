# -*- coding: utf-8 -*-
"""OpenCTI Malpedia Knowledge importer module."""
import sys
import time
from datetime import datetime
from typing import Any

import stix2
from malpedia_services import (
    MalpediaClient,
    MalpediaConfig,
    MalpediaConverter,
    MalpediaModels,
    MalpediaUtils,
)
from malpedia_services.constants import (
    LAST_RUN,
    LAST_VERSION,
    TLP_MAPPING,
    URLS_MAPPING,
)
from pycti import OpenCTIConnectorHelper
from pydantic import ValidationError


class MalpediaConnector:
    """Malpedia Connector importer."""

    def __init__(self) -> None:
        """Initialize the Malpedia Connector with necessary configuration"""

        self.config = MalpediaConfig()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.api_client = MalpediaClient(self.helper, self.config.auth_key)
        self.helper.metric.state("idle")

        """
        If we run without API key we can assume all data is TLP:WHITE 
        else we default to TLP:AMBER to be safe.
        """
        self.default_marking = (
            stix2.TLP_WHITE if self.api_client.unauthenticated else stix2.TLP_AMBER
        )

        self.models = MalpediaModels()
        self.utils = MalpediaUtils(self.helper, self.config.interval_sec)
        self.converter = MalpediaConverter(self.helper, self.default_marking)
        self.update_existing_data = self.config.update_existing_data

        self.work_id = None
        self.stix_objects = []
        self.stix_relationships = []

    def start(self):
        """Malpedia Connector execution"""
        self.helper.connector_logger.info("[CONNECTOR] Starting Malpedia connector...")

        while True:
            try:
                current_malpedia_version = self.api_client.current_version()
                self.helper.connector_logger.info(
                    "[CONNECTOR] Current Malpedia version",
                    {"version": current_malpedia_version},
                )
                timestamp = self.utils.current_unix_timestamp()
                current_state = self.utils.load_state()
                self.helper.connector_logger.info(
                    "[CONNECTOR] Loaded state",
                    {
                        "current_state": (
                            "First run" if current_state == {} else str(current_state)
                        )
                    },
                )

                last_run = self.utils.get_state_value(current_state, LAST_RUN)
                last_version = self.utils.get_state_value(current_state, LAST_VERSION)

                """
                Only run the connector if:
                1. It is scheduled to run per interval
                2. The global Malpedia version from the API is newer than our last stored version.
                """
                if self.utils.is_scheduled(
                    last_run, timestamp
                ) and self.utils.check_version(last_version, current_malpedia_version):
                    self.helper.connector_logger.info("[CONNECTOR] Running importers")
                    self.helper.metric.inc("run_count")
                    self.helper.metric.state("running")
                    self.work_id = self.utils.initiate_work_id(timestamp)

                    self.helper.connector_logger.info(
                        "[CONNECTOR] Running Malpedia process...",
                        {
                            "state": (
                                "First run"
                                if current_state == {}
                                else str(current_state)
                            )
                        },
                    )
                    self._run_malpedia_process()

                    new_state = current_state.copy()
                    new_state[LAST_RUN] = self.utils.current_unix_timestamp()
                    new_state[LAST_VERSION] = current_malpedia_version

                    msg = "[CONNECTOR] Connector successfully run, storing the new state..."
                    self.helper.connector_logger.info(msg, {"new_state": new_state})
                    self.helper.api.work.to_processed(self.work_id, msg)

                    self.helper.set_state(new_state)
                    new_interval_in_hours = round(self.config.interval_sec / 60 / 60, 2)
                    self.helper.connector_logger.info(
                        "[CONNECTOR] State stored, next run in hours.",
                        {"next_run": new_interval_in_hours},
                    )

                else:
                    new_interval = self.config.interval_sec - (timestamp - last_run)
                    if new_interval < 0:
                        next_run = "waiting for a new version"
                    else:
                        next_run = round(new_interval / 60 / 60, 2)

                    self.helper.connector_logger.info(
                        "[CONNECTOR] The connector will not run, next run in hours.",
                        {
                            "config_interval_sec": self.config.interval_sec,
                            "next_run": str(next_run),
                        },
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.connector_logger.info("[CONNECTOR] Connector stop...")
                self.helper.metric.state("stopped")
                sys.exit(0)

            except Exception as e:
                self.helper.connector_logger.error(
                    "[CONNECTOR] Error while processing data:", {"error": str(e)}
                )
                self.helper.metric.state("stopped")
                sys.exit(0)

            if self.helper.connect_run_and_terminate:
                self.helper.connector_logger.info("[CONNECTOR] Connector stop...")
                self.helper.metric.state("stopped")
                self.helper.force_ping()
                sys.exit(0)

            self.helper.metric.state("idle")
            time.sleep(60)

    def _run_malpedia_process(self):

        # Generate Malpedia Identity (Organization)
        malpedia_identity = self.converter.generate_malpedia_stix_identity()
        self.stix_objects.append(malpedia_identity)

        # Start process families
        self._process_families()

        self.helper.connector_logger.info(
            "[CONNECTOR] The number of Stix bundle(s) to be generated.",
            {
                "stix_entity_bundles_generated": len(self.stix_objects),
                "stix_relationship_bundles_generated": len(self.stix_relationships),
            },
        )
        # Create stix2 bundle and send
        final_stix_objects = self.stix_objects + self.stix_relationships
        stix2_bundle = self.helper.stix2_create_bundle(final_stix_objects)
        self.helper.send_stix2_bundle(
            stix2_bundle,
            work_id=self.work_id,
            update=self.config.update_existing_data,
        )

        self.helper.metric.inc("record_send", len(final_stix_objects))
        state_timestamp = int(datetime.utcnow().timestamp())
        self.helper.connector_logger.info(
            "[CONNECTOR] Malpedia importer bundle completed",
            {
                "state_last_run": state_timestamp,
                "total_bundle_generated": len(final_stix_objects),
            },
        )

    def _process_families(self) -> None:
        # Download the newest knowledge as json from the API
        families_json = self.api_client.query("get/families")

        if families_json is None:
            raise ValueError(
                "An error occurred during the API request to get all families."
            )

        for family_name in families_json:
            try:
                # Sometimes the updated field is empty and we fix it with None
                # to allow downstream code to choose sensible defaults.
                if families_json[family_name]["updated"] == "":
                    families_json[family_name]["updated"] = None

                family_model = self.models.create_family_model()
                data_family = family_model.parse_obj(families_json[family_name])
                data_family.malpedia_name = family_name

            except ValidationError as e:
                self.helper.connector_logger.error(
                    "[ERROR-FAMILY] Error marshaling family data",
                    {
                        "family_name": family_name,
                        "error": str(e),
                        "families_json": families_json,
                    },
                )
                self.helper.metric.inc("error_count")
                continue

            ######################################################
            # Generate Malware by family
            ######################################################
            self.helper.connector_logger.info(
                "[MALWARE] Generate Malware...",
                {"family_name": family_name},
            )

            malware_id = self._generate_malware_by_family(data_family)

            ######################################################
            # Generate Yara Rules
            ######################################################
            if not self.config.import_yara:
                self.helper.connector_logger.info(
                    "[CONFIGURATION] Due to the configuration, if import yara is false, "
                    "we skip creating for the yara indicator.",
                    {"family_name": family_name},
                )
            else:
                yara_rules = self.api_client.query("get/yara/" + family_name)

                if yara_rules is None:
                    self.helper.connector_logger.error(
                        "[API] Some error occurred during yara rule creation",
                        {"family_name": family_name},
                    )
                    self.helper.metric.inc("error_count")
                elif not yara_rules:
                    self.helper.connector_logger.info(
                        "[YARA-RULES] No Yara rules found for this family...",
                        {"family_name": family_name},
                    )
                else:
                    self.helper.connector_logger.info(
                        "[YARA-RULES] Generate yara rules for...",
                        {"family_name": family_name},
                    )
                    self._generate_yara_rule_associated_with_malware(
                        yara_rules, malware_id
                    )

            ######################################################
            # Generate Samples if user authentified
            ######################################################
            if not self.api_client.unauthenticated:
                if (
                    not self.config.create_indicators
                    and not self.config.create_observables
                ):
                    self.helper.connector_logger.info(
                        "[CONFIGURATION] Due to the configuration, if create indicator and observable are false, "
                        "we skip creating them for the samples.",
                        {"family_name": family_name},
                    )
                else:
                    samples = self.api_client.query("list/samples/" + family_name)

                    if samples is None:
                        self.helper.connector_logger.error(
                            "[API] Some error occurred during indicator/observable sample creation",
                            {"family_name": family_name},
                        )
                        self.helper.metric.inc("error_count")
                    elif not samples:
                        self.helper.connector_logger.info(
                            "[SAMPLES] No Sample found for this family...",
                            {"family_name": family_name},
                        )
                    else:
                        self.helper.connector_logger.info(
                            "[SAMPLES] Generate indicators/observables samples...",
                            {"family_name": family_name},
                        )
                        self._generate_samples_associated_with_malware(
                            samples, malware_id
                        )
            else:
                self.helper.connector_logger.info(
                    "[AUTHENTICATE] You are an unauthenticated user, you do not have access to retrieve information "
                    "about the samples, the creation of the samples will be skipped.",
                    {"family_name": family_name},
                )

            ######################################################
            # Generate Intrusion Sets
            ######################################################
            if not self.config.import_intrusion_sets:
                self.helper.connector_logger.info(
                    "[CONFIGURATION] Due to the configuration, if import intrusion set is false, "
                    "we skip creating them for the intrusion set.",
                    {"family_name": family_name},
                )
            elif hasattr(data_family, "attribution") and not data_family.attribution:
                self.helper.connector_logger.info(
                    "[INTRUSION-SET] No intrusion set found for this family...",
                    {"family_name": data_family.malpedia_name},
                )
            else:
                self.helper.connector_logger.info(
                    "[INTRUSION-SETS] Generate intrusion sets for...",
                    {"family_name": family_name},
                )
                self._generate_intrusion_set_associated_with_malware(
                    data_family, malware_id
                )

    def _generate_malware_by_family(self, data_family) -> str:
        try:
            if data_family.description == "" or data_family.description is None:
                data_family.description = (
                    "Malpedia entry for " + data_family.malpedia_name
                )

            family_external_references = data_family.urls
            family_main_url = data_family.malpedia_url
            family_external_references.insert(0, family_main_url)

            external_references = self.converter.generate_stix_external_reference(
                family_external_references
            )
            prepared_malware = self.models.create_malware_model()(
                name=data_family.main_name,
                description=data_family.description,
                aliases=data_family.malpedia_aliases,
                external_references=external_references,
                object_marking_refs=[self.default_marking["id"]],
            )

            # Generate stix Malware
            stix_malware = self.converter.generate_stix_malware(prepared_malware)
            self.stix_objects.append(stix_malware)

        except Exception as e:
            self.helper.metric.inc("error_count")
            return self.helper.connector_logger.error(
                "[ERROR-MALWARE] Error creating malware entity",
                {"malware_name": data_family.main_name, "error": str(e)},
            )
        return stix_malware.id

    def _generate_yara_rule_associated_with_malware(
        self, yara_rules: Any, malware_id: str
    ) -> None:
        for tlp_level in yara_rules:
            for yara_rule in yara_rules[tlp_level]:
                try:
                    self.helper.connector_logger.info(
                        "[YARA-RULE] Generate yara_rule...",
                        {"tlp_level": tlp_level, "yara_rule_name": yara_rule},
                    )

                    mapped_marking = TLP_MAPPING[tlp_level]
                    if mapped_marking == "":
                        continue

                    prepared_yara_rule = self.models.create_yara_rule_model()(
                        name=yara_rule,
                        description="Yara rule from Malpedia library",
                        pattern=yara_rules[tlp_level][yara_rule],
                        pattern_type="yara",
                        object_marking_refs=[mapped_marking],
                    )

                    # Generate stix Indicator
                    stix_indicator = self.converter.generate_stix_indicator(
                        prepared_yara_rule
                    )
                    self.stix_objects.append(stix_indicator)

                    # Generate Relationship : Indicator -> "indicates" -> Malware
                    indicator_to_malware = self.converter.generate_stix_relationship(
                        stix_indicator.id, "indicates", malware_id
                    )
                    self.stix_relationships.append(indicator_to_malware)

                except Exception as e:
                    self.helper.metric.inc("error_count")
                    self.helper.connector_logger.error(
                        "[ERROR-YARA-RULES] Error creating Yara indicator or relationship",
                        {"error": str(e)},
                    )
                    continue

    def _generate_samples_associated_with_malware(
        self, samples: list, malware_id: str
    ) -> None:

        for sample in samples:
            if "sha256" in sample and sample["sha256"] is not None:

                # Sanity check the hash value
                if sample["sha256"] == "" or len(sample["sha256"]) != 64:
                    continue

                sample_hash = sample["sha256"].lower()
                pattern_hash = "[file:hashes.'SHA-256' = '" + sample_hash + "']"

                ######################################################
                # Generate Sample Observable
                ######################################################
                stix_observable_id = None
                if self.config.create_observables:
                    self.helper.connector_logger.info(
                        "[SAMPLE] Generate observable sample...",
                        {"sample_sha256": sample["sha256"]},
                    )
                    try:
                        prepared_stix_observable_file = (
                            self.models.create_observable_sample_model()(
                                name=sample_hash,
                                hashes={
                                    "SHA-256": sample_hash,
                                },
                                object_marking_refs=[self.default_marking["id"]],
                            )
                        )

                        # Generate stix observable
                        stix_observable = self.converter.generate_stix_observable_file(
                            prepared_stix_observable_file
                        )
                        stix_observable_id = stix_observable.id
                        self.stix_objects.append(stix_observable)

                        # Generate Relationship : Observable -> "related-to" -> Malware
                        observable_to_malware = (
                            self.converter.generate_stix_relationship(
                                stix_observable.id, "related-to", malware_id
                            )
                        )
                        self.stix_relationships.append(observable_to_malware)

                    except Exception as e:
                        self.helper.metric.inc("error_count")
                        self.helper.connector_logger.error(
                            "[ERROR-SAMPLE] Error creating observable sample",
                            {"sample_hash": sample_hash, "error": str(e)},
                        )
                        continue
                else:
                    self.helper.connector_logger.info(
                        "[CONFIGURATION] Due to the configuration, if create observable is false, "
                        "we skip creating them for the sample.",
                        {"sample_sha256": sample["sha256"]},
                    )

                ######################################################
                # Generate Sample Indicator
                ######################################################
                stix_indicator_id = None
                if self.config.create_indicators:
                    self.helper.connector_logger.info(
                        "[SAMPLE] Generate indicator sample...",
                        {"sample_sha256": sample["sha256"]},
                    )
                    try:
                        prepared_indicator = (
                            self.models.create_indicator_sample_model()(
                                name=sample_hash,
                                description="Sample hash pattern from Malpedia",
                                pattern=pattern_hash,
                                pattern_type="stix",
                                object_marking_refs=[self.default_marking["id"]],
                            )
                        )

                        # Generate stix indicator
                        stix_indicator = self.converter.generate_stix_indicator(
                            prepared_indicator
                        )
                        stix_indicator_id = stix_indicator.id
                        self.stix_objects.append(stix_indicator)

                        # Generate Relationship : Indicator -> "indicates" -> Malware
                        indicator_to_malware = (
                            self.converter.generate_stix_relationship(
                                stix_indicator.id, "indicates", malware_id
                            )
                        )
                        self.stix_relationships.append(indicator_to_malware)

                    except Exception as e:
                        self.helper.metric.inc("error_count")
                        self.helper.connector_logger.error(
                            "[ERROR-SAMPLE] Error creating indicator sample",
                            {"sample_hash": sample_hash, "error": str(e)},
                        )
                        continue
                else:
                    self.helper.connector_logger.info(
                        "[CONFIGURATION] Due to the configuration, if create indicator is false, "
                        "we skip creating them for the sample.",
                        {"sample_sha256": sample["sha256"]},
                    )

                ######################################################
                # Generate Relationship
                ######################################################
                if self.config.create_indicators and self.config.create_observables:

                    # Generate Relationship : Indicator -> "based-on" -> Observable
                    indicator_to_observable = self.converter.generate_stix_relationship(
                        stix_indicator_id, "based-on", stix_observable_id
                    )
                    self.stix_relationships.append(indicator_to_observable)

            else:
                self.helper.connector_logger.error(
                    "[ERROR-SAMPLE] Error sample data.",
                    {"sample": sample},
                )
                self.helper.metric.inc("error_count")
                continue

    def _generate_intrusion_set_associated_with_malware(
        self, data_family, malware_id: str
    ) -> None:

        for actor in data_family.attribution:
            self.helper.connector_logger.info(
                "[INTRUSION-SET] Generate intrusion set...",
                {"family_name": data_family.malpedia_name, "actor": actor},
            )

            actor_json = self.api_client.query(
                "get/actor/" + actor.lower().replace(" ", "_")
            )

            if actor_json is None:
                self.helper.connector_logger.info(
                    "[API] Some error occurred during actor creation", {"actor": actor}
                )
                continue

            if "detail" in actor_json and actor_json["detail"] == "Not found":
                continue

            if actor_json["value"] == "" or actor_json["value"] is None:
                continue

            if self.config.import_intrusion_sets:

                try:
                    if (
                        "description" in actor_json
                        and actor_json["description"] is not None
                        and actor_json["description"] != ""
                    ):
                        description = actor_json["description"]
                    else:
                        description = (
                            f"Malpedia library entry for {actor_json['value']}"
                        )

                    if (
                        "cfr-type-of-incident" in actor_json["meta"]
                        and len(actor_json["meta"]["cfr-type-of-incident"]) > 0
                    ):

                        actor_type_of_incident = actor_json["meta"][
                            "cfr-type-of-incident"
                        ]
                        if isinstance(actor_type_of_incident, str):
                            actor_type_of_incident = [actor_type_of_incident]

                        primary_motivation = actor_type_of_incident[0]
                        secondary_motivations = actor_type_of_incident[1:]
                    else:
                        primary_motivation = ""
                        secondary_motivations = []

                    # List of external references
                    actor_external_references = actor_json["meta"]["refs"]
                    actor_main_url = URLS_MAPPING["base_url_actor"] + actor_json[
                        "value"
                    ].lower().replace(" ", "_")
                    actor_external_references.insert(0, actor_main_url)
                    stix_external_references = (
                        self.converter.generate_stix_external_reference(
                            actor_external_references
                        )
                    )

                    aliases = (
                        actor_json["meta"]["synonyms"]
                        if "synonyms" in actor_json["meta"]
                        else []
                    )

                    prepared_intrusion_set = self.models.create_intrusion_set_model()(
                        name=actor_json["value"],
                        description=description,
                        aliases=aliases,
                        primary_motivation=primary_motivation,
                        secondary_motivations=secondary_motivations,
                        external_references=stix_external_references,
                        object_marking_refs=[self.default_marking["id"]],
                    )

                    # Generate stix Intrusion Set
                    stix_intrusion_set = self.converter.generate_stix_intrusion_set(
                        prepared_intrusion_set
                    )
                    self.stix_objects.append(stix_intrusion_set)

                    # Generate Relationship : Intrusion_set -> "uses" -> Malware
                    intrusion_set_to_malware = (
                        self.converter.generate_stix_relationship(
                            stix_intrusion_set.id, "uses", malware_id
                        )
                    )
                    self.stix_relationships.append(intrusion_set_to_malware)

                    # Get Country name
                    if "country" in actor_json["meta"]:
                        country_name = self.utils.get_country_name(
                            actor_json["meta"]["country"]
                        )
                        if country_name is not None:
                            stix_location_country = (
                                self.converter.generate_stix_location(country_name)
                            )
                            self.stix_objects.append(stix_location_country)

                            # Generate Relationship : Intrusion set -> "Originates From" -> Location
                            intrusion_set_to_country = (
                                self.converter.generate_stix_relationship(
                                    stix_intrusion_set.id,
                                    "originates-from",
                                    stix_location_country.id,
                                )
                            )
                            self.stix_relationships.append(intrusion_set_to_country)

                    # All victims
                    if "cfr-suspected-victims" in actor_json["meta"]:
                        all_victims = actor_json["meta"]["cfr-suspected-victims"]
                        list_of_countries_victims = self.utils.filter_countries_victims(
                            all_victims
                        )

                        # Generate victims Locations and relationships
                        for victim in list_of_countries_victims:
                            stix_location = self.converter.generate_stix_location(
                                victim
                            )
                            self.stix_objects.append(stix_location)

                            # Generate Relationship : Intrusion set -> "target" -> Location
                            intrusion_set_to_victim = (
                                self.converter.generate_stix_relationship(
                                    stix_intrusion_set.id, "targets", stix_location.id
                                )
                            )
                            self.stix_relationships.append(intrusion_set_to_victim)

                except Exception as e:
                    self.helper.metric.inc("error_count")
                    self.helper.connector_logger.error(
                        "[ERROR-INTRUSION-SET] Error creating intrusion set",
                        {"actor": actor, "error": str(e)},
                    )
                    continue
