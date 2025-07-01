import re
import sys
from datetime import datetime, timedelta, timezone

import pycti
import requests
import stix2
from config import ConnectorSettings
from converter_to_stix import ConverterToStix
from pycti import OpenCTIConnectorHelper
from utils import (
    domain_extractor,
    fetch_country_domain,
    ip_fetcher,
    is_domain,
    is_ipv4,
    is_ipv6,
    ransom_note_generator,
    safe_datetime,
    threat_description_generator,
)


class RansomwareAPIConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.
    """

    def __init__(
        self, helper: OpenCTIConnectorHelper, config: ConnectorSettings
    ) -> None:
        self.helper = helper
        self.config = config
        self.work_id = None
        self.marking = stix2.TLP_WHITE
        self.last_run = None
        self.last_run_datetime_with_ingested_data = None
        self.converter_to_stix = ConverterToStix(self.helper, self.config)
        self.author = self.converter_to_stix.author

        interval = self.config.ransomware.interval
        if interval:
            self.interval = interval if re.match(r"^\d+[dhms]$", interval) else None
        else:
            self.interval = None

    def location_fetcher(self, country: str):
        """
        Fetches the location object from OpenCTI
        :param country: country code format ISO 3166-1 alpha-2
        :return: country stix id if retrieve else None
        """
        country_id = pycti.Location.generate_id(country, "Country")
        try:
            country_out = self.helper.api.stix_domain_object.read(id=country_id)
            if country_out and country_out.get("standard_id").startswith("location--"):
                return country_out.get("standard_id")
            return None
        except Exception as e:
            self.helper.connector_logger.error(
                "Error fetching location", {"country": country, "error": e}
            )
            return None

    def sector_fetcher(self, sector: str):
        """
        Fetch the sector object related to param by searching with conditions:
            - entity_type is "sector"
            - name is egual to sector string OR x_opencti_aliases is egual to sector string
        :param sector: sector in string
        :return: sector id or None
        """
        if sector == "":
            return None

        sector_out = None
        rubbish = [" and ", " or ", " ", ";"]
        for item in rubbish:
            sector = " ".join(sector.split(item))

        try:
            sector_out = self.helper.api.identity.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {
                            "key": "entity_type",
                            "values": ["Sector"],
                            "operator": "eq",
                        },
                    ],
                    "filterGroups": [
                        {
                            "mode": "or",
                            "filters": [
                                {
                                    "key": "name",
                                    "values": sector,
                                    "operator": "eq",
                                },
                                {
                                    "key": "x_opencti_aliases",
                                    "values": sector,
                                    "operator": "eq",
                                },
                            ],
                            "filterGroups": [],
                        }
                    ],
                },
            )
        except Exception as e:
            self.helper.connector_logger.error(
                "Error fetching sector", {"sector": sector, "error": e}
            )
            return None

        if sector_out and sector_out.get("standard_id").startswith("identity--"):
            return sector_out.get("standard_id")

        return None

    # pylint:disable=too-many-branches,too-many-statements
    def stix_object_generator(self, item, group_data):
        """
        Generates STIX objects from the ransomware.live API data
        :param item: dict of data from api call
        :param group_data: results from ransomware api /group in json
        :return:
        """
        bundle_objects = []

        # Creating Victim object
        post_title = item.get("victim")
        victim_name, identity_class = (
            (post_title, "organization")
            if len(post_title) > 2
            else ((post_title + ":<)"), "individual")
        )
        victim = self.converter_to_stix.create_identity(
            victim_name=victim_name, identity_class=identity_class
        )
        bundle_objects.append(victim)

        # RansomNote External Reference
        ransom_note_external_reference = ransom_note_generator(item.get("group"))

        # Attack Date sets the start_time of the relationship between a threat actor or intrusion set and a victim.
        # This value (attack_date_iso) will also be used in the report. (Report : Attack Date -> Published)
        attack_date = item.get("attackdate")
        attack_date_iso = safe_datetime(attack_date)

        # Discovered sets the created date of the relationship between a Threat Actor or Intrusion Set and a Victim.
        # This value (discovered_iso) will also be used in the report. (Report : Discovered -> Created)
        discovered = item.get("discovered")
        discovered_iso = safe_datetime(discovered)

        # Creating Threat Actor object
        threat_actor = None
        if self.config.ransomware.create_threat_actor:
            threat_actor_name = item.get("group")
            threat_description = threat_description_generator(
                threat_actor_name, group_data
            )
            threat_actor = self.converter_to_stix.create_threat_actor(
                threat_actor_name=threat_actor_name,
                threat_description=threat_description,
                ransom_note_external_reference=ransom_note_external_reference,
            )
            bundle_objects.append(threat_actor)

            target_relation = self.converter_to_stix.create_relationship(
                source_ref=threat_actor.get("id"),
                target_ref=victim.get("id"),
                relationship_type="targets",
                start_time=attack_date_iso,
                created=discovered_iso,
            )
            bundle_objects.append(target_relation)

        # Creating Intrusion Set object
        try:
            if item.get("group") in ["lockbit3", "lockbit2"]:
                intrusion_description = threat_description_generator(
                    item.get("lockbit3"), group_data
                )
                intrusion_set = self.converter_to_stix.create_intrusionset(
                    name="lockbit",
                    intrusion_description=intrusion_description,
                    ransom_note_external_reference=ransom_note_external_reference,
                )

            else:
                intrusion_set_name = item.get("group")
                intrusion_description = threat_description_generator(
                    item.get("group"), group_data
                )
                # Warning: IntrusionSet can have a name like "J".
                # No error from Stix2 but in OCTI name must be at least 2 characters
                intrusion_set = self.converter_to_stix.create_intrusionset(
                    name=intrusion_set_name,
                    intrusion_description=intrusion_description,
                    ransom_note_external_reference=ransom_note_external_reference,
                )

            bundle_objects.append(intrusion_set)

            relation_victim_intrusion = self.converter_to_stix.create_relationship(
                source_ref=intrusion_set.get("id"),
                target_ref=victim.get("id"),
                relationship_type="targets",
                start_time=attack_date_iso,
                created=discovered_iso,
            )
            bundle_objects.append(relation_victim_intrusion)

            if self.config.ransomware.create_threat_actor:
                relation_intrusion_threat_actor = (
                    self.converter_to_stix.create_relationship(
                        intrusion_set.get("id"), threat_actor.get("id"), "attributed-to"
                    )
                )
                bundle_objects.append(relation_intrusion_threat_actor)
        except stix2.exceptions.STIXError as e:
            self.helper.connector_logger.error(
                "Error while creating intrusion set object", {"error": e}
            )

        # Creating External References Object if they have external references
        external_references = [ransom_note_external_reference]

        for field in ["screenshot", "website", "post_url"]:

            if item.get(field):
                external_reference = self.converter_to_stix.create_external_reference(
                    url=item[field],
                    description=f"This is the {field} for the ransomware campaign.",
                )
                external_references.append(external_reference)

        # Creating Report object
        object_refs = [
            victim.get("id"),
            intrusion_set.get("id"),
            relation_victim_intrusion.get("id"),
        ]
        if self.config.ransomware.create_threat_actor:
            object_refs.append(target_relation.get("id"))
            object_refs.append(relation_intrusion_threat_actor.get("id"))

        report_name = item.get("group") + " has published a new victim: " + post_title
        report = self.converter_to_stix.create_report(
            name=report_name,
            attack_date_iso=attack_date_iso,
            description=item.get("description"),
            object_refs=object_refs,
            discovered_iso=discovered_iso,
            external_references=external_references,
        )

        # Creating Sector object
        try:
            if item.get("activity"):
                sector_id = self.sector_fetcher(item.get("activity"))
                if sector_id:
                    report.get("object_refs").append(sector_id)

                    relation_sector_victim = self.converter_to_stix.create_relationship(
                        source_ref=victim.get("id"),
                        target_ref=sector_id,
                        relationship_type="part-of",
                    )
                    bundle_objects.append(relation_sector_victim)

                    if self.config.ransomware.create_threat_actor:
                        relation_sector_threat_actor = (
                            self.converter_to_stix.create_relationship(
                                threat_actor.get("id"),
                                sector_id,
                                "targets",
                                attack_date_iso,
                                discovered_iso,
                            )
                        )
                        bundle_objects.append(relation_sector_threat_actor)
                        report.get("object_refs").append(
                            relation_sector_threat_actor.get("id")
                        )

                    report.get("object_refs").append(relation_sector_victim.get("id"))

                    relation_intrusion_sector = (
                        self.converter_to_stix.create_relationship(
                            intrusion_set.get("id"),
                            sector_id,
                            "targets",
                            attack_date_iso,
                            discovered_iso,
                        )
                    )
                    bundle_objects.append(relation_intrusion_sector)
                    report.get("object_refs").append(
                        relation_intrusion_sector.get("id")
                    )
        except Exception as e:
            self.helper.connector_logger.error(
                "Error while creating Sector object", {"error": e}
            )

        domain_name = None

        # Several domain has unicode characters
        domain_obj = item.get("domain").replace("\u200b", "")

        # Retrieve domain name where "victim" is a domain name
        if is_domain(item.get("victim")):
            domain_name = domain_extractor(item.get("victim"))
        # Retrieve domain name where "victim" is not a domain name
        elif (
            domain_obj
            and domain_obj != ""
            and not is_domain(item.get("victim"))
            and domain_extractor(domain_obj)
        ):
            domain_name = domain_extractor(domain_obj)

        # Create domain object
        if domain_name:
            description = fetch_country_domain(domain_name)

            domain = self.converter_to_stix.create_domain(
                domain_name=domain_name, description=description
            )
            bundle_objects.append(domain)

            relation_victim_domain = self.converter_to_stix.create_relationship(
                domain.get("id"), victim.get("id"), "belongs-to"
            )
            bundle_objects.append(relation_victim_domain)

            # Fetching IP address of the domain
            resolved_ip = ip_fetcher(domain_name)
            if is_ipv4(resolved_ip):
                ip_object = self.converter_to_stix.create_ipv4(resolved_ip)
            elif is_ipv6(resolved_ip):
                ip_object = self.converter_to_stix.create_ipv6(resolved_ip)
            else:
                ip_object = None

            if ip_object and ip_object.get("id"):
                relation_domain_ip = self.converter_to_stix.create_relationship(
                    source_ref=domain.get("id"),
                    target_ref=ip_object.get("id"),
                    relationship_type="resolves-to",
                )
                bundle_objects.append(ip_object)
                bundle_objects.append(relation_domain_ip)
                report.get("object_refs").append(ip_object.get("id"))
                report.get("object_refs").append(relation_domain_ip.get("id"))

            report.get("object_refs").append(domain.get("id"))
            report.get("object_refs").append(relation_victim_domain.get("id"))

        # Creating Location object
        if item.get("country") and len(item.get("country", "Four")) < 4:

            country_name = item.get("country")
            country_stix_id = self.location_fetcher(country_name)

            location = self.converter_to_stix.create_location(
                country_stix_id=country_stix_id, country_name=country_name
            )

            # If country not yet available, add it in the bundle_objects for creation
            if country_stix_id is None:
                bundle_objects.append(location)

            location_relation = self.converter_to_stix.create_relationship(
                source_ref=victim.get("id"),
                target_ref=location.get("id"),
                relationship_type="located-at",
            )
            bundle_objects.append(location_relation)

            relation_intrusion_location = self.converter_to_stix.create_relationship(
                source_ref=intrusion_set.get("id"),
                target_ref=location.get("id"),
                relationship_type="targets",
                start_time=attack_date_iso,
                created=discovered_iso,
            )
            bundle_objects.append(relation_intrusion_location)

            if self.config.ransomware.create_threat_actor:
                relation_threat_actor_location = (
                    self.converter_to_stix.create_relationship(
                        source_ref=threat_actor.get("id"),
                        target_ref=location.get("id"),
                        relationship_type="targets",
                        start_time=attack_date_iso,
                        created=discovered_iso,
                    )
                )
                bundle_objects.append(relation_threat_actor_location)
                report.get("object_refs").append(
                    relation_threat_actor_location.get("id")
                )

            report.get("object_refs").append(location.get("id"))
            report.get("object_refs").append(relation_intrusion_location.get("id"))
            report.get("object_refs").append(location_relation.get("id"))

            bundle_objects.append(report)

        self.helper.connector_logger.info(
            "Sending STIX objects to collect_intelligence.",
            {"len_bundle_objects": len(bundle_objects)},
        )
        return bundle_objects

    def collect_historic_intelligence(self):
        """
        Collects historic intelligence from ransomware.live
        :return:
        """
        base_url = "https://api.ransomware.live/v2/victims/"
        groups_url = "https://api.ransomware.live/v2/groups"
        headers = {"accept": "application/json", "User-Agent": "OpenCTI"}
        group_data = []

        # fetching group information
        try:
            response = requests.get(groups_url, headers=headers, timeout=(20000, 20000))
            response.raise_for_status()
            group_data = response.json()
        except requests.exceptions.HTTPError as err:
            self.helper.connector_logger.error(
                "Http error during collect of historic intelligence.",
                {"error": err, "url": groups_url},
            )
        except Exception as e:
            self.helper.connector_logger.error(
                "Error while collecting historic intelligence", {"error": e}
            )

        # Checking if the historic year is less than 2020 as there is no data past 2020
        year = (
            self.config.ransomware.history_start_year
            if self.config.ransomware.history_start_year >= 2020
            else 2020
        )

        current_year = datetime.now().year
        bundle = []
        nb_stix_objects = 0

        for year in range(year, current_year + 1):  # Looping through the years
            year_url = base_url + str(year)
            for month in range(1, 13):  # Looping through the months
                bundles = []
                url = year_url + "/" + str(month)
                response = requests.get(url, headers=headers, timeout=(20000, 20000))
                response.raise_for_status()
                response_json = response.json()

                try:
                    for item in response_json:

                        bundle_list = self.stix_object_generator(item, group_data)

                        if bundle_list:
                            # Add Author object
                            bundle_list = [self.converter_to_stix.author] + bundle_list

                            nb_stix_objects += len(bundle_list)

                            # Deduplicate the objects
                            bundle_list = self.helper.stix2_deduplicate_objects(
                                bundle_list
                            )

                            bundles.append(
                                stix2.Bundle(
                                    objects=bundle_list, allow_custom=True
                                ).serialize()
                            )
                        else:
                            self.helper.connector_logger.info("No new data to process")

                    if bundles:
                        # Initiate new work
                        friendly_name = f"RansomwareLive - {year}/{month}"
                        self.work_id = self.helper.api.work.initiate_work(
                            self.helper.connect_id, friendly_name
                        )

                        for bundle in bundles:
                            self.helper.send_stix2_bundle(
                                bundle=bundle,
                                work_id=self.work_id,
                                cleanup_inconsistent_bundle=True,
                            )

                        self.helper.connector_logger.info(
                            "Sending STIX objects to OpenCTI...",
                            {"len_bundle_list": len(bundle_list)},
                        )

                except requests.exceptions.HTTPError as err:
                    self.helper.connector_logger.error(
                        "Http error during collect of historic intelligence",
                        {"error": err, "url": url},
                    )
                except Exception as e:
                    self.helper.connector_logger.error(
                        "Error while collecting historic intelligence", {"error": e}
                    )

        if nb_stix_objects:
            self.last_run_datetime_with_ingested_data = datetime.now(
                tz=timezone.utc
            ).isoformat(timespec="seconds")

    def collect_intelligence(self):
        """
        Collects intelligence from the last 24 on ransomware.live
        """

        url = "https://api.ransomware.live/v2/recentvictims"
        groups_url = "https://api.ransomware.live/v2/groups"
        headers = {"accept": "application/json"}
        group_data = []

        # fetching group information
        try:
            response = requests.get(groups_url, headers=headers, timeout=(20000, 20000))
            response.raise_for_status()
            group_data = response.json()
        except requests.exceptions.HTTPError as err:
            self.helper.connector_logger.error(
                "Http error during collect intelligence",
                {"error": err, "url": groups_url},
            )
        except Exception as e:
            self.helper.connector_logger.error(
                "Error while collecting intelligence", {"error": e}
            )

        # fetching recent requests
        try:
            response = requests.get(url, headers=headers, timeout=(20000, 20000))
            response.raise_for_status()

            if response.status_code == 200:
                response_json = response.json()
                nb_stix_objects = 0
                bundles = []
                last_run_datetime = (
                    self.last_run_datetime_with_ingested_data or self.last_run
                )

                # Previous last_run was in seconds
                if isinstance(last_run_datetime, int):
                    last_run_datetime = datetime.fromtimestamp(
                        last_run_datetime, tz=timezone.utc
                    )
                elif isinstance(last_run_datetime, str):
                    last_run_datetime = datetime.strptime(
                        last_run_datetime, "%Y-%m-%dT%H:%M:%S%z"
                    )

                for item in response_json:
                    created = datetime.strptime(
                        item.get("discovered"), "%Y-%m-%d %H:%M:%S.%f"
                    ).replace(tzinfo=timezone.utc)

                    if not last_run_datetime:
                        time_diff = 1
                    else:
                        time_diff = (
                            created - (last_run_datetime - timedelta(days=1))
                        ).seconds  # pushing all the data from the last 24 hours

                    if time_diff < 86400:

                        bundle_list = self.stix_object_generator(
                            item, group_data
                        )  # calling the stix_object_generator method to create stix objects

                        if bundle_list:
                            # Add Author object at first
                            bundle_list = [self.converter_to_stix.author] + bundle_list

                            # Deduplicate the objects
                            bundle_list = self.helper.stix2_deduplicate_objects(
                                bundle_list
                            )

                            nb_stix_objects += len(bundle_list)

                            self.helper.connector_logger.info(
                                "Sending STIX objects to OpenCTI...",
                                {"len_bundle_list": len(bundle_list)},
                            )

                            # Creating Bundle
                            bundles.append(
                                stix2.Bundle(
                                    objects=bundle_list, allow_custom=True
                                ).serialize()
                            )
                        else:
                            self.helper.connector_logger.info("No new data to process")

                if bundles:
                    # Initiate new work
                    self.work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, "RansomwareLive"
                    )

                    for bundle in bundles:
                        self.helper.send_stix2_bundle(
                            bundle=bundle,
                            work_id=self.work_id,
                            cleanup_inconsistent_bundle=True,
                        )

                    self.helper.connector_logger.info(
                        "Sending STIX objects to OpenCTI...",
                        {"total_number_stix_objects": nb_stix_objects},
                    )

                if nb_stix_objects:
                    self.last_run_datetime_with_ingested_data = datetime.now(
                        tz=timezone.utc
                    ).isoformat(timespec="seconds")

        except requests.exceptions.HTTPError as err:
            self.helper.connector_logger.error(
                "Http error during collect intelligence", {"error": err, "url": url}
            )
        except Exception as e:
            self.helper.connector_logger.error(
                "Error while collecting intelligence", {"error": e}
            )

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        # Main procedure
        self.helper.connector_logger.info(
            "Starting connector...", {"connector_name": self.helper.connect_name}
        )

        try:
            # Get the current timestamp and check
            now = datetime.now(tz=timezone.utc)
            current_state = self.helper.get_state()

            if current_state and "last_run" in current_state:
                if isinstance(current_state["last_run"], int):
                    self.last_run = datetime.fromtimestamp(current_state["last_run"])
                else:
                    self.last_run = datetime.fromisoformat(current_state["last_run"])

            self.last_run_datetime_with_ingested_data = (
                current_state.get("last_run_datetime_with_ingested_data")
                if current_state
                else None
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Starting connector...",
                {
                    "connector_name": self.helper.connect_name,
                    "connector_start_time": now.isoformat(timespec="seconds"),
                    "last_run": (
                        self.last_run if self.last_run else "Connector has never run"
                    ),
                    "last_run_datetime_with_ingested_data": (
                        self.last_run_datetime_with_ingested_data
                        if self.last_run_datetime_with_ingested_data
                        else "Connector has never ingested data"
                    ),
                },
            )

            self.helper.connector_logger.info(
                "Running connector...", {"connector_name": self.helper.connect_name}
            )

            # Perform the collect of intelligence
            try:
                if not self.last_run and self.config.ransomware.pull_history:
                    self.collect_historic_intelligence()
                else:
                    self.collect_intelligence()
            except Exception as e:
                self.helper.connector_logger.error(
                    "Error during bundle creation", {"error": e}
                )

            # Store the current timestamp as a last run
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run",
                {
                    "current_state": self.last_run,
                    "new_last_run_start_datetime": now.isoformat(timespec="seconds"),
                },
            )

            if self.last_run:
                current_state["last_run"] = now.isoformat(timespec="seconds")
            else:
                current_state = {"last_run": now.isoformat(timespec="seconds")}

            if self.last_run_datetime_with_ingested_data:
                current_state["last_run_datetime_with_ingested_data"] = (
                    self.last_run_datetime_with_ingested_data
                )

            self.helper.set_state(current_state)

            message = "Connector successfully run, storing last_run as" + now.isoformat(
                timespec="seconds"
            )
            if self.work_id:
                self.helper.api.work.to_processed(self.work_id, message)
            self.helper.connector_logger.info(message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "Connector stopped", {"connector_name": self.helper.connect_name}
            )
            sys.exit(0)
        except Exception as e:
            self.helper.connector_logger.error("Connector error on run", {"error": e})

    def run(self):
        if self.config.connector.duration_period:
            self.helper.schedule_iso(
                message_callback=self.process_message,
                duration_period=self.config.connector.duration_period,
            )
        else:
            self.helper.schedule_unit(
                message_callback=self.process_message,
                duration_period=self.interval,
                time_unit=self.helper.TimeUnit.MINUTES,
            )
