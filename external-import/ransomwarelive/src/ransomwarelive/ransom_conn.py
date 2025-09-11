import sys
from datetime import datetime, timedelta, timezone

import pycti
import stix2
from pycti import OpenCTIConnectorHelper

from .api_client import RansomwareAPIClient, RansomwareAPIError
from .config import ConnectorSettings
from .converter_to_stix import ConverterToStix
from .utils import domain_extractor, is_domain, safe_datetime

ONE_DAY_IN_SECONDS = 86400


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
        self.converter_to_stix = ConverterToStix()
        self.author = self.converter_to_stix.author
        self.api_client = RansomwareAPIClient()

    def location_fetcher(self, country: str):
        """
        Fetches the location object from OpenCTI

        Param:
            country: country code format ISO 3166-1 alpha-2
        Return:
            country stix id if retrieve else None
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

        Param:
            sector: sector in string
        Return:
            sector id or None
        """
        if sector == "":
            return None

        try:
            sector_out = None
            rubbish = [" and ", " or ", " ", ";"]
            for item in rubbish:
                sector = " ".join(sector.split(item))

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

            if sector_out and sector_out.get("standard_id").startswith("identity--"):
                return sector_out.get("standard_id")
        except Exception as e:
            self.helper.connector_logger.error(
                "Error fetching sector", {"sector": sector, "error": e}
            )
            return None

    def create_bundle_list(self, item, group_data):
        """
        Retrieve STIX objects from the ransomware.live API data and add it in bundle list

        Params:
            item: dict of data from api call
            group_data: results from ransomware api /group in json
        Return:
            bundle_objects: list of stix2 objects
        """
        bundle_objects = []

        # Creating Victim object
        victim_name = item.get("victim")
        victim = self.converter_to_stix.process_victim(victim_name=victim_name)
        bundle_objects.append(victim)

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
        if self.config.connector.create_threat_actor:
            threat_actor, target_relation = self.converter_to_stix.process_threat_actor(
                threat_actor_name=item.get("group"),
                group_data=group_data,
                victim=victim,
                attack_date_iso=attack_date_iso,
                discovered_iso=discovered_iso,
            )
            bundle_objects.append(threat_actor)
            bundle_objects.append(target_relation)

        # Creating Intrusion Set object
        intrusion_set_name = item.get("group")
        intrusion_set, relation_victim_intrusion = (
            self.converter_to_stix.process_intrusion_set(
                intrusion_set_name=intrusion_set_name,
                group_data=group_data,
                group_name_lockbit=item.get("lockbit3"),
                victim=victim,
                attack_date_iso=attack_date_iso,
                discovered_iso=discovered_iso,
            )
        )
        bundle_objects.append(intrusion_set)
        bundle_objects.append(relation_victim_intrusion)

        if self.config.connector.create_threat_actor:
            relation_intrusion_threat_actor = (
                self.converter_to_stix.create_relationship(
                    intrusion_set.get("id"), threat_actor.get("id"), "attributed-to"
                )
            )
            bundle_objects.append(relation_intrusion_threat_actor)

        # Creating External References Object if they have external references
        external_references = self.converter_to_stix.process_external_references(item)

        # Creating Report object
        object_refs = [
            victim.get("id"),
            intrusion_set.get("id"),
            relation_victim_intrusion.get("id"),
        ]
        if self.config.connector.create_threat_actor:
            object_refs.append(target_relation.get("id"))
            object_refs.append(relation_intrusion_threat_actor.get("id"))

        report = self.converter_to_stix.process_report(
            report_name=item.get("group"),
            victim_name=victim_name,
            attack_date_iso=attack_date_iso,
            description=item.get("description"),
            object_refs=object_refs,
            discovered_iso=discovered_iso,
            external_references=external_references,
        )

        # Creating Sector object
        if item.get("activity"):
            sector_id = self.sector_fetcher(item.get("activity"))
            if sector_id:
                report.get("object_refs").append(sector_id)

                (
                    relation_sector_victim,
                    relation_sector_threat_actor,
                    relation_intrusion_sector,
                ) = self.converter_to_stix.process_sector(
                    victim=victim,
                    create_threat_actor=self.config.connector.create_threat_actor,
                    intrusion_set=intrusion_set,
                    threat_actor=threat_actor,
                    sector_id=sector_id,
                    attack_date_iso=attack_date_iso,
                    discovered_iso=discovered_iso,
                )

                bundle_objects.append(relation_sector_victim)

                if self.config.connector.create_threat_actor:
                    bundle_objects.append(relation_sector_threat_actor)
                    report.get("object_refs").append(
                        relation_sector_threat_actor.get("id")
                    )

                report.get("object_refs").append(relation_sector_victim.get("id"))
                bundle_objects.append(relation_intrusion_sector)
                report.get("object_refs").append(relation_intrusion_sector.get("id"))

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
            domain, relation_victim_domain, ip_object, relation_domain_ip = (
                self.converter_to_stix.process_domain(
                    domain_name=domain_name, victim=victim
                )
            )

            bundle_objects.append(domain)
            bundle_objects.append(relation_victim_domain)

            if ip_object and ip_object.get("id"):
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

            (
                location,
                location_relation,
                relation_intrusion_location,
                relation_threat_actor_location,
            ) = self.converter_to_stix.process_location(
                country_name=country_name,
                victim=victim,
                intrusion_set=intrusion_set,
                create_threat_actor=self.config.connector.create_threat_actor,
                threat_actor=threat_actor,
                country_stix_id=country_stix_id,
                attack_date_iso=attack_date_iso,
                discovered_iso=discovered_iso,
            )

            # If country not yet available, add it in the bundle_objects for creation
            if country_stix_id is None:
                bundle_objects.append(location)

            bundle_objects.append(location_relation)
            bundle_objects.append(relation_intrusion_location)

            if self.config.connector.create_threat_actor:
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
        """Collects historic intelligence from ransomware.live"""
        # fetching group information
        group_data = self.api_client.get_feed("groups")

        # Checking if the historic year is less than 2020 as there is no data past 2020
        year = (
            self.config.connector.history_start_year
            if self.config.connector.history_start_year >= 2020
            else 2020
        )

        current_year = datetime.now().year
        bundle = []
        nb_stix_objects = 0

        for year in range(year, current_year + 1):  # Looping through the years
            year_url = "victims/" + str(year)
            for month in range(1, 13):  # Looping through the months
                bundles = []
                path = year_url + "/" + str(month)
                response_json = self.api_client.get_feed(path)

                for item in response_json:
                    try:
                        bundle_list = self.create_bundle_list(
                            item=item, group_data=group_data
                        )

                        if bundle_list:
                            # Add Author object
                            bundle_list = [self.converter_to_stix.author] + bundle_list

                            nb_stix_objects += len(bundle_list)

                            # Deduplicate the objects
                            bundle_list = self.helper.stix2_deduplicate_objects(
                                bundle_list
                            )

                            bundles.append(self.helper.stix2_create_bundle(bundle_list))
                        else:
                            self.helper.connector_logger.info("No new data to process")
                    except stix2.exceptions.STIXError as error:
                        self.helper.connector_logger.error(
                            "Error during creation of bundle on collect historic intelligence",
                            {"error": error},
                        )
                        continue

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

        if nb_stix_objects:
            self.last_run_datetime_with_ingested_data = datetime.now(
                tz=timezone.utc
            ).isoformat(timespec="seconds")

    def collect_intelligence(self):
        """Collects intelligence from the last 24 on ransomware.live"""
        # fetching group information
        group_data = self.api_client.get_feed("groups")

        # fetching recent requests
        response_json = self.api_client.get_feed("recentvictims")

        nb_stix_objects = 0
        bundles = []
        last_run_datetime = self.last_run_datetime_with_ingested_data or self.last_run

        for item in response_json:
            created = datetime.strptime(
                item.get("discovered"), "%Y-%m-%d %H:%M:%S.%f"
            ).replace(tzinfo=timezone.utc)

            # We only retrieve the data from the last 24h.
            # If no last_run, just put time_diff to 0.
            # The result of created date - (last_run date - 1 day) has to be at most 24h/1 day.
            if not last_run_datetime:
                time_diff = 0
            else:
                time_diff = (
                    created - (last_run_datetime - timedelta(days=1))
                ).seconds  # pushing all the data from the last 24 hours

            if time_diff < ONE_DAY_IN_SECONDS:
                try:
                    bundle_list = self.create_bundle_list(
                        item=item,
                        group_data=group_data,
                    )  # calling the stix_object_generator method to create stix objects

                    if bundle_list:
                        # Add Author object at first
                        bundle_list = [self.converter_to_stix.author] + bundle_list

                        # Deduplicate the objects
                        bundle_list = self.helper.stix2_deduplicate_objects(bundle_list)

                        nb_stix_objects += len(bundle_list)

                        self.helper.connector_logger.info(
                            "Sending STIX objects to OpenCTI...",
                            {"len_bundle_list": len(bundle_list)},
                        )

                        # Creating Bundle
                        bundles.append(self.helper.stix2_create_bundle(bundle_list))
                    else:
                        self.helper.connector_logger.info("No new data to process")
                except stix2.exceptions.STIXError as error:
                    self.helper.connector_logger.error(
                        "Error during creation of bundle on collect intelligence",
                        {"error": error},
                    )
                    continue

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

    def process_message(self) -> None:
        """Connector main process to collect intelligence"""
        # Main procedure
        self.helper.connector_logger.info(
            "Starting connector...", {"connector_name": self.helper.connect_name}
        )

        try:
            # Get the current timestamp and check
            now = datetime.now(tz=timezone.utc)
            current_state = self.helper.get_state()

            if current_state:
                if "last_run" in current_state:
                    if isinstance(current_state["last_run"], int):
                        self.last_run = datetime.fromtimestamp(
                            current_state["last_run"]
                        ).replace(tzinfo=timezone.utc)
                    else:
                        self.last_run = datetime.fromisoformat(
                            current_state["last_run"]
                        )
                if current_state.get("last_run_datetime_with_ingested_data", None):
                    self.last_run_datetime_with_ingested_data = datetime.fromisoformat(
                        current_state["last_run_datetime_with_ingested_data"]
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
                if not self.last_run and self.config.connector.pull_history:
                    self.collect_historic_intelligence()
                else:
                    self.collect_intelligence()

                # Store the current timestamp as a last run
                self.helper.connector_logger.debug(
                    "Getting current state and update it with last run",
                    {
                        "current_state": self.last_run,
                        "new_last_run_start_datetime": now.isoformat(
                            timespec="seconds"
                        ),
                    },
                )

                if current_state:
                    current_state["last_run"] = now.isoformat(timespec="seconds")

                    if self.last_run_datetime_with_ingested_data:
                        current_state["last_run_datetime_with_ingested_data"] = (
                            self.last_run_datetime_with_ingested_data
                        )

                    self.helper.set_state(current_state)
                else:
                    state = {"last_run": now.isoformat(timespec="seconds")}
                    if self.last_run_datetime_with_ingested_data:
                        state["last_run_datetime_with_ingested_data"] = (
                            self.last_run_datetime_with_ingested_data
                        )
                    self.helper.set_state(state)

            except RansomwareAPIError as e:
                self.helper.connector_logger.error(
                    "Error while fetching Ransomware API", {"error": e}
                )

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "Connector stopped", {"connector_name": self.helper.connect_name}
            )
            sys.exit(0)
        except Exception as e:
            self.helper.connector_logger.error("Connector error on run", {"error": e})

        finally:
            message = "Connector successfully run, storing last_run as" + now.isoformat(
                timespec="seconds"
            )

            if self.work_id:
                self.helper.api.work.to_processed(self.work_id, message)
            self.helper.connector_logger.info(message)

            self.work_id = None

    def run(self):
        """Run the main process encapsulated in a scheduler"""
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
