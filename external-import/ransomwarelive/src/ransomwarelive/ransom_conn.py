import sys
from datetime import datetime, timedelta, timezone

import pycti
import stix2
from models.configs.config_loader import ConfigLoader
from pycti import OpenCTIConnectorHelper
from ransomwarelive.api_client import RansomwareAPIClient, RansomwareAPIError
from ransomwarelive.converter_to_stix import ConverterToStix
from ransomwarelive.utils import domain_extractor, is_domain, safe_datetime

ONE_DAY_IN_SECONDS = 86400


class RansomwareAPIConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.
    """

    def __init__(self, helper: OpenCTIConnectorHelper, config: ConfigLoader) -> None:
        self.helper = helper
        self.config = config
        self.work_id = None
        marking_value = self.config["MARKING_VALUE"]
        self.converter_to_stix = ConverterToStix(marking_value)
        self.marking = self.converter_to_stix.marking
        self.last_run = None
        self.last_run_datetime_with_ingested_data = None
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
                country_obj = (
                    self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                        entity_type="country",
                        entity_id=country_out["standard_id"],
                        only_entity=True,
                    )
                )
                return country_obj
            else:
                country_obj = self.converter_to_stix.create_country(
                    country_name=country
                )
                return country_obj

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
                    "filters": [{"key": "entity_type", "values": ["Sector"], "operator": "eq"}],
                    "filterGroups": [
                        {
                            "mode": "or",
                            "filters": [
                                {"key": "name", "values": sector, "operator": "eq"},
                                {"key": "x_opencti_aliases", "values": sector, "operator": "eq"},
                            ],
                            "filterGroups": [],
                        }
                    ],
                },
            )

            if sector_out and sector_out.get("standard_id").startswith("identity--"):
                sector_obj = (
                    self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                        entity_type="Sector",
                        entity_id=sector_out["standard_id"],
                        only_entity=True,
                    )
                )
                return sector_obj
            else:
                sector_obj = self.converter_to_stix.create_sector(name=sector)
                return sector_obj

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
        """Retrieve STIX objects and add them to bundle list"""
        bundle_objects = []

        external_references = item.get("external_references", [])

        # 1. Creating Victim object
        victim_name = item.get("victim")
        victim = self.converter_to_stix.process_victim(victim_name=victim_name)
        bundle_objects.append(victim)

        attack_date = item.get("attackdate")
        attack_date_iso = safe_datetime(attack_date)

        discovered = item.get("discovered")
        discovered_iso = safe_datetime(discovered)

        # 2. Creating Threat Actor object
        threat_actor = None
        target_relation = None
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
        
        # 3. Creating Campaign object
        campaign = None
        if self.config.connector.create_campaign : 
            campaign, target_relation = self.converter_to_stix.process_campaign(
                actor_name=item.get("group"),
                group_data=group_data,
                victim=victim,
                description=item.get("description"),
                attack_date_iso=attack_date_iso, #first_seen
                external_references=external_references,
            )
            bundle_objects.append(campaign)
        
            # Relation entre la campagne et la victime
            relation_campaign_victim = self.converter_to_stix.create_relationship(
            campaign.id, victim.get("id"), "targets"
            )
            if relation_campaign_victim:
                bundle_objects.append(relation_campaign_victim)

        # 4. Creating Intrusion Set object
        intrusion_set = None
        relation_victim_intrusion = None
        relation_intrusion_threat_actor = None

        if self.config.connector.create_intrusion_set:
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
            if relation_victim_intrusion:
                bundle_objects.append(relation_victim_intrusion)

            # Link Intrusion Set <-> Threat Actor
            if self.config.connector.create_threat_actor and self.config.connector.create_intrusion_set:
                relation_intrusion_threat_actor = (self.converter_to_stix.create_relationship(
                    intrusion_set.id, threat_actor.id, "attributed-to")
                )
                bundle_objects.append(relation_intrusion_threat_actor)
            
            # Link Campaign -> Intrusion Set
            if  self.config.connector.create_campaign and self.config.connector.create_intrusion_set:
                relation_campaign_intrusion = self.converter_to_stix.create_relationship(
                campaign.id, intrusion_set.id, "attributed-to"
                )  
                if relation_campaign_intrusion:
                    bundle_objects.append(relation_campaign_intrusion)

        # Creating External References
        external_references = self.converter_to_stix.process_external_references(item)

        # 5. Creating Report object
        report = None
        object_refs = []
        if self.config.connector.create_report:
            object_refs.append(victim.get("id"))
           
            if self.config.connector.create_intrusion_set:
                object_refs.append(intrusion_set.id)
                object_refs.append(relation_victim_intrusion.id)
            if self.config.connector.create_threat_actor and target_relation and threat_actor:
                object_refs.append(target_relation.get("id"))
            if self.config.connector.create_threat_actor and self.config.connector.create_intrusion_set:
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
            if report:
                if self.config.connector.create_campaign:
                    report.get("object_refs").append(campaign.get("id"))
                    report.get("object_refs").append(relation_campaign_victim.get("id"))
                if self.config.connector.create_campaign and self.config.connector.create_intrusion_set:
                    report.get("object_refs").append(relation_campaign_intrusion.get("id"))
                bundle_objects.append(report)

        # 6. Creating Sector object
        if item.get("activity") and item["activity"] != "Not Found":
            sector = self.sector_fetcher(item["activity"])

            if sector:
                (
                    relation_sector_victim,
                    relation_sector_threat_actor,
                    relation_intrusion_sector,
                    relation_campaign_sector,
                ) = self.converter_to_stix.process_sector(
                    sector=sector,
                    victim=victim,
                    create_threat_actor=self.config.connector.create_threat_actor,
                    intrusion_set=intrusion_set,
                    threat_actor=threat_actor,
                    campaign=campaign,
                    attack_date_iso=attack_date_iso,
                    discovered_iso=discovered_iso,
                )

                bundle_objects.append(sector)
                bundle_objects.append(relation_sector_victim)

                if self.config.connector.create_threat_actor:
                    bundle_objects.append(relation_sector_threat_actor)
                    if self.config.connector.create_report:
                        report.get("object_refs").append(
                        relation_sector_threat_actor.get("id")
                    )
                if self.config.connector.create_intrusion_set:
                    bundle_objects.append(relation_intrusion_sector)

                if self.config.connector.create_campaign:
                    bundle_objects.append(relation_campaign_sector)

                if self.config.connector.create_report and report:
                    report.get("object_refs").append(sector.get("id"))
                    report.get("object_refs").append(relation_sector_victim.get("id"))
                    if relation_sector_threat_actor:
                        report.get("object_refs").append(relation_sector_threat_actor.get("id"))
                    if relation_intrusion_sector:
                        report.get("object_refs").append(relation_intrusion_sector.get("id"))
                    if relation_campaign_sector:
                        report.get("object_refs").append(relation_campaign_sector.get("id"))

        # 7. Creating Domain object
        domain_name = None
        domain_obj = item.get("domain").replace("\u200b", "")

        if is_domain(item.get("victim")):
            domain_name = domain_extractor(item.get("victim"))
        elif (
            domain_obj
            and domain_obj != ""
            and not is_domain(item.get("victim"))
            and domain_extractor(domain_obj)
        ):
            domain_name = domain_extractor(domain_obj)

        if domain_name:
            domain, relation_victim_domain = self.converter_to_stix.process_domain(
                domain_name=domain_name, victim=victim
            )

            bundle_objects.append(domain)
            bundle_objects.append(relation_victim_domain)

            if self.config.connector.create_report and report:
                report.get("object_refs").append(domain.get("id"))
                report.get("object_refs").append(relation_victim_domain.get("id"))

        # 8. Creating Location object
        if item.get("country"):
            country_name = item["country"]
            location = self.location_fetcher(country_name)

            if location:
                (
                    location_relation,
                    relation_intrusion_location,
                    relation_threat_actor_location,
                ) = self.converter_to_stix.process_location(
                    location=location,
                    victim=victim,
                    intrusion_set=intrusion_set,
                    create_threat_actor=self.config.connector.create_threat_actor,
                    threat_actor=threat_actor,
                    attack_date_iso=attack_date_iso,
                    discovered_iso=discovered_iso,
                )

                bundle_objects.append(location)
                bundle_objects.append(location_relation)
               
                if relation_intrusion_location: 
                    bundle_objects.append(relation_intrusion_location)

                if self.config.connector.create_threat_actor:
                    bundle_objects.append(relation_threat_actor_location)

                if self.config.connector.create_report and report: 
                    if relation_threat_actor_location:
                        report.get("object_refs").append(relation_threat_actor_location.get("id"))
                    report.get("object_refs").append(location.get("id"))
                    if relation_intrusion_location:
                        report.get("object_refs").append(relation_intrusion_location.get("id"))
                    report.get("object_refs").append(location_relation.get("id"))

                    if report:
                        bundle_objects.append(report)

        # Add Report finally
        if report:
            bundle_objects.append(report)

        self.helper.connector_logger.info(
            "Sending STIX objects to collect_intelligence.",
            {"len_bundle_objects": len(bundle_objects)},
        )
        bundle_objects = [self.converter_to_stix.marking, self.converter_to_stix.author] + bundle_objects

        return bundle_objects


from datetime import datetime, timezone
import stix2

def collect_historic_intelligence(self):
    """Collects historic intelligence from ransomware.live"""
    # fetching group information
    group_data = self.api_client.get_feed("groups")

    history_start_year = str(self.config.connector.history_start_year).strip()

    start_year_historic = 2020
    start_month_historic = 1

    # Extract year/month from string
    if history_start_year.isdigit():
        if len(history_start_year) >= 6:
            # "YYYYMM": first 4 = year, last 2 = month
            start_year_historic = int(history_start_year[:4])
            start_month_historic = int(history_start_year[-2:])
        elif len(history_start_year) == 4:
            # "YYYY": only year, start from January
            start_year_historic = int(history_start_year)
            start_month_historic = 1
    else:
        self.helper.connector_logger.warning(
            f"Invalid history_start_year '{history_start_year}', defaulting to 2020-01"
        )

    # Clamp year/month to valid ranges
    if start_year_historic < 2020:
        start_year_historic = 2020
    if not (1 <= start_month_historic <= 12):
        self.helper.connector_logger.warning(
            f"Invalid start month parsed from history_start_year '{history_start_year}', defaulting to 1"
        )
        start_month_historic = 1

    # Upper bounds: do not query in the future
    now = datetime.now()
    current_year = now.year
    current_month = now.month

    # If start year is in the future, stop early
    if start_year_historic > current_year:
        self.helper.connector_logger.info(
            f"No historic collection: start_year_historic '{start_year_historic}' > current_year '{current_year}'."
        )
        return

    nb_stix_objects = 0

    # Iterate years and months:
    # - First year: start at start_month_historic
    # - Next years: start at January
    # - Current year: stop at current_month
    for year in range(start_year_historic, current_year + 1):   # Looping through the years
        year_url = "victims/" + str(year)

        first_month = start_month_historic if year == start_year_historic else 1
        last_month = current_month if year == current_year else 12

        for month in range(first_month, last_month + 1):
            bundles = []
            path = year_url + "/" + str(month)
            response_json = self.api_client.get_feed(path)

            for item in response_json:
                try:
                    bundle_list = self.create_bundle_list(item=item, group_data=group_data)

                    if bundle_list:
                        # Add author, deduplicate, and bundle
                        bundle_list = [self.converter_to_stix.author] + bundle_list
                        nb_stix_objects += len(bundle_list)
                        # Deduplicate the objects
                        bundle_list = self.helper.stix2_deduplicate_objects(bundle_list)
                        bundles.append(self.helper.stix2_create_bundle(bundle_list))
                    else:
                        self.helper.connector_logger.info("No new data to process")
                except stix2.exceptions.STIXError as error:
                    self.helper.connector_logger.error(
                        "Error during creation of bundle on collect historic intelligence",
                        {"error": error},
                    )
                    continue

            # Send bundles for this year/month
            if bundles:
                # Initiate new work
                friendly_name = f"RansomwareLive - {year}/{month:02d}"
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
                    {"count_bundles": len(bundles)},
                )

    # Record last run time when data was ingested
    if nb_stix_objects:
        self.last_run_datetime_with_ingested_data = datetime.now(
            tz=timezone.utc
        ).isoformat(timespec="seconds")

    def collect_intelligence(self):
        """Collects intelligence from the last 24 on ransomware.live"""
        group_data = self.api_client.get_feed("groups")
        response_json = self.api_client.get_feed("recentvictims")

        nb_stix_objects = 0
        bundles = []
        last_run_datetime = self.last_run_datetime_with_ingested_data or self.last_run

        for item in response_json:
            created = datetime.strptime(
                item.get("discovered"), "%Y-%m-%d %H:%M:%S.%f"
            ).replace(tzinfo=timezone.utc)

            if not last_run_datetime:
                time_diff = 0
            else:
                time_diff = (
                    created - (last_run_datetime - timedelta(days=1))
                ).seconds

            if time_diff < ONE_DAY_IN_SECONDS:
                try:
                    bundle_list = self.create_bundle_list(
                        item=item,
                        group_data=group_data,
                    )

                    if bundle_list:
                        # Add Author object and marking
                        bundle_list = [self.converter_to_stix.marking, self.converter_to_stix.author] + bundle_list
                        bundle_list = self.helper.stix2_deduplicate_objects(bundle_list)
                        nb_stix_objects += len(bundle_list)

                        self.helper.connector_logger.info(
                            "Sending STIX objects to OpenCTI...",
                            {"len_bundle_list": len(bundle_list)},
                        )
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
        self.helper.connector_logger.info(
            "Starting connector...", {"connector_name": self.helper.connect_name}
        )

        try:
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

            try:
                if not self.last_run and self.config.connector.pull_history:
                    self.collect_historic_intelligence()
                else:
                    self.collect_intelligence()

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
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )