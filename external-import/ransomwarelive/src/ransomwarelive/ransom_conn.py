import sys
from datetime import datetime, timedelta, timezone

import pycti
import stix2
from models.configs.config_loader import ConfigLoader
from pycti import OpenCTIConnectorHelper
from ransomwarelive.api_client import RansomwareAPIClient, RansomwareAPIError
from ransomwarelive.converter_to_stix import ConverterToStix
from ransomwarelive.utils import (
    domain_extractor,
    get_group_entry,
    is_domain,
    safe_datetime,
)

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
        # ``ConfigLoader`` is a Pydantic settings object, not a dict — the
        # marking lives on the validated ``connector.marking_value`` field
        # added in ``models/configs/connector_configs.py``. Going through
        # the pydantic attribute keeps the value type-checked and the
        # supported TLP enumeration enforced.
        self.converter_to_stix = ConverterToStix(
            self.config.connector.marking_value,
            self.config.connector.create_leak_site_domains,
        )
        self.marking = self.converter_to_stix.marking
        self.last_run = None
        self.last_run_datetime_with_ingested_data = None
        self.author = self.converter_to_stix.author
        self.api_client = RansomwareAPIClient(helper=self.helper)
        # Track groups already enriched this run to avoid re-fetching/re-emitting
        # the same leak-site domains and TTP relationships for every victim.
        # Reset at the start of each collection sweep (see
        # ``collect_intelligence`` / ``collect_historic_intelligence``) because
        # ``schedule_iso`` reuses this instance across scheduled runs.
        self.processed_groups: set[str] = set()

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
                    "filters": [
                        {"key": "entity_type", "values": ["Sector"], "operator": "eq"}
                    ],
                    "filterGroups": [
                        {
                            "mode": "or",
                            "filters": [
                                {"key": "name", "values": sector, "operator": "eq"},
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

    def attack_pattern_fetcher(self, technique_id: str) -> str | None:
        """
        Return the STIX ID of an AttackPattern in OpenCTI by MITRE technique ID.

        Param:
            technique_id: MITRE ATT&CK technique ID (e.g. "T1190")
        Return:
            STIX ID string (e.g. "attack-pattern--uuid") or None if not found
        """
        try:
            result = self.helper.api.attack_pattern.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {
                            "key": "x_mitre_id",
                            "values": [technique_id],
                            "operator": "eq",
                        }
                    ],
                    "filterGroups": [],
                }
            )
            if result and result.get("standard_id"):
                return result["standard_id"]
            return None
        except Exception as e:
            self.helper.connector_logger.error(
                "Error fetching attack pattern",
                {"technique_id": technique_id, "error": e},
            )
            return None

    def process_group_ttps(
        self,
        group_entry: dict,
        intrusion_set: stix2.IntrusionSet,
    ) -> list:
        """
        Create 'uses' relationships from an IntrusionSet to ATT&CK AttackPatterns
        listed in the group's TTPs.  Silently skips any technique not found in OpenCTI
        (e.g. when the MITRE ATT&CK connector has not yet run).

        Params:
            group_entry (dict): single group entry from /v2/groups API
            intrusion_set (stix2.IntrusionSet): the group's IntrusionSet object
        Returns:
            list of 'uses' Relationship objects (the referenced AttackPatterns
            are resolved from OpenCTI by id and are not added to the bundle)
        """
        objects = []
        for tactic in group_entry.get("ttps") or []:
            for technique in tactic.get("techniques") or []:
                technique_id = technique.get("technique_id")
                if not technique_id:
                    continue
                attack_pattern_id = self.attack_pattern_fetcher(technique_id)
                if attack_pattern_id:
                    relation = self.converter_to_stix.create_relationship(
                        source_ref=intrusion_set.get("id"),
                        target_ref=attack_pattern_id,
                        relationship_type="uses",
                    )
                    objects.append(relation)
        return objects

    def _collect_group_enrichment_objects(
        self,
        group_name: str,
        group_data: list[dict],
        intrusion_set: stix2.IntrusionSet,
    ) -> list:
        """
        Return leak-site and TTP STIX objects for a group, or an empty list if the
        group has already been processed this run (deduplication guard).

        Params:
            group_name (str): group name as it appears in victim data
            group_data (list[dict]): full /v2/groups API response for this run
            intrusion_set (stix2.IntrusionSet): the group's IntrusionSet object
        Returns:
            list of stix2 objects to add to the bundle
        """
        if group_name in self.processed_groups:
            return []
        group_entry = get_group_entry(group_name, group_data)
        if not group_entry:
            # Don't mark the group processed until a matching entry is found, so
            # a partial/inconsistent API response doesn't permanently skip it.
            return []
        self.processed_groups.add(group_name)
        objects = []
        if self.config.connector.create_leak_site_domains:
            objects.extend(
                self.converter_to_stix.process_group_leak_sites(
                    group_entry=group_entry,
                    intrusion_set=intrusion_set,
                )
            )
        objects.extend(
            self.process_group_ttps(
                group_entry=group_entry,
                intrusion_set=intrusion_set,
            )
        )
        return objects

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

        # 1. Creating Victim object
        victim_name = item.get("victim")
        victim = self.converter_to_stix.process_victim(victim_name=victim_name)
        bundle_objects.append(victim)

        attack_date = item.get("attackdate")
        attack_date_iso = safe_datetime(attack_date)

        discovered = item.get("discovered")
        discovered_iso = safe_datetime(discovered)

        # Build the canonical external-reference list ONCE up-front so
        # every emitted SDO (Threat Actor, Campaign, Report, …) sees the
        # same list. The previous shape initialised ``external_references``
        # from ``item.get("external_references", [])`` (an empty list in
        # practice) and only rebuilt it via ``process_external_references``
        # *after* the Campaign had already been created, so the Campaign
        # missed its screenshot / website / post URL references.
        external_references = self.converter_to_stix.process_external_references(
            item,
            create_leak_post_refs=self.config.connector.create_leak_post_refs,
        )

        # 2. Creating Threat Actor object
        threat_actor = None
        relation_threat_actor_victim = None
        if self.config.connector.create_threat_actor:
            (
                threat_actor,
                relation_threat_actor_victim,
            ) = self.converter_to_stix.process_threat_actor(
                threat_actor_name=item.get("group"),
                group_data=group_data,
                victim=victim,
                attack_date_iso=attack_date_iso,
                discovered_iso=discovered_iso,
            )
            bundle_objects.append(threat_actor)
            bundle_objects.append(relation_threat_actor_victim)

        # 3. Creating Campaign object — reuse the ``targets`` relationship
        # ``process_campaign`` already creates instead of building a second
        # one manually below (that produced a duplicate Campaign -> Victim
        # ``targets`` relationship in the bundle on every cycle).
        campaign = None
        relation_campaign_victim = None
        if self.config.connector.create_campaign:
            (
                campaign,
                relation_campaign_victim,
            ) = self.converter_to_stix.process_campaign(
                actor_name=item.get("group"),
                group_data=group_data,
                victim=victim,
                description=item.get("description"),
                attack_date_iso=attack_date_iso,  # first_seen
                # ``discovered_iso`` becomes the ``created`` timestamp on
                # the Campaign -> Victim ``targets`` relationship emitted
                # by ``process_campaign``. Without it the relationship
                # would be timestamp-less while the parallel
                # ThreatActor -> Victim / IntrusionSet -> Victim
                # relationships emitted below correctly carry the same
                # discovery time — leaving the Campaign relationship
                # subtly out of sync.
                discovered_iso=discovered_iso,
                external_references=external_references,
            )
            bundle_objects.append(campaign)
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
            # Leak-site DomainName observables and IntrusionSet->AttackPattern
            # 'uses' relationships for this group (deduped per run).
            bundle_objects.extend(
                self._collect_group_enrichment_objects(
                    group_name=intrusion_set_name,
                    group_data=group_data,
                    intrusion_set=intrusion_set,
                )
            )

            # Link Intrusion Set <-> Threat Actor
            if (
                self.config.connector.create_threat_actor
                and self.config.connector.create_intrusion_set
            ):
                relation_intrusion_threat_actor = (
                    self.converter_to_stix.create_relationship(
                        intrusion_set.id, threat_actor.id, "attributed-to"
                    )
                )
                bundle_objects.append(relation_intrusion_threat_actor)

            # Link Campaign -> Intrusion Set
            if (
                self.config.connector.create_campaign
                and self.config.connector.create_intrusion_set
            ):
                relation_campaign_intrusion = (
                    self.converter_to_stix.create_relationship(
                        campaign.id, intrusion_set.id, "attributed-to"
                    )
                )
                if relation_campaign_intrusion:
                    bundle_objects.append(relation_campaign_intrusion)

        # 5. Accumulate the Report ``object_refs`` as the bundle is
        # built. ``stix2`` SDOs are conceptually immutable: although
        # the ``object_refs`` list happens to round-trip a ``.append``
        # in stix2 3.0.1, the pattern bypasses the property
        # validators, relies on the storage container being a list
        # (a future stix2 release could swap it for a tuple), and is
        # easy to misread because the Report would have to be
        # constructed with a partial ``object_refs`` list and then
        # mutated in-place. Build the canonical list here and create
        # the Report once at the end of this method instead.
        object_refs = []
        if self.config.connector.create_report:
            object_refs.append(victim.get("id"))

            if self.config.connector.create_intrusion_set:
                object_refs.append(intrusion_set.id)
                if relation_victim_intrusion:
                    object_refs.append(relation_victim_intrusion.id)
            if (
                self.config.connector.create_threat_actor
                and relation_threat_actor_victim
                and threat_actor
            ):
                # The Threat Actor SDO itself has to be referenced from
                # the Report alongside its outgoing ``targets``
                # relationship — otherwise enabling ``create_report``
                # together with ``create_threat_actor`` produces a
                # Report whose ``object_refs`` reach the relationship
                # but not the Threat Actor entity at the source of it.
                object_refs.append(threat_actor.id)
                object_refs.append(relation_threat_actor_victim.get("id"))
            if (
                self.config.connector.create_threat_actor
                and self.config.connector.create_intrusion_set
                and relation_intrusion_threat_actor
            ):
                object_refs.append(relation_intrusion_threat_actor.get("id"))
            if self.config.connector.create_campaign and campaign:
                object_refs.append(campaign.get("id"))
                if relation_campaign_victim:
                    object_refs.append(relation_campaign_victim.get("id"))
            if (
                self.config.connector.create_campaign
                and self.config.connector.create_intrusion_set
                and relation_campaign_intrusion
            ):
                object_refs.append(relation_campaign_intrusion.get("id"))

        # 6. Creating Sector object — the converter's ``process_sector``
        # now gates the per-actor / per-intrusion / per-campaign
        # relationships on the matching flag, so the call site has to
        # pass every flag the user has enabled. Without this every
        # ``relation_intrusion_sector`` / ``relation_campaign_sector``
        # came back ``None`` and was about to be appended into the
        # bundle anyway.
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
                    create_intrusion_set=self.config.connector.create_intrusion_set,
                    create_campaign=self.config.connector.create_campaign,
                    intrusion_set=intrusion_set,
                    threat_actor=threat_actor,
                    campaign=campaign,
                    attack_date_iso=attack_date_iso,
                    discovered_iso=discovered_iso,
                )

                bundle_objects.append(sector)
                bundle_objects.append(relation_sector_victim)

                if (
                    self.config.connector.create_threat_actor
                    and relation_sector_threat_actor
                ):
                    bundle_objects.append(relation_sector_threat_actor)
                if (
                    self.config.connector.create_intrusion_set
                    and relation_intrusion_sector
                ):
                    bundle_objects.append(relation_intrusion_sector)
                if self.config.connector.create_campaign and relation_campaign_sector:
                    bundle_objects.append(relation_campaign_sector)

                if self.config.connector.create_report:
                    object_refs.append(sector.get("id"))
                    object_refs.append(relation_sector_victim.get("id"))
                    if relation_sector_threat_actor:
                        object_refs.append(relation_sector_threat_actor.get("id"))
                    if relation_intrusion_sector:
                        object_refs.append(relation_intrusion_sector.get("id"))
                    if relation_campaign_sector:
                        object_refs.append(relation_campaign_sector.get("id"))

        # 7. Creating Domain object — guard the unicode-strip against a
        # missing/null ``domain`` field. ``item.get("domain")`` can be
        # ``None`` (or absent) and calling ``.replace`` on it would
        # ``AttributeError`` and abort the whole bundle build for the
        # victim. Defaulting to an empty string keeps the downstream
        # ``is_domain`` / ``domain_extractor`` checks happy.
        domain_name = None
        domain_obj = (item.get("domain") or "").replace("\u200b", "")

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

            if self.config.connector.create_report:
                object_refs.append(domain.get("id"))
                object_refs.append(relation_victim_domain.get("id"))

        # 8. Creating Location object — ``process_location`` now gates
        # the IntrusionSet -> Location relationship on
        # ``create_intrusion_set``, so the call site has to forward the
        # flag (without it the relationship always came back ``None``
        # even when the user had explicitly opted into intrusion sets).
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
                    create_intrusion_set=self.config.connector.create_intrusion_set,
                    threat_actor=threat_actor,
                    attack_date_iso=attack_date_iso,
                    discovered_iso=discovered_iso,
                )

                bundle_objects.append(location)
                bundle_objects.append(location_relation)

                if relation_intrusion_location:
                    bundle_objects.append(relation_intrusion_location)

                if (
                    self.config.connector.create_threat_actor
                    and relation_threat_actor_location
                ):
                    bundle_objects.append(relation_threat_actor_location)

                if self.config.connector.create_report:
                    if relation_threat_actor_location:
                        object_refs.append(relation_threat_actor_location.get("id"))
                    object_refs.append(location.get("id"))
                    if relation_intrusion_location:
                        object_refs.append(relation_intrusion_location.get("id"))
                    object_refs.append(location_relation.get("id"))

        # 9. Creating Report object — built ONCE here, after every
        # ``object_refs`` entry has been accumulated above. The earlier
        # shape created the Report mid-flow and then mutated
        # ``report.get("object_refs").append(...)`` from the Sector /
        # Domain / Location blocks. Although that round-tripped on
        # stix2 3.0.1 (where ``object_refs`` is internally a list) the
        # pattern bypasses property validators and breaks the moment a
        # future stix2 release stores list properties as tuples — and
        # makes the data flow much harder to follow. Building the full
        # ``object_refs`` list first and constructing the Report once
        # is the canonical stix2 idiom.
        if self.config.connector.create_report:
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
                bundle_objects.append(report)

        self.helper.connector_logger.info(
            "Sending STIX objects to collect_intelligence.",
            {"len_bundle_objects": len(bundle_objects)},
        )

        # Author + marking are prepended by the two callers
        # (``collect_intelligence`` / ``collect_historic_intelligence``)
        # in exactly one place each — this builder must NOT prepend
        # them too, otherwise the same author / marking SDO ends up in
        # the bundle twice (and the historic-vs-recent paths drift).
        return bundle_objects

    def collect_historic_intelligence(self):
        """Collects historic intelligence from ransomware.live"""
        # ``schedule_iso`` reuses the same connector instance across every
        # scheduled run, so the per-run group-enrichment dedup guard has to be
        # cleared at the start of each collection sweep. Otherwise a group
        # enriched on an earlier run stays in ``processed_groups`` forever and
        # its newly disclosed leak sites / TTPs are silently skipped until the
        # process restarts.
        self.processed_groups = set()
        # fetching group information
        group_data = self.api_client.get_feed("groups")
        if not group_data:
            self.helper.connector_logger.info(
                "No group data retrieved from ransomware.live API"
            )
            return

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

        # Clamp year/month to valid ranges.
        #
        # When clamping the year up to 2020, the month MUST also be
        # reset to 1 so the combined ``(year, month)`` floor matches
        # the documented contract ("values older than 2020 are
        # clamped to 2020-01"). The previous shape only clamped the
        # year and left a parsed ``YYYYMM`` month intact — so a
        # ``history_start_year=201912`` ended up starting the
        # backfill at 2020-12 (skipping the entire 2020 jan-nov
        # window) instead of the documented 2020-01.
        if start_year_historic < 2020:
            start_year_historic = 2020
            start_month_historic = 1
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
        for year in range(
            start_year_historic, current_year + 1
        ):  # Looping through the years
            year_url = "victims/" + str(year)

            first_month = start_month_historic if year == start_year_historic else 1
            last_month = current_month if year == current_year else 12

            for month in range(first_month, last_month + 1):
                bundles = []
                path = year_url + "/" + str(month)
                response_json = self.api_client.get_feed(path)
                if not response_json:
                    self.helper.connector_logger.info(
                        f"No data retrieved from ransomware.live API for {year}/{month}"
                    )
                    continue

                for item in response_json:
                    try:
                        bundle_list = self.create_bundle_list(
                            item=item, group_data=group_data
                        )

                        if bundle_list:
                            # Prepend BOTH the marking definition and the
                            # author. ``send_stix2_bundle`` below is called
                            # with ``cleanup_inconsistent_bundle=True``, so
                            # any ``object_marking_refs`` pointing at a
                            # marking SDO that is not also in the bundle
                            # would be stripped — that is exactly the
                            # empty-marking regression #6419 reported, and
                            # the live ``collect_intelligence`` path
                            # already prepends ``[marking, author]`` here.
                            # The historic backfill must mirror that or it
                            # silently reintroduces the bug for the
                            # backfill bundles only.
                            bundle_list = [
                                self.converter_to_stix.marking,
                                self.converter_to_stix.author,
                            ] + bundle_list
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
        # Reset the per-run group-enrichment dedup guard (see
        # ``collect_historic_intelligence``): the connector instance is reused
        # across scheduled runs, so without this a group enriched on a previous
        # run would be skipped forever and never pick up new leak sites / TTPs.
        self.processed_groups = set()
        group_data = self.api_client.get_feed("groups")
        if not group_data:
            self.helper.connector_logger.info(
                "No group data retrieved from ransomware.live API"
            )
            return

        # fetching recent requests
        response_json = self.api_client.get_feed("recentvictims")
        if not response_json:
            self.helper.connector_logger.info(
                "No recent victim data retrieved from ransomware.live API"
            )
            return

        nb_stix_objects = 0
        bundles = []
        # Upper bound for the recent-victim filter must be a clock that
        # advances every cycle, otherwise a stretch of zero-ingest
        # cycles can permanently freeze the window in the past and any
        # disclosure with ``created`` past the frozen upper bound is
        # silently dropped on every subsequent cycle.
        # ``self.last_run`` is set by ``process_message`` on every
        # cycle (independent of ingest outcome);
        # ``self.last_run_datetime_with_ingested_data`` only advances
        # on cycles that actually produced bundles. The previous shape
        # used the ingest-only timestamp as the primary anchor, which
        # made the upper bound stick at the last successful ingest and
        # excluded every subsequently-disclosed victim from the
        # window. Prefer ``self.last_run`` and only fall back to the
        # ingest-only timestamp when the connector has never run
        # before (cold start).
        last_run_datetime = self.last_run or self.last_run_datetime_with_ingested_data

        for item in response_json:
            discovered_raw = item.get("discovered")
            created = safe_datetime(discovered_raw)
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)

            # The recent-victims filter accepts items disclosed in the
            # 24h window ending at ``last_run_datetime``: from
            # ``last_run_datetime - 1 day`` (covering disclosures the
            # previous run might have missed because the upstream
            # stream had not flushed them yet) to ``last_run_datetime``
            # (excluded — anything more recent is picked up on the
            # next cycle). The previous shape used
            # ``timedelta.seconds`` which only returns the 0..86399
            # seconds-of-day component and silently wrapped negative
            # deltas (items disclosed *older* than
            # ``last_run_datetime - 1 day``) back into the in-window
            # range — defeating the 24h filter and re-importing every
            # old victim on every cycle. Bounded
            # ``0 <= time_diff < ONE_DAY_IN_SECONDS`` now respects
            # both ends of the window so neither sign of drift slips
            # through.
            if not last_run_datetime:
                is_recent = True
            else:
                time_diff = (
                    created - (last_run_datetime - timedelta(days=1))
                ).total_seconds()
                is_recent = 0 <= time_diff < ONE_DAY_IN_SECONDS

            if is_recent:
                try:
                    bundle_list = self.create_bundle_list(
                        item=item,
                        group_data=group_data,
                    )

                    if bundle_list:
                        # Add Author object and marking
                        bundle_list = [
                            self.converter_to_stix.marking,
                            self.converter_to_stix.author,
                        ] + bundle_list
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

                # ``self.last_run_datetime_with_ingested_data`` is a
                # ``datetime`` on cycles that *loaded* it from prior
                # state (``datetime.fromisoformat`` at the top of
                # ``process_message``) and an ISO ``str`` on cycles
                # that *just set* it via the collectors. Either way the
                # value persisted to ``helper.set_state(...)`` must be
                # JSON-serialisable — storing a raw ``datetime`` makes
                # the platform's state writer either reject the payload
                # or stringify it in a non-round-trippable shape.
                # Coerce to an ISO string with the same precision used
                # for ``last_run`` so both fields round-trip
                # symmetrically across ``set_state`` /
                # ``datetime.fromisoformat``.
                last_run_datetime_with_ingested_data_iso = (
                    self.last_run_datetime_with_ingested_data.isoformat(
                        timespec="seconds"
                    )
                    if isinstance(self.last_run_datetime_with_ingested_data, datetime)
                    else self.last_run_datetime_with_ingested_data
                )
                if current_state:
                    current_state["last_run"] = now.isoformat(timespec="seconds")
                    if last_run_datetime_with_ingested_data_iso:
                        current_state["last_run_datetime_with_ingested_data"] = (
                            last_run_datetime_with_ingested_data_iso
                        )
                    self.helper.set_state(current_state)
                else:
                    state = {"last_run": now.isoformat(timespec="seconds")}
                    if last_run_datetime_with_ingested_data_iso:
                        state["last_run_datetime_with_ingested_data"] = (
                            last_run_datetime_with_ingested_data_iso
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
            message = (
                f"Connector successfully run, storing last_run as "
                f"{now.isoformat(timespec='seconds')}"
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
