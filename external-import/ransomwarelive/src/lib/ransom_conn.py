import datetime as dt
import os
import re
import sys
from datetime import UTC, datetime

import pycti
import requests
import tldextract
import validators
import whois
from pycti import OpenCTIConnectorHelper
from pydantic import TypeAdapter, ValidationError
from stix2 import (
    TLP_WHITE,
    Bundle,
    DomainName,
    ExternalReference,
    Identity,
    IntrusionSet,
    IPv4Address,
    IPv6Address,
    Location,
    Relationship,
    Report,
    ThreatActor,
)


class RansomwareAPIConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.
    """

    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})
        self.work_id = None
        self.marking = TLP_WHITE
        self.last_run = None
        self.last_run_datetime_with_ingested_data = None

        self.get_historic = os.environ.get("RANSOMWARE_PULL_HISTORY", False)
        self.get_historic_year = os.environ.get("RANSOMWARE_HISTORY_START_YEAR", 2020)
        self.create_threat_actor = os.environ.get(
            "RANSOMWARE_CREATE_THREAT_ACTOR", False
        )
        self.duration_period = os.environ.get("CONNECTOR_DURATION_PERIOD", None)
        interval = os.environ.get("RANSOMWARE_INTERVAL", None)
        self.interval = interval if re.match(r"^\d+[dhms]$", interval) else None

        self.author = Identity(
            id=pycti.Identity.generate_id("Ransomware.Live", "organization"),
            name="Ransomware.Live",
            identity_class="organization",
            type="identity",
            object_marking_refs=[self.marking.get("id")],
            contact_information="https://www.ransomware.live/about#data",
            x_opencti_reliability="A - Completely reliable",
            allow_custom=True,
        )

    # Generates a group description from the ransomware.live API data
    def threat_description_generator(self, group_name, group_data):

        matching_items = [
            item for item in group_data if item.get("name", None) == group_name
        ]

        if matching_items and matching_items[0].get("description") is not (
            None or "" or " " or "null"
        ):
            description = matching_items[0].get(
                "description", "No description available"
            )

        else:
            description = "No description available"
        return description

    # Generates a relationship object
    def relationship_generator(
        self,
        source_ref: str,
        target_ref: str,
        relationship_type: str,
        attackdate: datetime = None,
        discovered: datetime = None,
    ) -> Relationship:

        relation = Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type,
                source_ref,
                target_ref,
                attackdate,
            ),
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            start_time=attackdate if attackdate else None,
            created=discovered if discovered else None,
            created_by_ref=self.author.get("id"),
        )
        return relation

    # Validates if the input is a domain
    def is_domain(self, name):
        return bool(validators.domain(name))

    # Validates if the input is an IPv4 address
    def is_ipv4(self, ip):
        return bool(validators.ipv4(ip))

    # Validates if the input is an IPv6 address
    def is_ipv6(self, ip):
        return bool(validators.ipv6(ip))

    # Fetches the IP address of a domain
    def ip_fetcher(self, domain):

        try:
            params = {"name": domain, "type": "A"}

            headers = {"accept": "application/json", "User-Agent": "OpenCTI"}

            response = requests.get(
                "https://dns.google/resolve",
                headers=headers,
                params=params,
                timeout=(20000, 20000),
            )
            response.raise_for_status()

            if response.status_code == 200:
                response_json = response.json()
                if response_json.get("Answer") is not None:
                    for item in response_json.get("Answer"):
                        if item.get("type") == 1 and self.is_ipv4(item.get("data")):
                            ip_address = item.get("data")
                            return ip_address
            return None
        except requests.exceptions.HTTPError as err:
            self.helper.connector_logger.error(
                "Http error during ip fetcher", {"error": err}
            )
        except Exception as e:
            self.helper.connector_logger.error(
                "Error fetching IP address", {"domain": domain, "error": e}
            )
            return None

    # Fetches the whois information of a domain
    def fetch_country_domain(self, domain):
        try:
            w = whois.whois(domain)
        except Exception as e:
            self.helper.connector_logger.error(
                "Error fetching WHOIS for domain", {"domain": domain, "error": e}
            )
            return None

        try:
            description = f"Domain:{domain}  \n"
            # Using whois data from w instead of response_json
            if w is not None:
                if w.get("country") is not None:
                    description += f" is registered in {w.get('country')}  \n"
                if w.get("registrar") is not None:
                    description += f"registered with {w.get('registrar')}  \n"
                if w.get("creation_date") is not None:
                    description += f" creation_date {w.get('creation_date')}  \n"
                if w.get("expiration_date") is not None:
                    description += f" expiration_date {w.get('expiration_date')}  \n"

        except Exception as e:
            self.helper.connector_logger.error(
                "Error fetching whois for domain", {"domain": domain, "error": e}
            )
            return None

        return description

    # Extracts the domain from a URL
    def domain_extractor(self, url):
        try:
            if validators.domain(url):
                return url
            domain = tldextract.extract(url).registered_domain
            if validators.domain(domain):
                return domain
            return None
        except Exception as e:
            self.helper.connector_logger.error("Error extracting domain", {"error": e})
            return None

    # Fetches the location object from OpenCTI
    def opencti_location_check(self, country):
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

    def sector_fetcher(self, sector):
        if sector == "":
            return None
        try:
            sectors_split = []
            rubbish = [" and ", " or ", " ", ";"]
            for item in rubbish:
                sector = " ".join(sector.split(item))

            sectors_split = sector.split()
            for item in sectors_split:
                if item in ("and", "or", ",", ", "):
                    sectors_split.remove(item)
                else:
                    item2 = item.strip()
                    sectors_split.remove(item)
                    sectors_split.append(item2)

            filtered_sectors = [
                {"key": "entity_type", "values": ["Sector"], "operator": "eq"},
            ]
            for sub_sector in sectors_split:
                sub_filter = {
                    "key": "name",
                    "values": [sub_sector],
                    "mode": "or",
                    "operator": "eq",
                }
                filtered_sectors.append(sub_filter)

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
            return None

        except Exception as e:
            self.helper.connector_logger.error(
                "Error fetching sector", {"sector": sector, "error": e}
            )
            return None

    def ip_object_creator(self, ip):
        try:
            if self.is_ipv4(ip):
                return self.ipv4_generator(ip)
            if self.is_ipv6(ip):
                return self.ipv6_generator(ip)
            return None
        except Exception as e:
            self.helper.connector_logger.error(
                "Error creating IP object", {"ip": ip, "error": e}
            )
            return None

    # Generates a ransom note external reference
    def ransom_note_generator(self, group_name):

        if group_name in ("lockbit3", "lockbit2"):
            return ExternalReference(
                source_name="Ransom Note",
                url="https://www.ransomware.live/ransomnotes/lockbit",
                description="Sample Ransom Note",
            )
        return ExternalReference(
            source_name="Ransom Note",
            url=f"https://www.ransomware.live/ransomnotes/{group_name}",
            description="Sample Ransom Note",
        )

    # Generates a STIX object for an IPv4 address
    def ipv4_generator(self, ip):
        return IPv4Address(
            value=ip,
            type="ipv4-addr",
            object_marking_refs=[self.marking.get("id")],
            created_by_ref=self.author.get("id"),
            allow_custom=True,
        )

    # Generates a STIX object for an IPv6 address
    def ipv6_generator(self, ip):
        return IPv6Address(
            value=ip,
            type="ipv6-addr",
            object_marking_refs=[self.marking.get("id")],
            created_by_ref=self.author.get("id"),
            allow_custom=True,
        )

    # Generates a STIX object for a domain
    def domain_generator(self, domain_name, description="-"):
        domain = DomainName(
            value=domain_name,
            type="domain-name",
            object_marking_refs=[self.marking.get("id")],
            allow_custom=True,
            created_by_ref=self.author.get("id"),
            x_opencti_description=description,
        )
        return domain

    def safe_datetime(self, value: str | None, check_field: str) -> datetime | None:
        """Safely parses a string into a naive datetime object (without timezone).
        Returns None if the input is None or not a valid ISO 8601 datetime string.
        Can avoid errors where fields are missing or incorrectly formed.
        Args:
            value (str | None): The input string to validate and convert to datetime.
            check_field (str): The name of the field being validated (used for logging).
        Returns:
            datetime | None : A naive datetime object if the input is valid, otherwise None.
        Examples:
            self.safe_datetime("2025-01-01 07:20:50.000000", "attack_date")
            > datetime.datetime(2025, 1, 1, 7, 20, 50, 0)

            self.safe_datetime(None, "attack_date")
            > None

            self.safe_datetime("invalid-date", "attack_date")
            > None
        """
        try:
            return TypeAdapter(datetime).validate_python(value)
        except ValidationError:
            self.helper.connector_log.debug(
                "The expected value is not a valid datetime.",
                {"field": check_field, "value": value},
            )
            return None

    # Generates STIX objects from the ransomware.live API data
    # pylint:disable=too-many-branches,too-many-statements
    def stix_object_generator(self, item, group_data):
        """Generates STIX objects from the ransomware.live API data"""

        # Creating Victim object
        post_title = item.get("victim")
        victim_name, identity_class = (
            (post_title, "organization")
            if len(post_title) > 2
            else ((post_title + ":<)"), "individual")
        )
        victim = Identity(
            id=pycti.Identity.generate_id(victim_name, identity_class),
            name=victim_name,
            identity_class=identity_class,
            type="identity",
            created_by_ref=self.author.get("id"),
            object_marking_refs=[self.marking.get("id")],
        )

        # RansomNote External Reference
        external_references_group = self.ransom_note_generator(item.get("group"))

        # Attack Date sets the start_time of the relationship between a threat actor or intrusion set and a victim.
        # This value (attack_date_iso) will also be used in the report. (Report : Attack Date -> Published)
        attack_date = item.get("attackdate")
        attack_date_iso = self.safe_datetime(attack_date, "attack_date")

        # Discovered sets the created date of the relationship between a Threat Actor or Intrusion Set and a Victim.
        # This value (discovered_iso) will also be used in the report. (Report : Discovered -> Created)
        discovered = item.get("discovered")
        discovered_iso = self.safe_datetime(discovered, "discovered")

        # Creating Threat Actor object
        threat_actor = None
        if self.create_threat_actor:
            threat_actor_name = item.get("group")
            threat_actor = ThreatActor(
                id=pycti.ThreatActorGroup.generate_id(threat_actor_name),
                name=threat_actor_name,
                labels=["ransomware"],
                created_by_ref=self.author.get("id"),
                description=self.threat_description_generator(
                    threat_actor_name, group_data
                ),
                object_marking_refs=[self.marking.get("id")],
                external_references=[external_references_group],
            )

            target_relation = self.relationship_generator(
                threat_actor.get("id"),
                victim.get("id"),
                "targets",
                attack_date_iso,
                discovered_iso,
            )

        # Creating Intrusion Set object
        try:
            if item.get("group") == "lockbit3" or item.get("group") == "lockbit2":
                intrusion_set = IntrusionSet(
                    id=pycti.IntrusionSet.generate_id("lockbit"),
                    name="lockbit",
                    labels=["ransomware"],
                    created_by_ref=self.author.get("id"),
                    description=self.threat_description_generator(
                        item.get("lockbit3"), group_data
                    ),
                    object_marking_refs=[self.marking.get("id")],
                    external_references=[external_references_group],
                )

            else:
                intrusionset_name = item.get("group")
                intrusion_set = IntrusionSet(
                    id=pycti.IntrusionSet.generate_id(intrusionset_name),
                    name=intrusionset_name,
                    labels=["ransomware"],
                    created_by_ref=self.author.get("id"),
                    description=self.threat_description_generator(
                        item.get("group"), group_data
                    ),
                    object_marking_refs=[self.marking.get("id")],
                    external_references=[external_references_group],
                )

            relation_vi_is = self.relationship_generator(
                intrusion_set.get("id"),
                victim.get("id"),
                "targets",
                attack_date_iso,
                discovered_iso,
            )
            if self.create_threat_actor:
                relation_is_ta = self.relationship_generator(
                    intrusion_set.get("id"), threat_actor.get("id"), "attributed-to"
                )

        except Exception as e:
            self.helper.connector_logger.error(
                "Error while creating intrusion set object", {"error": e}
            )

        # Creating External References Object if they have external references
        external_references = []
        external_references.append(external_references_group)

        for field in ["screenshot", "website", "post_url"]:

            if item.get(field):
                external_reference = ExternalReference(
                    source_name="ransomware.live",
                    url=item[field],
                    description=f"This is the {field} for the ransomware campaign.",
                )
                external_references.append(external_reference)

        # Creating Report object
        object_refs = [
            victim.get("id"),
            intrusion_set.get("id"),
            relation_vi_is.get("id"),
        ]
        if self.create_threat_actor:
            object_refs.append(target_relation.get("id"))
            object_refs.append(relation_is_ta.get("id"))
        report_name = item.get("group") + " has published a new victim: " + post_title
        report = Report(
            id=pycti.Report.generate_id(report_name, attack_date_iso),
            report_types=["Ransomware-report"],
            name=report_name,
            description=item.get("description"),
            created_by_ref=self.author.get("id"),
            object_refs=object_refs,
            published=attack_date_iso,
            created=discovered_iso,
            object_marking_refs=[self.marking.get("id")],
            external_references=external_references,
        )

        # Initial Bundle objects
        bundle = [
            self.author,
            victim,
            intrusion_set,
            relation_vi_is,
        ]
        if self.create_threat_actor:
            bundle.append(threat_actor)
            bundle.append(relation_is_ta)
            bundle.append(target_relation)

        # Creating Sector object
        try:
            if item.get("activity") is not None:
                sector_id = self.sector_fetcher(item.get("activity"))
                if sector_id is not None:
                    relation_sec_vic = self.relationship_generator(
                        victim.get("id"), sector_id, "part-of"
                    )
                    if self.create_threat_actor:
                        relation_sec_TA = self.relationship_generator(
                            threat_actor.get("id"),
                            sector_id,
                            "targets",
                            attack_date_iso,
                            discovered_iso,
                        )
                        bundle.append(relation_sec_TA)
                        report.get("object_refs").append(relation_sec_TA.get("id"))
                    relation_is_sec = self.relationship_generator(
                        intrusion_set.get("id"),
                        sector_id,
                        "targets",
                        attack_date_iso,
                        discovered_iso,
                    )
                    bundle.append(relation_sec_vic)
                    bundle.append(relation_is_sec)

                    report.get("object_refs").append(sector_id)
                    report.get("object_refs").append(relation_sec_vic.get("id"))
                    report.get("object_refs").append(relation_is_sec.get("id"))
        except Exception as e:
            self.helper.connector_logger.error(
                "Error while creating Sector object", {"error": e}
            )

        # Creating Domain object
        if self.is_domain(item.get("victim")):

            domain_name = item.get("victim")
            # Extracting domain name
            domain_name = self.domain_extractor(domain_name)
            # Fetching domain description
            description = self.fetch_country_domain(domain_name)

            domain = self.domain_generator(item.get("victim"), description)
            relation_vi_do = self.relationship_generator(
                domain.get("id"), victim.get("id"), "belongs-to"
            )

            # Fetching IP address of the domain
            resolved_ip = self.ip_fetcher(domain_name)

            ip_object = self.ip_object_creator(resolved_ip)

            if ip_object is not None and ip_object.get("id") is not None:
                relation_do_ip = self.relationship_generator(
                    domain.get("id"), ip_object.get("id"), "resolves-to"
                )
                bundle.append(ip_object)
                bundle.append(relation_do_ip)
                report.get("object_refs").append(ip_object.get("id"))
                report.get("object_refs").append(relation_do_ip.get("id"))

            # self.helper.api.stix_cyber_observable.ask_for_enrichment(domain.get("id"))
            report.get("object_refs").append(domain.get("id"))
            report.get("object_refs").append(relation_vi_do.get("id"))
            bundle.append(domain)
            bundle.append(relation_vi_do)

        elif (
            item.get("domain") != ""
            and not self.is_domain(item.get("victim"))
            and item.get("domain") is not None
        ):

            if self.domain_extractor(item.get("domain")) is not None:

                domain_name = self.domain_extractor(item.get("domain"))

                description = self.fetch_country_domain(domain_name)
                try:
                    domain2 = self.domain_generator(domain_name, description)
                except Exception as e:
                    self.helper.connector_logger.error(
                        "Error creating domain object",
                        {
                            "domain_name": domain_name,
                            "description": description,
                            "error": e,
                        },
                    )

                relation_vi_do2 = self.relationship_generator(
                    domain2.get("id"), victim.get("id"), "belongs-to"
                )
                resolved_ip = self.ip_fetcher(domain_name)

                ip_object = self.ip_object_creator(resolved_ip)

                if ip_object is not None:
                    relation_do_ip2 = self.relationship_generator(
                        domain2.get("id"), ip_object.get("id"), "resolves-to"
                    )
                    bundle.append(ip_object)
                    bundle.append(relation_do_ip2)
                    report.get("object_refs").append(ip_object.get("id"))
                    report.get("object_refs").append(relation_do_ip2.get("id"))

                report.get("object_refs").append(domain2.get("id"))
                report.get("object_refs").append(relation_vi_do2.get("id"))
                bundle.append(domain2)
                bundle.append(relation_vi_do2)

        # Creating Location object
        if (
            item.get("country") != ""
            and item.get("country") is not None
            and len(item.get("country", "Four")) < 4
        ):

            country_name = item.get("country")
            country_stix_id = self.opencti_location_check(country_name)
            location3 = Location(
                id=country_stix_id
                or pycti.Location.generate_id(country_name, "Country"),
                name=country_name,
                country=item.get("country"),
                type="location",
                created_by_ref=self.author.get("id"),
                object_marking_refs=[self.marking.get("id")],
            )
            # If country not yet available, add it in the bundle for creation
            if country_stix_id is None:
                bundle.append(location3)

            location_relation = self.relationship_generator(
                victim.get("id"), location3.get("id"), "located-at"
            )

            relation_is_lo = self.relationship_generator(
                intrusion_set.get("id"),
                location3.get("id"),
                "targets",
                attack_date_iso,
                discovered_iso,
            )
            if self.create_threat_actor:
                relation_TA_LO = self.relationship_generator(
                    threat_actor.get("id"),
                    location3.get("id"),
                    "targets",
                    attack_date_iso,
                    discovered_iso,
                )
                bundle.append(relation_TA_LO)
                report.get("object_refs").append(relation_TA_LO.get("id"))

            bundle.append(relation_is_lo)
            bundle.append(location_relation)

            report.get("object_refs").append(location3.get("id"))
            report.get("object_refs").append(relation_is_lo.get("id"))
            report.get("object_refs").append(location_relation.get("id"))

        bundle.append(report)
        self.helper.connector_logger.info(
            "Sending STIX objects to collect_intelligence.", {"len_bundle": len(bundle)}
        )
        return bundle

    # Collects historic intelligence from ransomware.live
    def collect_historic_intelligence(self):
        """Collects historic intelligence from ransomware.live"""
        base_url = "https://api.ransomware.live/v2/victims/"
        groups_url = "https://api.ransomware.live/v2/groups"
        headers = {"accept": "application/json", "User-Agent": "OpenCTI"}

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
            group_data = []

        current_year = int(dt.date.today().year)
        # Checking if the historic year is less than 2020 as there is no data past 2020
        if int(self.get_historic_year) < 2020:
            year = 2020
        else:
            year = int(self.get_historic_year)

        stix_objects = []
        bundle = []

        for year in range(year, current_year + 1):  # Looping through the years
            year_url = base_url + str(year)
            for month in range(1, 13):  # Looping through the months
                url = year_url + "/" + str(month)
                response = requests.get(url, headers=headers, timeout=(20000, 20000))
                response.raise_for_status()

                try:
                    if response.status_code == 200:
                        response_json = response.json()

                        for item in response_json:

                            try:
                                bundle_list = self.stix_object_generator(
                                    item, group_data
                                )
                            except Exception as e:
                                self.helper.connector_logger.error(
                                    "Error creating STIX objects",
                                    {"victim": item.get("victim"), "error": e},
                                )

                            if bundle_list is None:
                                self.helper.connector_logger.info(
                                    "No new data to process"
                                )

                            else:

                                # Deduplicate the objects
                                bundle_list = self.helper.stix2_deduplicate_objects(
                                    bundle_list
                                )

                                bundle = Bundle(
                                    objects=bundle_list, allow_custom=True
                                ).serialize()

                            if bundle is not None:
                                self.helper.send_stix2_bundle(
                                    bundle=bundle,
                                    work_id=self.work_id,
                                    cleanup_inconsistent_bundle=True,
                                )

                            self.helper.connector_logger.info(
                                "Sending STIX objects to OpenCTI...",
                                {"len_bundle_list": len(bundle_list)},
                            )
                    else:
                        self.helper.connector_logger.info(
                            "Error and response status code",
                            {"status_code": response.status_code},
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
                    return stix_objects

        return None

    def collect_intelligence(self, last_run) -> list:

        url = "https://api.ransomware.live/v2/recentvictims"
        groups_url = "https://api.ransomware.live/v2/groups"
        headers = {"accept": "application/json"}

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
            group_data = []

        # fetching recent requests
        try:
            response = requests.get(url, headers=headers, timeout=(20000, 20000))
            response.raise_for_status()
            if response.status_code == 200:
                response_json = response.json()
                stix_objects = []
                for item in response_json:
                    created = datetime.strptime(
                        item.get("discovered"), "%Y-%m-%d %H:%M:%S.%f"
                    )
                    if last_run is None:
                        time_diff = 1
                    else:
                        time_diff = int(datetime.timestamp(created)) - (
                            int(last_run) - 84600
                        )  # pushing all the data from the last 24 hours
                    if time_diff > 0:
                        bundle_list = self.stix_object_generator(
                            item, group_data
                        )  # calling the stix_object_generator method to create stix objects

                        stix_objects.extend(bundle_list)
                        bundle = None
                        if bundle_list is None:
                            self.helper.connector_logger.info("No new data to process")

                        else:

                            # Deduplicate the objects
                            bundle_list = self.helper.stix2_deduplicate_objects(
                                bundle_list
                            )

                            self.helper.connector_logger.info(
                                "Sending STIX objects to OpenCTI...",
                                {"len_bundle_list": len(bundle_list)},
                            )

                            # Creating Bundle
                            bundle = Bundle(
                                objects=bundle_list, allow_custom=True
                            ).serialize()

                        if bundle is not None:
                            self.helper.send_stix2_bundle(
                                bundle=bundle,
                                work_id=self.work_id,
                                cleanup_inconsistent_bundle=True,
                            )
                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"len_stix_objects": len(stix_objects)},
                )
        except requests.exceptions.HTTPError as err:
            self.helper.connector_logger.error(
                "Http error during collect intelligence", {"error": err, "url": url}
            )
        except Exception as e:
            self.helper.connector_logger.error(
                "Error while collecting intelligence", {"error": e}
            )
        return []

    def _get_interval(self) -> int:
        """Returns the interval to use for the connector

        This SHOULD return always the interval in seconds. If the connector is expecting that the parameter is
        received as hoursUncomment as necessary.
        """
        unit = self.interval[-1:]
        value = self.interval[:-1]

        try:
            if unit == "d":
                # In days:
                return int(value) * 60 * 60 * 24
            if unit == "h":
                # In hours:
                return int(value) * 60 * 60
            if unit == "m":
                # In minutes:
                return int(value) * 60
            if unit == "s":
                # In seconds:
                return int(value)
            raise ValueError(f"Unsupported unit: {unit}")
        except Exception as e:
            self.helper.connector_logger.error(
                "Error when converting RANSOMWARE_INTERVAL environment variable",
                {"interval": self.interval, "error": str(e)},
            )
            raise ValueError(
                f"Error when converting RANSOMWARE_INTERVAL environment variable: '{self.interval}'. {str(e)}"
            ) from e

    def process_message(self) -> None:
        # Main procedure
        self.helper.connector_logger.info(
            "Starting connector...", {"connector_name": self.helper.connect_name}
        )

        try:
            # Get the current timestamp and check
            now = datetime.now(tz=UTC)
            current_state = self.helper.get_state()

            self.last_run = current_state.get("last_run") if current_state else None
            self.last_run_datetime_with_ingested_data = (
                current_state.get("last_run_datetime_with_ingested_data")
                if current_state
                else None
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Starting connector...",
                {
                    "connector_name": self.helper.connect_name,
                    "connector_start_time": now.isoformat(sep=" ", timespec="seconds"),
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

            # friendly_name will be display on OpenCTI platform
            friendly_name = "RansomwareLive"

            # Initiate new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "Running connector...", {"connector_name": self.helper.connect_name}
            )

            # Perform the collect of intelligence
            try:

                if not self.last_run and self.get_historic:
                    bundle_objects = self.collect_historic_intelligence()
                else:
                    bundle_objects = self.collect_intelligence(self.last_run)

                # Deduplicate the objects
                if bundle_objects is not None and len(bundle_objects) > 0:
                    bundle_objects = self.helper.stix2_deduplicate_objects(
                        bundle_objects
                    )
            except Exception as e:
                self.helper.connector_logger.error(
                    "Error during bundle creation", {"error": e}
                )

            # Create and send bundle
            try:
                if bundle_objects is not None and len(bundle_objects) > 0:
                    bundle = self.helper.stix2_create_bundle(bundle_objects)
                    bundles_sent = self.helper.send_stix2_bundle(
                        bundle=bundle, work_id=work_id, cleanup_inconsistent_bundle=True
                    )
                    self.last_run_datetime_with_ingested_data = datetime.now(
                        tz=UTC
                    ).isoformat(timespec="seconds")
                    self.helper.connector_logger.info(
                        "Sending STIX objects to OpenCTI...",
                        {"length_bundle_sent": len(bundles_sent)},
                    )
            except Exception as e:
                self.helper.connector_logger.error(
                    "Error sending STIX2 bundle to OpenCTI", {"error": e}
                )

            # Store the current timestamp as a last run
            self.helper.connector_logger.debug(
                "Getting current state and update it with last_run",
                {"current_state": self.last_run, "new_last_run": now.timestamp()},
            )

            if self.last_run:
                current_state["last_run"] = now.isoformat(sep=" ", timespec="seconds")
            else:
                current_state = {"last_run": now.isoformat(sep=" ", timespec="seconds")}

            if self.last_run_datetime_with_ingested_data:
                current_state["last_run_datetime_with_ingested_data"] = (
                    self.last_run_datetime_with_ingested_data
                )

            self.helper.set_state(current_state)

            message = "Connector successfully run, storing last_run as" + now.isoformat(
                sep=" ", timespec="seconds"
            )
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)
            self.work_id = None

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "Connector stopped", {"connector_name": self.helper.connect_name}
            )
            sys.exit(0)
        except Exception as e:
            self.helper.connector_logger.error("Connector error on run", {"error": e})

    def run(self):
        if self.duration_period:
            self.helper.schedule_iso(
                message_callback=self.process_message,
                duration_period=self.duration_period,
            )
        else:
            self.helper.schedule_unit(
                message_callback=self.process_message,
                duration_period=self.interval,
                time_unit=self.helper.TimeUnit.DAYS,
            )
