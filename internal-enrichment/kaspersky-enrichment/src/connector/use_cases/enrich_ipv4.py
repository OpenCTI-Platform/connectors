from datetime import datetime, timedelta

from connector.constants import DATETIME_FORMAT
from connector.converter_to_stix import ConverterToStix
from connector.utils import (
    is_last_seen_equal_to_first_seen,
    is_quota_exceeded,
    string_to_datetime,
)
from kaspersky_client import KasperskyClient
from pycti import STIX_EXT_OCTI_SCO, OpenCTIConnectorHelper, OpenCTIStix2


class Ipv4Enricher:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client: KasperskyClient,
        sections: str,
        zone_octi_score_mapping: dict,
        converter_to_stix: ConverterToStix,
    ):
        self.helper = helper
        self.client = client
        self.sections = sections
        self.zone_octi_score_mapping = zone_octi_score_mapping
        self.converter_to_stix = converter_to_stix

    def process_ipv4_enrichment(self, observable: dict) -> list:
        """
        Collect intelligence from the source for an IPV4 type
        """
        octi_objects = []
        observable_to_ref = self.converter_to_stix.create_reference(
            obs_id=observable["id"]
        )
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")

        # Retrieve ipv4
        obs_ipv4 = observable["value"]

        # Get entity data from api client
        entity_data = self.client.get_ipv4_info(obs_ipv4, self.sections)

        # Check Quota
        if is_quota_exceeded(entity_data["LicenseInfo"]):
            self.helper.connector_logger.warning(
                "[CONNECTOR] The daily quota has been exceeded",
                {
                    "day_requests": entity_data["LicenseInfo"]["DayRequests"],
                    "day_quota": entity_data["LicenseInfo"]["DayQuota"],
                },
            )

        # Prepare author object
        author = self.converter_to_stix.create_author()
        octi_objects.append(author.to_stix2_object())

        # Prepare TLPMarkings
        tlp_clear = self.converter_to_stix.create_tlp_marking("clear")
        octi_objects.append(tlp_clear.to_stix2_object())
        tlp_amber = self.converter_to_stix.create_tlp_marking("amber")
        octi_objects.append(tlp_amber.to_stix2_object())

        # Manage IpGeneralInfo data

        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from IpGeneralInfo data..."
        )

        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from IpGeneralInfo data..."
        )
        entity_general_info = entity_data["IpGeneralInfo"]

        # Score
        if entity_data.get("Zone"):
            score = self.zone_octi_score_mapping[entity_data["Zone"].lower()]
            observable = OpenCTIStix2.put_attribute_in_extension(
                observable, STIX_EXT_OCTI_SCO, "score", score
            )

        # Labels
        if entity_general_info.get("Categories"):
            observable["labels"] = observable.get("x_opencti_labels", [])
            for label in entity_general_info["Categories"]:
                pretty_label = label.replace("CATEGORY_", "").replace("_", "")
                if pretty_label not in observable["labels"]:
                    observable["labels"].append(pretty_label)

        # Country
        if entity_general_info.get("CountryCode"):
            obs_country = self.converter_to_stix.create_country(
                entity_general_info["CountryCode"]
            )

            if obs_country:
                octi_objects.append(obs_country.to_stix2_object())
                country_relation = self.converter_to_stix.create_relationship(
                    source_obj=observable_to_ref,
                    relationship_type="located-at",
                    target_obj=obs_country,
                )
                octi_objects.append(country_relation.to_stix2_object())

        # Manage FilesDownloadedFromIp data

        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from FilesDownloadedFromIp data..."
        )

        if entity_data.get("FilesDownloadedFromIp"):
            for file in entity_data["FilesDownloadedFromIp"]:
                obs_file = self.converter_to_stix.create_file(
                    hashes={"MD5": file["Md5"]},
                    score=self.zone_octi_score_mapping[file["Zone"].lower()],
                )

                if obs_file:
                    octi_objects.append(obs_file.to_stix2_object())
                    file_first_seen_datetime, file_last_seen_datetime = (
                        self.get_first_and_last_seen_datetime(
                            file["FirstSeen"], file["LastSeen"]
                        )
                    )
                    file_relation = self.converter_to_stix.create_relationship(
                        relationship_type="related-to",
                        source_obj=observable_to_ref,
                        target_obj=obs_file,
                        start_time=file_first_seen_datetime,
                        stop_time=file_last_seen_datetime,
                    )
                    octi_objects.append(file_relation.to_stix2_object())

        # Manage HostedUrls data

        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from HostedUrls data..."
        )

        if entity_data.get("HostedUrls"):
            for url_entity in entity_data["HostedUrls"]:
                obs_url = self.converter_to_stix.create_url(
                    url_info=url_entity,
                    obs_url_score=self.zone_octi_score_mapping[
                        url_entity["Zone"].lower()
                    ],
                )

                if obs_url:
                    octi_objects.append(obs_url.to_stix2_object())
                    url_first_seen_datetime, url_last_seen_datetime = (
                        self.get_first_and_last_seen_datetime(
                            url_entity["FirstSeen"], url_entity["LastSeen"]
                        )
                    )
                    url_relation = self.converter_to_stix.create_relationship(
                        relationship_type="related-to",
                        source_obj=observable_to_ref,
                        target_obj=obs_url,
                        start_time=url_first_seen_datetime,
                        stop_time=url_last_seen_datetime,
                    )
                    octi_objects.append(url_relation.to_stix2_object())

        # Manage IpWhoIs data

        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from IpWhoIs data..."
        )

        if entity_data.get("IpWhoIs") and entity_data["IpWhoIs"].get("Asn"):
            asn_entities = entity_data["IpWhoIs"]["Asn"]
            for asn_entity in asn_entities:
                obs_asn = self.converter_to_stix.create_autonomous_system(
                    number=asn_entity["Number"]
                )

                if obs_asn:
                    octi_objects.append(obs_asn.to_stix2_object())
                    asn_relation = self.converter_to_stix.create_relationship(
                        source_obj=observable_to_ref,
                        relationship_type="belongs-to",
                        target_obj=obs_asn,
                    )
                    octi_objects.append(asn_relation.to_stix2_object())

        # Manage IpDnsResolutions

        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from IpDnsResolutions data..."
        )

        if entity_data.get("IpDnsResolutions"):
            for resolution in entity_data["IpDnsResolutions"]:
                obs_domain = self.converter_to_stix.create_domain(
                    name=resolution["Domain"],
                    score=self.zone_octi_score_mapping[resolution["Zone"].lower()],
                )

                if obs_domain:
                    octi_objects.append(obs_domain.to_stix2_object())
                    domain_first_seen_datetime, domain_last_seen_datetime = (
                        self.get_first_and_last_seen_datetime(
                            resolution["FirstSeen"], resolution["LastSeen"]
                        )
                    )
                    domain_relation = self.converter_to_stix.create_relationship(
                        relationship_type="resolves-to",
                        source_obj=obs_domain,
                        target_obj=observable_to_ref,
                        start_time=domain_first_seen_datetime,
                        stop_time=domain_last_seen_datetime,
                    )
                    octi_objects.append(domain_relation.to_stix2_object())

        # Manage Industries data

        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from Industries data..."
        )

        if entity_data.get("Industries"):
            for industry in entity_data["Industries"]:
                industry_object = self.converter_to_stix.create_sector(industry)

                if industry_object:
                    octi_objects.append(industry_object.to_stix2_object())
                    industry_relation = self.converter_to_stix.create_relationship(
                        relationship_type="related-to",
                        source_obj=observable_to_ref,
                        target_obj=industry_object,
                    )
                    octi_objects.append(industry_relation.to_stix2_object())

        return octi_objects

    def get_first_and_last_seen_datetime(
        self, first_seen: str, last_seen: str
    ) -> datetime:
        """
        Convert first and last seen string to datetime.
        If last==first, add one minute to last seen value.
        """
        first_seen_datetime = string_to_datetime(first_seen, DATETIME_FORMAT)
        last_seen_datetime = string_to_datetime(last_seen, DATETIME_FORMAT)
        if is_last_seen_equal_to_first_seen(first_seen_datetime, last_seen_datetime):
            last_seen_datetime = last_seen_datetime + timedelta(minutes=1)

        return first_seen_datetime, last_seen_datetime
