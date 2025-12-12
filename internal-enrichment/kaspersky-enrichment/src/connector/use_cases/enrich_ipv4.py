from connector.constants import DATETIME_FORMAT
from connector.converter_to_stix import ConverterToStix
from connector.utils import check_quota, string_to_datetime
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
        if check_quota(entity_data["LicenseInfo"]):
            self.helper.connector_logger.warning(
                "[CONNECTOR] The daily quota has been exceeded",
                {
                    "day_requests": entity_data["LicenseInfo"]["DayRequests"],
                    "day_quota": entity_data["LicenseInfo"]["DayQuota"],
                },
            )

        # Manage IpGeneralInfo data

        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from IpGeneralInfo data..."
        )
        entity_general_info = entity_data["IpGeneralInfo"]

        # Score
        if entity_data.get("Zone"):
            score = self.zone_octi_score_mapping[entity_data["Zone"].lower()]
            OpenCTIStix2.put_attribute_in_extension(
                observable, STIX_EXT_OCTI_SCO, "score", score
            )

        # Labels
        if entity_general_info.get("Categories"):
            observable["labels"] = []
            if observable.get("x_opencti_labels"):
                observable["labels"] = observable["x_opencti_labels"]
            for label in entity_general_info["Categories"]:
                if label not in observable["labels"]:
                    observable["labels"].append(label)

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
                    first_seen_datetime = string_to_datetime(
                        file["FirstSeen"], DATETIME_FORMAT
                    )
                    last_seen_datetime = string_to_datetime(
                        file["LastSeen"], DATETIME_FORMAT
                    )
                    file_relation = self.converter_to_stix.create_relationship(
                        relationship_type="related-to",
                        source_obj=observable_to_ref,
                        target_obj=obs_file,
                        start_time=first_seen_datetime,
                        stop_time=last_seen_datetime,
                    )
                    octi_objects.append(file_relation.to_stix2_object())

        # Manage HostedUrls data

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
                    url_first_seen_datetime = string_to_datetime(
                        url_entity["FirstSeen"], DATETIME_FORMAT
                    )
                    url_last_seen_datetime = string_to_datetime(
                        url_entity["LastSeen"], DATETIME_FORMAT
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

        return octi_objects
