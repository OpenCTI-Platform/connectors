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


class DomainEnricher:
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

    def process_domain_enrichment(self, observable: dict) -> list:
        """
        Collect intelligence from the source for a Domain-Name/Hostname type
        """
        octi_objects = []
        observable_to_ref = self.converter_to_stix.create_reference(
            obs_id=observable["id"]
        )
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")

        # Retrieve domain
        obs_domain = observable["value"]

        # Get entity data from api client
        entity_data = self.client.get_domain_info(obs_domain, self.sections)

        # Check Quota
        if is_quota_exceeded(entity_data["LicenseInfo"]):
            self.helper.connector_logger.warning(
                "[CONNECTOR] The daily quota has been exceeded",
                {
                    "day_requests": entity_data["LicenseInfo"]["DayRequests"],
                    "day_quota": entity_data["LicenseInfo"]["DayQuota"],
                },
            )

        # Manage DomainGeneralInfo data

        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from DomainGeneralInfo data..."
        )
        entity_general_info = entity_data["DomainGeneralInfo"]

        # Labels
        if entity_general_info.get("Categories"):
            observable["labels"] = observable.get("x_opencti_labels", [])
            for label in entity_general_info["Categories"]:
                pretty_label = label.replace("CATEGORY_", "").replace("_", " ")
                if pretty_label not in observable["labels"]:
                    observable["labels"].append(pretty_label)

        # Manage Zone data

        if entity_data.get("Zone"):
            score = self.zone_octi_score_mapping[entity_data["Zone"].lower()]
            observable = OpenCTIStix2.put_attribute_in_extension(
                observable, STIX_EXT_OCTI_SCO, "score", score
            )

        # Manage DomainDnsResolutions

        if entity_data.get("DomainDnsResolutions"):
            ipv4_entities = entity_data["DomainDnsResolutions"]
            for ipv4_entity in ipv4_entities:
                obs_ipv4 = self.converter_to_stix.create_ipv4(ipv4_entity["Ip"])

                if obs_ipv4:
                    octi_objects.append(obs_ipv4.to_stix2_object())
                    ipv4_relation = self.converter_to_stix.create_relationship(
                        source_obj=observable_to_ref,
                        relationship_type="resolves-to",
                        target_obj=obs_ipv4,
                    )
                    octi_objects.append(ipv4_relation.to_stix2_object())

        # Manage FilesDownloaded

        if entity_data.get("FilesDownloaded"):
            files_downloaded = entity_data["FilesDownloaded"]
            for file_downloaded_entity in files_downloaded:
                # Create File object and relation
                obs_file = self.converter_to_stix.create_file(
                    hashes={"MD5": file_downloaded_entity["Md5"]},
                    score=self.zone_octi_score_mapping[
                        file_downloaded_entity["Zone"].lower()
                    ],
                )

                if obs_file:
                    octi_objects.append(obs_file.to_stix2_object())
                    file_first_seen_datetime, file_last_seen_datetime = (
                        self.get_first_and_last_seen_datetime(
                            file_downloaded_entity["FirstSeen"],
                            file_downloaded_entity["LastSeen"],
                        )
                    )
                    file_relation = self.converter_to_stix.create_relationship(
                        source_obj=observable_to_ref,
                        relationship_type="related-to",
                        target_obj=obs_file,
                        start_time=file_first_seen_datetime,
                        stop_time=file_last_seen_datetime,
                    )
                    octi_objects.append(file_relation.to_stix2_object())

                # Create Url object and relation
                obs_url = self.converter_to_stix.create_url(
                    url_info=file_downloaded_entity,
                    obs_url_score=self.zone_octi_score_mapping[
                        file_downloaded_entity["Zone"].lower()
                    ],
                )

                if obs_url:
                    octi_objects.append(obs_url.to_stix2_object())
                    file_first_seen_datetime, file_last_seen_datetime = (
                        self.get_first_and_last_seen_datetime(
                            file_downloaded_entity["FirstSeen"],
                            file_downloaded_entity["LastSeen"],
                        )
                    )
                    file_relation = self.converter_to_stix.create_relationship(
                        source_obj=observable_to_ref,
                        relationship_type="related-to",
                        target_obj=obs_url,
                        start_time=file_first_seen_datetime,
                        stop_time=file_last_seen_datetime,
                    )
                    octi_objects.append(file_relation.to_stix2_object())

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
