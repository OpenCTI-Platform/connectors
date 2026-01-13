import logging

from connector.converter_to_stix import ConverterToStix
from connector.use_cases.common import BaseUseCases
from connector.utils import get_first_and_last_seen_datetime
from kaspersky_client import KasperskyClient


class DomainEnricher(BaseUseCases):
    def __init__(
        self,
        connector_logger: logging.Logger,
        client: KasperskyClient,
        sections: str,
        zone_octi_score_mapping: dict,
        converter_to_stix: ConverterToStix,
    ):
        BaseUseCases.__init__(self, connector_logger, converter_to_stix)
        self.connector_logger = connector_logger
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
        self.connector_logger.info(
            "[ENRICH DOMAIN] Starting enrichment...",
            {"observable_id": observable["id"]},
        )

        # Retrieve domain
        obs_domain = observable["value"]

        # Get entity data from api client
        entity_data = self.client.get_data("domain", obs_domain, self.sections)

        # Check Quota
        self.check_quota(entity_data["LicenseInfo"])

        # Create and add author, TLP clear and TLP amber to octi_objects
        octi_objects.extend(self.generate_author_and_tlp_markings())

        # Manage DomainGeneralInfo data

        self.connector_logger.info(
            "[ENRICH DOMAIN] Process enrichment from DomainGeneralInfo data...",
            {"observable_id": observable["id"]},
        )

        # Score
        if entity_data.get("Zone"):
            observable = self.update_observable_score(entity_data["Zone"], observable)

        entity_general_info = entity_data["DomainGeneralInfo"]

        # Labels
        if entity_general_info.get("Categories"):
            observable["labels"] = observable.get("x_opencti_labels", [])
            for label in entity_general_info["Categories"]:
                pretty_label = label.replace("CATEGORY_", "").replace("_", " ")
                if pretty_label not in observable["labels"]:
                    observable["labels"].append(pretty_label)

        # Manage DomainDnsResolutions

        if entity_data.get("DomainDnsResolutions"):
            self.connector_logger.info(
                "[ENRICH DOMAIN] Process enrichment from DomainDnsResolutions data...",
                {"observable_id": observable["id"]},
            )

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
            self.connector_logger.info(
                "[ENRICH DOMAIN] Process enrichment from FilesDownloaded data...",
                {"observable_id": observable["id"]},
            )
            files_downloaded = entity_data["FilesDownloaded"]

            # Create File object and relation
            octi_objects.extend(self.manage_files(files_downloaded, observable_to_ref))

            # Create Url object and relation
            for file_downloaded_entity in files_downloaded:

                obs_url = self.converter_to_stix.create_url(
                    obs_url_score=self.zone_octi_score_mapping[
                        file_downloaded_entity["Zone"].lower()
                    ],
                    url_info=file_downloaded_entity["Url"],
                )

                if obs_url:
                    octi_objects.append(obs_url.to_stix2_object())
                    file_first_seen_datetime, file_last_seen_datetime = (
                        get_first_and_last_seen_datetime(
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

        # Manage FilesAccessed

        if entity_data.get("FilesAccessed"):
            self.connector_logger.info(
                "[ENRICH DOMAIN] Process enrichment from FilesAccessed data...",
                {"observable_id": observable["id"]},
            )

            files_accessed = entity_data["FilesAccessed"]
            for file_accessed in files_accessed:
                obs_file_accessed = self.converter_to_stix.create_file(
                    hashes={"MD5": file_accessed["Md5"]},
                    score=self.zone_octi_score_mapping[file_accessed["Zone"].lower()],
                )

                if obs_file_accessed:
                    octi_objects.append(obs_file_accessed.to_stix2_object())
                    file_first_seen_datetime, file_last_seen_datetime = (
                        get_first_and_last_seen_datetime(
                            file_accessed["FirstSeen"],
                            file_accessed["LastSeen"],
                        )
                    )
                    relation_type = (
                        "communicates-with"
                        if observable["x_opencti_type"] == "Domain-Name"
                        else "related-to"
                    )
                    file_accessed_relation = self.converter_to_stix.create_relationship(
                        source_obj=obs_file_accessed,
                        relationship_type=relation_type,
                        target_obj=observable_to_ref,
                        start_time=file_first_seen_datetime,
                        stop_time=file_last_seen_datetime,
                    )
                    octi_objects.append(file_accessed_relation.to_stix2_object())

        # Manage Industries data

        if entity_data.get("Industries"):
            octi_objects.extend(
                self.manage_industries(observable_to_ref, entity_data["Industries"])
            )

        return octi_objects
