import logging

from connector.converter_to_stix import ConverterToStix
from connector.use_cases.common import BaseUseCases
from kaspersky_client import KasperskyClient


class UrlEnricher(BaseUseCases):
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

    def process_url_enrichment(self, observable: dict) -> list:
        """
        Collect intelligence from the source for an URL type
        """
        octi_objects = []
        observable_to_ref = self.converter_to_stix.create_reference(
            obs_id=observable["id"]
        )
        self.connector_logger.info(
            "[ENRICH URL] Starting enrichment...",
            {"observable_id": observable["id"]},
        )

        # Retrieve url
        obs_url = (
            observable["value"]
            if observable["value"].startswith("http")
            else "http://" + observable["value"]
        )

        # Get entity data from api client
        entity_data = self.client.get_data("url", obs_url, self.sections)

        # Check Quota
        self.check_quota(entity_data["LicenseInfo"])

        # Create and add author, TLP clear and TLP amber to octi_objects
        octi_objects.append(self.generate_author_and_tlp_markings())

        # Manage UrlGeneralInfo data

        self.connector_logger.info(
            "[ENRICH URL] Process enrichment from UrlGeneralInfo data...",
            {"observable_id": observable["id"]},
        )

        # Score
        if entity_data.get("Zone"):
            observable = self.update_observable_score(entity_data["Zone"], observable)

        entity_general_info = entity_data["UrlGeneralInfo"]

        if entity_general_info.get("Categories"):
            # Labels
            observable["labels"] = observable.get("x_opencti_labels", [])
            for label in entity_general_info["Categories"]:
                pretty_label = label.replace("CATEGORY_", "").replace("_", " ")
                if pretty_label not in observable["labels"]:
                    observable["labels"].append(pretty_label)

            # Host
            if entity_general_info.get("Host"):
                domain_object = self.converter_to_stix.create_domain(
                    name=entity_general_info["Host"]
                )
                if domain_object:
                    octi_objects.append(domain_object.to_stix2_object())
                    domain_relation = self.converter_to_stix.create_relationship(
                        relationship_type="related-to",
                        source_obj=observable_to_ref,
                        target_obj=domain_object,
                    )
                    octi_objects.append(domain_relation.to_stix2_object())

        # Manage FilesDownloaded data

        if entity_data.get("FilesDownloaded"):
            self.connector_logger.info(
                "[ENRICH URL] Process enrichment from FilesDownloaded data...",
                {"observable_id": observable["id"]},
            )
            octi_objects.append(
                self.manage_files(entity_data["FilesDownloaded"], observable_to_ref)
            )

        # Manage FilesAccessed data

        if entity_data.get("FilesAccessed"):
            self.connector_logger.info(
                "[ENRICH URL] Process enrichment from FilesAccessed data...",
                {"observable_id": observable["id"]},
            )
            octi_objects.append(
                self.manage_files(entity_data["FilesAccessed"], observable_to_ref)
            )

        # Manage Industries data

        if entity_data.get("Industries"):
            octi_objects.append(
                self.manage_industries(observable_to_ref, entity_data["Industries"])
            )

        return octi_objects
