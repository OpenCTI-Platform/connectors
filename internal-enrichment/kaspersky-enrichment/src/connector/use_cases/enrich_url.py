from connector.converter_to_stix import ConverterToStix
from connector.use_cases.common import BaseUseCases
from connector.utils import get_first_and_last_seen_datetime
from kaspersky_client import KasperskyClient
from pycti import OpenCTIConnectorHelper


class UrlEnricher(BaseUseCases):
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client: KasperskyClient,
        sections: str,
        zone_octi_score_mapping: dict,
        converter_to_stix: ConverterToStix,
    ):
        BaseUseCases.__init__(self, helper, converter_to_stix)
        self.helper = helper
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
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")

        # Retrieve domain
        obs_domain = observable["value"]

        # Get entity data from api client
        entity_data = self.client.get_url_info(obs_domain, self.sections)

        # Check Quota
        self.check_quota(entity_data["LicenseInfo"])

        # Create and add author, TLP clear and TLP amber to octi_objects
        octi_objects += self.generate_author_and_tlp_markings()

        # Manage UrlGeneralInfo data

        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from UrlGeneralInfo data..."
        )

        # Score
        if entity_data.get("Zone"):
            observable = self.update_observable_score(entity_data["Zone"], observable)

        entity_general_info = entity_data["UrlGeneralInfo"]

        if entity_general_info.get("Categories"):
            # Labels
            observable["labels"] = observable.get("x_opencti_labels", [])
            for label in entity_general_info["Categories"]:
                pretty_label = label.replace("CATEGORY_", "").replace("_", "")
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

        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from FilesDownloaded data..."
        )

        if entity_data.get("FilesDownloaded"):
            files_downloaded = entity_data["FilesDownloaded"]
            for file_downloaded_entity in files_downloaded:
                obs_file = self.converter_to_stix.create_file(
                    hashes={"MD5": file_downloaded_entity["Md5"]},
                    score=self.zone_octi_score_mapping[
                        file_downloaded_entity["Zone"].lower()
                    ],
                )

                if obs_file:
                    octi_objects.append(obs_file.to_stix2_object())
                    file_first_seen_datetime, file_last_seen_datetime = (
                        get_first_and_last_seen_datetime(
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

        return octi_objects
