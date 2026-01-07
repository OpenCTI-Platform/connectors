from connector.converter_to_stix import ConverterToStix
from connector.use_cases.common import BaseUseCases
from connector.utils import resolve_file_hash
from kaspersky_client import KasperskyClient
from pycti import OpenCTIConnectorHelper


class FileEnricher(BaseUseCases):
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

    def process_file_enrichment(self, observable: dict) -> list:
        """
        Collect intelligence from the source for a File type
        """
        octi_objects = []
        observable_to_ref = self.converter_to_stix.create_reference(
            obs_id=observable["id"]
        )
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")

        # Retrieve file hash
        obs_hash = resolve_file_hash(observable)

        # Get entity data from api client
        entity_data = self.client.get_file_info(obs_hash, self.sections)

        # Check Quota
        self.check_quota(entity_data["LicenseInfo"])

        # Create and add author, TLP clear and TLP amber to octi_objects
        octi_objects += self.generate_author_and_tlp_markings()

        # Manage FileGeneralInfo data

        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from FileGeneralInfo data..."
        )

        # Score
        if entity_data.get("Zone"):
            observable = self.update_observable_score(entity_data["Zone"], observable)

        entity_file_general_info = entity_data["FileGeneralInfo"]

        # Hashes
        if entity_file_general_info.get("Md5"):
            observable["hashes"]["MD5"] = entity_file_general_info["Md5"]
        if entity_file_general_info.get("Sha1"):
            observable["hashes"]["SHA-1"] = entity_file_general_info["Sha1"]
        if entity_file_general_info.get("Sha256"):
            observable["hashes"]["SHA-256"] = entity_file_general_info["Sha256"]

        # Size, mime_type
        mapping_fields = {"Size": "size", "Type": "mime_type"}
        for key, value in mapping_fields.items():
            if entity_file_general_info.get(key):
                observable[value] = entity_file_general_info[key]

        # Labels
        if entity_file_general_info.get("Categories"):
            observable["labels"] = observable.get("x_opencti_labels", [])
            for label in entity_file_general_info["Categories"]:
                pretty_label = label.replace("CATEGORY_", "").replace("_", "")
                if pretty_label not in observable["labels"]:
                    observable["labels"].append(pretty_label)

        # Manage FileNames data

        if entity_data.get("FileNames"):
            self.helper.connector_logger.info(
                "[CONNECTOR] Process enrichment from FileNames data..."
            )

            observable["additional_names"] = observable.get(
                "x_opencti_additional_names", []
            )
            for filename in entity_data["FileNames"]:
                if filename["FileName"] not in observable["additional_names"]:
                    observable["additional_names"].append(filename["FileName"])

        # Manage DetectionsInfo data

        if entity_data.get("DetectionsInfo"):
            self.helper.connector_logger.info(
                "[CONNECTOR] Process enrichment from DetectionsInfo data..."
            )

            content = "| Detection Date | Detection Name | Detection Method |\n"
            content += "|----------------|----------------|------------------|\n"

            for obs_detection_info in entity_data["DetectionsInfo"]:
                detection_name = f"[{obs_detection_info["DetectionName"]}]({obs_detection_info["DescriptionUrl"]})"
                content += f"| {obs_detection_info["LastDetectDate"]} | {detection_name} | {obs_detection_info["DetectionMethod"]} |\n"

            obs_note = self.converter_to_stix.create_note(observable_to_ref, content)
            octi_objects.append(obs_note.to_stix2_object())

        # Manage FileDownloadedFromUrls data

        if entity_data.get("FileDownloadedFromUrls"):
            self.helper.connector_logger.info(
                "[CONNECTOR] Process enrichment from FileDownloadedFromUrls data..."
            )

            for url_info in entity_data["FileDownloadedFromUrls"]:
                obs_url_score = self.zone_octi_score_mapping[url_info["Zone"].lower()]
                url_object = self.converter_to_stix.create_url(
                    obs_url_score, url_info["Url"]
                )

                if url_object:
                    octi_objects.append(url_object.to_stix2_object())
                    url_relation = self.converter_to_stix.create_relationship(
                        relationship_type="related-to",
                        source_obj=observable_to_ref,
                        target_obj=url_object,
                    )
                    octi_objects.append(url_relation.to_stix2_object())

        # Manage Industries data

        if entity_data.get("Industries"):
            octi_objects += self.manage_industries(
                observable_to_ref, entity_data["Industries"]
            )

        return octi_objects
