from connector.converter_to_stix import ConverterToStix
from connector.utils import check_quota, resolve_file_hash
from kaspersky_client import KasperskyClient
from pycti import STIX_EXT_OCTI_SCO, OpenCTIConnectorHelper, OpenCTIStix2


class FileEnricher:
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

    def process_file_enrichment(self, observable: dict) -> list:
        """
        Collect intelligence from the source for a File type
        """
        octi_objects = []
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")

        # Retrieve file hash
        obs_hash = resolve_file_hash(observable)

        # Get entity data from api client
        entity_data = self.client.get_file_info(obs_hash, self.sections)

        # Check Quota
        if check_quota(entity_data["LicenseInfo"]):
            self.helper.connector_logger.warning(
                "[CONNECTOR] The daily quota has been exceeded",
                {
                    "day_requests": entity_data["LicenseInfo"]["DayRequests"],
                    "day_quota": entity_data["LicenseInfo"]["DayQuota"],
                },
            )

        # Manage FileGeneralInfo data

        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from FileGeneralInfo data..."
        )

        entity_file_general_info = entity_data["FileGeneralInfo"]

        # Score
        if entity_data.get("Zone"):
            score = self.zone_octi_score_mapping[entity_data["Zone"].lower()]
            OpenCTIStix2.put_attribute_in_extension(
                observable, STIX_EXT_OCTI_SCO, "score", score
            )

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
            observable["labels"] = []
            if observable.get("x_opencti_labels"):
                observable["labels"] = observable["x_opencti_labels"]
            for label in entity_file_general_info["Categories"]:
                if label not in observable["labels"]:
                    observable["labels"].append(label)

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
                    observable["additional_names"].append(f" {filename["FileName"]}")
                else:
                    observable["additional_names"] = filename["FileName"]

        # Prepare author object
        author = self.converter_to_stix.create_author()
        octi_objects.append(author.to_stix2_object())

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

            obs_note = self.converter_to_stix.create_file_note(
                observable["id"], content
            )
            octi_objects.append(obs_note.to_stix2_object())

        # Manage FileDownloadedFromUrls data

        if entity_data.get("FileDownloadedFromUrls"):
            self.helper.connector_logger.info(
                "[CONNECTOR] Process enrichment from FileDownloadedFromUrls data..."
            )

            for url_info in entity_data["FileDownloadedFromUrls"]:
                obs_url_score = self.zone_octi_score_mapping[url_info["Zone"].lower()]
                url_object = self.converter_to_stix.create_url(obs_url_score, url_info)

                if url_object:
                    octi_objects.append(url_object.to_stix2_object())
                    url_relation = self.converter_to_stix.create_relationship(
                        source=observable["id"],
                        relationship_type="related-to",
                        target=url_object.id,
                    )
                    octi_objects.append(url_relation.to_stix2_object())

        # Manage Industries data

        if entity_data.get("Industries"):
            self.helper.connector_logger.info(
                "[CONNECTOR] Process enrichment from Industries data..."
            )

            for industry in entity_data["Industries"]:
                industry_object = self.converter_to_stix.create_sector(industry)

                if industry_object:
                    octi_objects.append(industry_object.to_stix2_object())
                    industry_relation = self.converter_to_stix.create_relationship(
                        source=observable["id"],
                        relationship_type="related-to",
                        target=industry_object.id,
                    )
                    octi_objects.append(industry_relation.to_stix2_object())

        return octi_objects
