import base64
import re
import urllib.parse
from typing import Dict, List, Mapping, Optional
from urllib.parse import urlparse

import requests
import stix2
from pycti import MarkingDefinition, OpenCTIConnectorHelper, get_config_variable

from .config_variables import ConfigConnector

ALLOWED_TLPS = {
    "tlp:clear",
    "tlp:white",
    "tlp:green",
    "tlp:amber",
    "tlp:amber+strict",
    "tlp:red",
}


def create_tlp_marking(tlp_value: str) -> stix2.MarkingDefinition:
    tlp_value_lower = tlp_value.lower()

    if tlp_value_lower == "tlp:clear" or tlp_value_lower == "tlp:white":
        return stix2.TLP_WHITE
    if tlp_value_lower == "tlp:green":
        return stix2.TLP_GREEN
    if tlp_value_lower == "tlp:amber":
        return stix2.TLP_AMBER
    if tlp_value_lower == "tlp:amber+strict":
        return stix2.MarkingDefinition(
            id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
            definition_type="statement",
            definition={"statement": "custom"},
            allow_custom=True,
            x_opencti_definition_type="TLP",
            x_opencti_definition="TLP:AMBER+STRICT",
        )
    if tlp_value_lower == "tlp:red":
        return stix2.TLP_RED

    raise ValueError(f"unknown TLP value {tlp_value}")


class EsetConnector:
    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """
        config = ConfigConnector()

        self.max_tlp = config.max_tlp
        self.eset_api_key = get_config_variable(
            "ESET_API_KEY", ["eset", "api_key"], config.load
        )
        self.eset_api_secret = get_config_variable(
            "ESET_API_SECRET", ["eset", "api_secret"], config.load
        )
        self.host = get_config_variable(
            "ESET_API_HOST",
            ["eset", "api_host"],
            config.load,
            default="https://eti.eset.com/",
        )
        # playbook_compatible=True only if a bundle is sent !
        self.helper = OpenCTIConnectorHelper(
            config=config.load, playbook_compatible=True
        )

    def entity_in_scope(self, data) -> bool:
        """
        Security to limit playbook triggers to something other than the initial scope
        :param data: Dictionary of data
        :return: boolean
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_split = data["entity_id"].split("--")
        entity_type = entity_split[0].lower()

        if entity_type in scopes:
            return True
        else:
            return False

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        """
        Extract TLP, and we check if the variable "max_tlp" is less than
        or equal to the markings access of the entity from OpenCTI
        If this is true, we can send the data to connector for enrichment.
        :param opencti_entity: Dict of observable from OpenCTI
        :return: Boolean
        """
        tlp = "TLP:CLEAR"

        if len(opencti_entity["objectMarking"]) != 0:
            for marking_definition in opencti_entity["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    tlp = marking_definition["definition"]

        valid_max_tlp = self.helper.check_max_tlp(tlp, self.max_tlp)

        if not valid_max_tlp:
            raise ValueError(
                "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
                "the connector does not has access to this observable, please check the group of the connector user"
            )

    P_ETI_PORTAL_URL = re.compile(
        r"^https://(?:www)?(?:[a-zA-Z0-9-.]+)?eset\.com/reports/apt/(?P<report_uid>[0-9a-f-]+)/download$"
    )

    def _get_eti_api_url(self, objects: list) -> None | str:
        for o in objects:
            if o["entity_type"].lower() != "text":
                continue

            value = o.get("observable_value")
            if not value:
                continue

            match = self.P_ETI_PORTAL_URL.match(value)
            if match is None:
                continue

            parts = urlparse(value)
            if not parts.netloc or not parts.netloc.lower().endswith("eset.com"):
                continue

            return urllib.parse.urljoin(
                self.host,
                f"api/v2/apt-reports/{match.group('report_uid')}/download/pdf",
            )

        return None

    def _get_tlp_from_labels(self, labels: List[Dict]) -> Optional[str]:
        """Returns valid TLP value from object labels."""
        if labels:
            for label in labels:
                if label["value"].lower() in ALLOWED_TLPS:
                    return label["value"]

        return None

    def enrich_report(
        self, report_object: dict, api_url: str, report_name: str
    ) -> Dict:
        """Download report from ESET portal and updates report STIX object."""
        with requests.get(
            api_url,
            headers={
                "Authorization": f"Bearer {self.eset_api_key}|{self.eset_api_secret}"
            },
        ) as response:
            response.raise_for_status()
            content = response.content

        file = {
            "name": report_name,
            "data": base64.b64encode(content).decode("utf-8"),
            "mime_type": "application/octet-pdf",
        }
        files = report_object.get("x_opencti_files", [])
        files.append(file)

        report_object["x_opencti_files"] = files
        return file

    # noinspection PyMethodMayBeStatic
    def has_attachment(self, import_files: list, attachment_name: str) -> bool:
        attachment_name = attachment_name.lower()
        for imported_file in import_files:
            if imported_file.get("name", "").lower() == attachment_name:
                return True
        return False

    def process_message(self, data: dict) -> str:
        self.helper.log_debug("Processing", {"data": data})

        enrichment_entity = data["enrichment_entity"]
        entity_id = data["entity_id"]

        if not self.entity_in_scope(data):
            return self.helper.log_info(
                "Skipping the following entity as it does not concern "
                "the initial scope found in the config connector: ",
                {"entity_id": entity_id},
            )

        created_by = enrichment_entity.get("createdBy")
        if created_by is None or created_by.get("name", "").lower() != "eset":
            return self.helper.log_debug(
                "Skipping entity not created by ESET", {"entity_id": entity_id}
            )

        self.extract_and_check_markings(enrichment_entity)

        stix_objects = data["stix_objects"]
        for stix_object in stix_objects:
            if entity_id == stix_object["id"]:
                break
        else:
            raise Exception("STIX object %s not found", entity_id)

        report_name = f"{stix_object['name']}.pdf"

        if self.has_attachment(enrichment_entity.get("importFiles", []), report_name):
            return self.helper.log_info(
                "Report already has attachment imported",
                {"entity_id": entity_id, "name": report_name},
            )

        url = self._get_eti_api_url(enrichment_entity.get("objects", []))
        if url is None:
            return self.helper.log_info(
                "Skipping report without ETI portal link", {"entity_id": entity_id}
            )

        self.helper.log_info(
            "Downloading report",
            {"entity_id": entity_id, "name": report_name, "url": url},
        )

        file = self.enrich_report(stix_object, url, report_name)

        # Add TLP marking for file data. If the report has non-default TLP, use it.
        # Otherwise, assign TLP specified as label.
        tlp_marking: Optional[Mapping] = None

        if enrichment_entity["objectMarking"]:
            for marking_definition in enrichment_entity["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    tlp_marking = marking_definition

        tlp_value_label: Optional[str] = self._get_tlp_from_labels(
            enrichment_entity.get("objectLabel")
        )

        if (not tlp_value_label and tlp_marking) or (
            tlp_marking
            and (
                tlp_marking["definition"].lower() != "tlp:clear"
                and tlp_marking["definition"].lower() != "tlp:white"
            )
        ):
            file["object_marking_refs"] = tlp_marking["standard_id"]
        elif tlp_value_label:
            tlp_marking = create_tlp_marking(tlp_value_label)

            self.helper.log_debug(
                "Adding TLP marking found as label",
                {"entity_id": entity_id, "tlp": tlp_value_label},
            )

            stix_objects.append(tlp_marking)
            file["object_marking_refs"] = tlp_marking["id"]

        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)

        self.helper.log_debug(
            "Sending bundle", {"entity_id": entity_id, "bundle": stix_objects_bundle}
        )
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

        return self.helper.log_info(
            "Bundle successfully sent",
            {"entity_id": entity_id, "bundles_sent": len(bundles_sent)},
        )

    def _process_message(self, data: dict) -> str:
        try:
            return self.process_message(data)
        except Exception as err:
            return self.helper.log_error(
                "Unexpected Error occurred", {"error_message": repr(err)}
            )

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
