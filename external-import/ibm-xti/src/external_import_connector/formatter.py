import re
from base64 import b64encode
from typing import Any

from cvss import CVSS3
from markdown_it import MarkdownIt
from pycti import OpenCTIConnectorHelper

md = MarkdownIt(
    options_update={"options": {"html": True, "linkify": True, "typographer": True}}
)


class OpenCTISTIXFormatter:
    __helper: OpenCTIConnectorHelper

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.__helper = helper

    def format_report(self, obj: dict[str, Any], alias: str):
        if not obj.get("external_references"):
            obj["external_references"] = []

        obj["external_references"].append(
            {"source_name": "x_force_stix_id", "external_id": obj["id"]}
        )

        obj["description"] = (
            obj["description"]
            .replace("data:image/jpg", "data:image/JPEG")
            .replace("data:image/JPG", "data:image/JPEG")
        )
        encoded_data = b64encode(md.render(obj["description"]).encode("utf-8")).decode(
            "utf-8"
        )
        obj["x_opencti_files"] = [
            {
                "name": f"{obj['id']}.html",
                "data": encoded_data,
                "mime_type": "text/html",
            }
        ]

        extensions = obj["extensions"]
        for key in extensions.keys():
            if key.startswith("extension-definition") and "summary" in extensions[key]:
                obj["description"] = extensions[key]["summary"]

        obj["labels"] = list(
            filter(lambda l: not l.startswith("int.entitle."), obj["labels"])
        )
        obj["labels"].append(alias)

    def format_indicator(self, obj: dict[str, Any]):
        if not obj.get("external_references"):
            obj["external_references"] = []

        obj["external_references"].append(
            {"source_name": "x_force_stix_id", "external_id": obj["id"]}
        )

    def __cvss_severity(self, score: float):
        if not score:
            return "Unknown"

        if 0.1 <= score <= 3.9:
            return "Low"

        if 4 <= score <= 6.9:
            return "Medium"

        if 7 <= score <= 8.9:
            return "High"

        if 9 <= score <= 10:
            return "Critical"

        return "Unknown"

    def __parse_cvss(self, obj: dict[str, Any], entry: Any):
        cvss: str = entry["string"]

        if not cvss:
            self.__helper.connector_logger.warning(f"{obj['id']}: No CVSS string found")
            return

        if not cvss.startswith("CVSS:"):
            self.__helper.connector_logger.warning(
                f"{obj['id']}: CVSS string doesn't start with 'CVSS:' prefix"
            )
            return

        version_match = re.match("CVSS:(.*?)/", cvss)
        if not version_match:
            self.__helper.connector_logger.warning(
                f"{obj['id']}: CVSS string is malformed"
            )
            return

        version = version_match[1]
        if not cvss.startswith("CVSS:3"):
            self.__helper.connector_logger.warning(
                f"{obj['id']}:  No common_vulnerability_scores support for version: '{version}'"
            )
            return

        cvss_vector = CVSS3(cvss)

        obj["x_opencti_cvss_base_score"] = entry["base_score"]
        obj["x_opencti_cvss_base_severity"] = self.__cvss_severity(entry["base_score"])
        obj["x_opencti_cvss_attack_vector"] = cvss_vector.get_value_description("AV")
        obj["x_opencti_cvss_integrity_impact"] = cvss_vector.get_value_description("I")
        obj["x_opencti_cvss_availability_impact"] = cvss_vector.get_value_description(
            "A"
        )
        obj["x_opencti_cvss_confidentiality_impact"] = (
            cvss_vector.get_value_description("C")
        )
        obj["x_opencti_epss_score"] = None
        obj["x_opencti_epss_percentile"] = None

    def format_vulnerability(self, obj: dict[str, Any]):
        # set CVE as the vulnerability name
        xfid = ""
        name = obj["name"]

        for reference in obj["external_references"]:
            if reference["source_name"] == "xfid":
                xfid = reference["external_id"]
            elif reference["source_name"] == "cve":
                obj["name"] = reference["external_id"]

        # If record has no cve, use xfid as the name
        if not obj["name"].startswith("CVE-"):
            obj["name"] = xfid

        # Save our vulnerability name as an external reference
        obj["external_references"].append({"source_name": "name", "external_id": name})

        # Save our object id as an external reference
        obj["external_references"].append(
            {"source_name": "x_force_stix_id", "external_id": obj["id"]}
        )

        extensions = obj["extensions"]
        for key in extensions.keys():
            if key.startswith("extension-definition"):
                # enrich the vulnerability with the x_opencti_cvss info
                for entry in extensions[key]["cvss"]:
                    self.__parse_cvss(obj, entry)

                for entry in extensions[key]["reference"]:
                    obj["external_references"].append(
                        {
                            "source_name": "reference",
                            "external_id": entry["url"],
                            "url": entry["url"],
                            "created": entry["date"],
                        }
                    )
                    if entry.get("kev_guidance"):
                        obj["x_opencti_cisa_kev"] = True

                del extensions[key]["reference"]
