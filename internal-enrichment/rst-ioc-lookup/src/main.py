import os
from datetime import datetime, timezone
from typing import Dict
from urllib.parse import urlparse

import requests
import yaml
from pycti import (
    STIX_EXT_OCTI_SCO,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    get_config_variable,
)


class RSTIocLookupConnector:
    def __init__(self):
        # Load config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.safe_load(open(config_file_path))
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, True)
        self.base_url = str(
            get_config_variable(
                "RST_IOC_LOOKUP_BASE_URL", ["rst-ioc-lookup", "base_url"], config
            )
        )
        self.api_key = str(
            get_config_variable(
                "RST_IOC_LOOKUP_API_KEY", ["rst-ioc-lookup", "api_key"], config
            )
        )
        self.max_tlp = str(
            get_config_variable(
                "RST_IOC_LOOKUP_MAX_TLP",
                ["rst-ioc-lookup", "max_tlp"],
                config,
                default="TLP:AMBER+STRICT",
            )
        )

        self.update_confidence = bool(
            get_config_variable(
                "RST_IOC_LOOKUP_UPDATE_CONFIDENCE",
                ["rst-ioc-lookup", "update_confidence"],
                config,
                default=True,
            )
        )

        self.update_score = bool(
            get_config_variable(
                "RST_IOC_LOOKUP_UPDATE_SCORE",
                ["rst-ioc-lookup", "update_score"],
                config,
                default=True,
            )
        )

        self.update_valid_from = bool(
            get_config_variable(
                "RST_IOC_LOOKUP_UPDATE_VALID_FROM",
                ["rst-ioc-lookup", "update_valid_from"],
                config,
                default=True,
            )
        )

        self.score_type = str(
            get_config_variable(
                "RST_IOC_LOOKUP_SCORE_TYPE",
                ["rst-ioc-lookup", "score_type"],
                config,
                default="total",
            )
        )

        self.update_description_action = str(
            get_config_variable(
                "RST_IOC_LOOKUP_UPDATE_DESCRIPTION_ACTION",
                ["rst-ioc-lookup", "update_description_action"],
                config,
                default="overwrite",
            )
        )

        self.detection_flag_threshold = int(
            get_config_variable(
                "RST_IOC_LOOKUP_DETECTION_FLAG_THRESHOLD",
                ["rst-ioc-lookup", "detection_flag_threshold"],
                config,
                default=45,
            )
        )

        self.label_format = str(
            get_config_variable(
                "RST_IOC_LOOKUP_LABEL_FORMAT",
                ["rst-ioc-lookup", "label_format"],
                config,
                default="short",
            )
        )

        self.timeout = int(
            get_config_variable(
                "RST_IOC_LOOKUP_TIMEOUT",
                ["rst-ioc-lookup", "timeout"],
                config,
                default=10,
            )
        )

        self.connector_auto = bool(
            get_config_variable(
                "CONNECTOR_AUTO",
                ["connector", "auto"],
                config,
            )
        )

        self.helper.log_info(f"connector_auto {self.connector_auto}")
        self.helper.log_info(f"update_score {self.update_score}")
        self.helper.log_info(f"update_confidence {self.update_confidence}")
        self.helper.log_info(f"detection_flag {self.detection_flag_threshold}")

    def format_tag(self, tag):
        # for compatibility with other sources
        # we may need the suffixes removed
        if self.label_format == "short":
            tag = (
                tag.replace("_group", "")
                .replace("_actor", "")
                .replace("_campaign", "")
                .replace("_ransomware", "")
                .replace("_tool", "")
                .replace("_backdoor", "")
                .replace("_rat", "")
                .replace("_exploit", "")
                .replace("_vuln", "")
            )
        elif self.label_format == "long":
            pass
        else:
            raise ValueError("Unsupported label format")
        return tag

    def extract_score(self, resp):
        if self.score_type == "last":
            # do not use the RST Cloud's decay algorithm
            # the score is set based on the last value
            # calculated by RST Cloud on a last seen day
            new_score = int(resp["score"]["last"])
        elif self.score_type == "total":
            # use the RST Cloud's decay algorithm
            # the score is set to the currect score value
            # having the decay algorithm is place
            new_score = int(resp["score"]["total"])
        else:
            raise ValueError("Unsupported score type")
        return new_score

    def format_description(self, ioc_raw):
        description = ioc_raw["description"]
        if ioc_raw.get("ports") and int(ioc_raw["ports"][0]) != -1:
            description = f'{description}\n\nPorts: {ioc_raw.get("ports")}'
        if (
            ioc_raw.get("resolved")
            and ioc_raw.get("resolved").get("whois")
            and ioc_raw.get("resolved").get("whois").get("havedata") == "true"
        ):
            description = f'{description}\n\nWhois Registrar: {ioc_raw["resolved"]["whois"]["registrar"]}'
            description = f'{description}\n--- Registrant: {ioc_raw["resolved"]["whois"]["registrant"]}'
            if int(ioc_raw["resolved"]["whois"]["age"]) > 0:
                description = (
                    f'{description}\n--- Age: {ioc_raw["resolved"]["whois"]["age"]}'
                )
            if ioc_raw["resolved"]["whois"]["created"] != "1970-01-01 00:00:00":
                description = f'{description}\n--- Created: {ioc_raw["resolved"]["whois"]["created"]}'
            if ioc_raw["resolved"]["whois"]["updated"] != "1970-01-01 00:00:00":
                description = f'{description}\n--- Updated: {ioc_raw["resolved"]["whois"]["updated"]}'
            if ioc_raw["resolved"]["whois"]["expires"] != "1970-01-01 00:00:00":
                description = f'{description}\n--- Expires: {ioc_raw["resolved"]["whois"]["expires"]}'
        if ioc_raw.get("resolved") and ioc_raw.get("resolved").get("ip"):
            if (
                len(ioc_raw["resolved"]["ip"]["a"])
                + len(ioc_raw["resolved"]["ip"]["alias"])
                + len(ioc_raw["resolved"]["ip"]["cname"])
                > 0
            ):
                description = f"{description}\n\nRelated IPs:"
                description = (
                    f'{description}\n--- A Records: {ioc_raw["resolved"]["ip"]["a"]}'
                )
                description = f'{description}\n--- Alias Records: {ioc_raw["resolved"]["ip"]["alias"]}'
                description = f'{description}\n--- CNAME Records: {ioc_raw["resolved"]["ip"]["cname"]}'
        if ioc_raw.get("geo"):
            description = f"{description}\n"
            if ioc_raw.get("geo").get("city"):
                description = f'{description}\nCity: {ioc_raw.get("geo").get("city")}.'
            if ioc_raw.get("geo").get("country"):
                description = (
                    f'{description}\nCountry: {ioc_raw.get("geo").get("country")}.'
                )
            if ioc_raw.get("geo").get("region"):
                description = (
                    f'{description}\nRegion: {ioc_raw.get("geo").get("region")}.'
                )
        if ioc_raw.get("asn"):
            description = f'{description}\n\nASN: {ioc_raw.get("asn").get("num")}. Number of domains: {ioc_raw.get("asn").get("domains")}'
            description = f'{description}\nOrg: {ioc_raw.get("asn").get("org")}'
            description = f'{description}\nISP: {ioc_raw.get("asn").get("isp")}'
            if ioc_raw.get("asn").get("cloud"):
                description = f'{description} Cloud: {ioc_raw.get("asn").get("cloud")}'
        if ioc_raw.get("filename"):
            description = f'{description}\n\nFile names: {ioc_raw.get("filename")}'
        if ioc_raw.get("resolved") and ioc_raw.get("resolved").get("status"):
            description = f'{description}\n\nHTTP Status Code: {ioc_raw.get("resolved").get("status")}'
        if ioc_raw.get("fp"):
            description = f'{description}\n\nIs a potential false positive? {ioc_raw.get("fp").get("alarm")}.'
            if ioc_raw.get("fp").get("descr"):
                description = f'{description} Why? {ioc_raw.get("fp").get("descr")}.'
        if ioc_raw.get("industry"):
            description = f'{description}\n\nRelated sectors: {ioc_raw.get("industry")}'
        if ioc_raw.get("cve"):
            description = f'{description}\n\nRelated CVEs: {ioc_raw.get("cve")}'
        if ioc_raw.get("ttp"):
            description = f'{description}\n\nRelated TTPs: {ioc_raw.get("ttp")}'

        return description

    def update_observable(self, stix_objects, labels, resp, obj_type):
        external_references = list()
        for obj in stix_objects:
            if "x_opencti_type" not in obj or obj["x_opencti_type"] != obj_type:
                continue

            if self.update_score:
                if "x_opencti_score" not in obj:
                    obj["x_opencti_score"] = 0
                new_score = self.extract_score(resp)
                obj = OpenCTIStix2.put_attribute_in_extension(
                    obj, STIX_EXT_OCTI_SCO, "score", new_score
                )
            obj = OpenCTIStix2.put_attribute_in_extension(
                obj, STIX_EXT_OCTI_SCO, "labels", labels, False
            )

            # update the observable description using one of the user selected strategies
            if self.update_description_action == "overwrite":
                obj["description"] = self.format_description(resp)
            elif self.update_description_action == "append":
                obj["description"] = (
                    f'{obj["description"]}\n\n{self.format_description(resp)}'
                )
            elif self.update_description_action == "prepend":
                obj["description"] = (
                    f'{self.format_description(resp)}\n\n{obj["description"]}'
                )
            else:
                raise ValueError("Unsupported description update action")

            external_references = list()
            for ref in resp["src"]["report"].split(","):
                ref_name = urlparse(ref).netloc
                if ref_name.strip() == "":
                    ref_name = ref
                external_references.append({"source_name": ref_name, "url": ref})
            obj["external_references"] = external_references

        return stix_objects

    def update_indicator(self, stix_objects, labels, resp, obj_type):
        for obj in stix_objects:
            if "x_opencti_type" not in obj or obj["x_opencti_type"] != obj_type:
                continue

            if self.update_score:
                if "x_opencti_score" not in obj:
                    obj["x_opencti_score"] = 0
                new_score = self.extract_score(resp)
                obj["x_opencti_score"] = new_score
                obj = OpenCTIStix2.put_attribute_in_extension(
                    obj, STIX_EXT_OCTI_SCO, "score", new_score
                )
                # if self.detection_flag_threshold == 0, then do not change
                # if more than 0 use as a threshold to update detection flag
                if self.detection_flag_threshold and self.detection_flag_threshold > 0:
                    if new_score >= self.detection_flag_threshold:
                        obj["x_opencti_detection"] = True
                    else:
                        obj["x_opencti_detection"] = False

            # set confidence to the src score confidence
            if self.update_confidence:
                obj["confidence"] = round(float(resp["score"]["src"]))

            # update the indicator description using one of the user selected strategies
            if self.update_description_action == "overwrite":
                obj["description"] = self.format_description(resp)
            elif self.update_description_action == "append":
                obj["description"] = (
                    f'{obj["description"]}\n\n{self.format_description(resp)}'
                )
            elif self.update_description_action == "prepend":
                obj["description"] = (
                    f'{self.format_description(resp)}\n\n{obj["description"]}'
                )
            else:
                raise ValueError("Unsupported description update action")

            # update valid from using last_seen
            # this pushes the date forward setting it to the newest date
            # help to keep an indicator in an active state (revoked = true)
            # if it is still being reported as malcious
            if self.update_valid_from:
                valid_from_dt = datetime.fromtimestamp(int(resp["lseen"]), timezone.utc)
                valid_from = valid_from_dt.isoformat(timespec="milliseconds")
                obj["valid_from"] = valid_from.replace("+00:00", "Z")

            obj = OpenCTIStix2.put_attribute_in_extension(
                obj, STIX_EXT_OCTI_SCO, "labels", labels, False
            )

            external_references = list()
            for ref in resp["src"]["report"].split(","):
                ref_name = urlparse(ref).netloc
                if ref_name.strip() == "":
                    ref_name = ref
                external_references.append({"source_name": ref_name, "url": ref})
            obj["external_references"] = external_references
        return stix_objects

    def _process_message(self, data: Dict) -> str:
        opencti_entity = data["enrichment_entity"]

        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError("TLP of the value is greater than MAX TLP")

        self.helper.log_debug(f"Data Entity {data}")

        # most of the entities will have 1 value
        # but StixFile can consist of multiple hashes
        values = []
        if data["entity_type"] in ["IPv4-Addr", "Domain-Name", "Url"]:
            values.append(data["stix_entity"]["value"])
        elif data["entity_type"] == "StixFile":
            if "hashes" in data["enrichment_entity"]:
                for hash in data["enrichment_entity"]["hashes"]:
                    if "algorithm" in hash and hash["algorithm"] in [
                        "MD5",
                        "SHA-1",
                        "SHA-256",
                    ]:
                        if len(hash["hash"]) > 0:
                            values.append(hash["hash"])
                        else:
                            data["stix_entity"]["hashes"].pop(hash["algorithm"])
            else:
                return "[CONNECTOR] No changes required. No MD5, SHA-1 or SHA-256 hash found"
        elif data["entity_type"] == "Indicator":
            values.append(data["enrichment_entity"]["name"])
        else:
            raise ValueError(f"Unsupported value: {data}")

        if len(values) < 1:
            return "[CONNECTOR] Nothing to check"
        # for IP, Domain, URL it is one query
        # for StixFile objects it can be up to 3 queries
        reponses = []
        for value in values:
            url = self.base_url + "/ioc"
            headers = {
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
            }
            params = {"value": value}
            r = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            r.raise_for_status()
            resp = r.json()
            reponses.append(resp)
            if len(resp.get("id", "")) > 0:
                # do not check all 3 hashes if at least one is listed in the lookup database
                break

        resp = {}
        for first_found in reponses:
            if "id" in first_found:
                resp = first_found
                break

        if "id" in resp:
            self.helper.log_debug(f"Response {resp}")
            stix_objects = data["stix_objects"]
            stix_entry = data["stix_entity"]
            if "labels" not in stix_entry:
                stix_entry["labels"] = []
            labels = stix_entry["labels"]
            # extract threat categories and threat names
            tags = []
            if "tags" in resp:
                tags = resp["tags"].get("tags", []) + resp.get("threat", [])
            # populate labels with new data
            for tag in tags:
                if tag != "generic" and self.format_tag(tag) not in labels:
                    labels.append(self.format_tag(tag))
            # update values depending on the obejct type
            if data["entity_type"] == "Indicator":
                stix_objects = self.update_indicator(
                    stix_objects, labels, resp, data["entity_type"]
                )
            else:
                stix_objects = self.update_observable(
                    stix_objects, labels, resp, data["entity_type"]
                )
            self.helper.log_debug(f"Result {stix_objects}")
            serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
            self.helper.send_stix2_bundle(serialized_bundle)
            return f"[CONNECTOR] Sent STIX bundle to update for {resp['ioc_value'].replace('.','[.]')}"
        else:
            return "[CONNECTOR] No changes required"

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    RSTIocLookupInstance = RSTIocLookupConnector()
    RSTIocLookupInstance.start()
