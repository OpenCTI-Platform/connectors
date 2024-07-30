import os
from typing import Dict

import requests
import yaml
from pycti import (
    STIX_EXT_OCTI_SCO,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    get_config_variable,
)


class RSTNoiseControlConnector:
    def __init__(self):
        # Load config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.safe_load(open(config_file_path))
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, True)
        self.base_url = get_config_variable(
            "RST_NOISE_CONTROL_BASE_URL", ["rst-noise-control", "base_url"], config
        )
        self.api_key = get_config_variable(
            "RST_NOISE_CONTROL_API_KEY", ["rst-noise-control", "api_key"], config
        )
        self.max_tlp = get_config_variable(
            "RST_NOISE_CONTROL_MAX_TLP",
            ["rst-noise-control", "max_tlp"],
            config,
            default="TLP:AMBER+STRICT",
        )

        self.update_confidence = bool(
            get_config_variable(
                "RST_NOISE_CONTROL_UPDATE_CONFIDENCE",
                ["rst-noise-control", "update_confidence"],
                config,
                default=True,
            )
        )

        self.update_score = bool(
            get_config_variable(
                "RST_NOISE_CONTROL_UPDATE_SCORE",
                ["rst-noise-control", "update_score"],
                config,
                default=True,
            )
        )
        self.change_score = int(
            get_config_variable(
                "RST_NOISE_CONTROL_CHANGE_ACTION_SCORE_CHANGE",
                ["rst-noise-control", "change_action_score_change"],
                config,
                default=10,
            )
        )
        self.drop_score = int(
            get_config_variable(
                "RST_NOISE_CONTROL_DROP_ACTION_SCORE_CHANGE",
                ["rst-noise-control", "drop_action_score_change"],
                config,
                default=50,
            )
        )
        self.detection_flag = bool(
            get_config_variable(
                "RST_NOISE_CONTROL_DROP_ACTION_DETECTION_FLAG",
                ["rst-noise-control", "drop_action_detection_flag"],
                config,
                default=True,
            )
        )

        self.created_by_filter = get_config_variable(
            "RST_NOISE_CONTROL_CREATED_BY_FILTER",
            ["rst-noise-control", "created_by_filter"],
            config,
            default="RST Cloud",
        )

        self.timeout = get_config_variable(
            "RST_NOISE_CONTROL_TIMEOUT",
            ["rst-noise-control", "timeout"],
            config,
            default=5,
        )

        self.connector_auto = bool(
            get_config_variable(
                "CONNECTOR_AUTO",
                ["connector", "auto"],
                config,
            )
        )

        self.helper.log_info(f"connector_auto {self.connector_auto}")
        self.helper.log_info(f"detection_flag {self.detection_flag}")
        self.helper.log_info(f"created_by_filter {self.created_by_filter}")

    def update_observable(self, stix_objects, labels, action, obj_type):
        for obj in stix_objects:
            if "x_opencti_type" not in obj or obj["x_opencti_type"] != obj_type:
                continue
            if action == "Drop":
                diff = self.drop_score
            elif action == "Change Score":
                diff = self.change_score
            else:
                raise ValueError(f"Unsupported action {action}")

            if "score" not in obj:
                obj["score"] = 0

            new_score = obj["score"]
            if new_score < diff:
                new_score = 0
            else:
                new_score = new_score - diff
            obj = OpenCTIStix2.put_attribute_in_extension(
                obj, STIX_EXT_OCTI_SCO, "labels", labels, False
            )
            obj = OpenCTIStix2.put_attribute_in_extension(
                obj, STIX_EXT_OCTI_SCO, "score", new_score
            )
        return stix_objects

    def update_indicator(self, stix_objects, labels, action, obj_type):
        for obj in stix_objects:
            if "x_opencti_type" not in obj or obj["x_opencti_type"] != obj_type:
                continue
            if action == "Drop":
                diff = self.drop_score
                obj["revoked"] = True
                if "indicator_types" in obj and "benign" not in obj["indicator_types"]:
                    obj["indicator_types"].append("benign")
                else:
                    obj["indicator_types"] = ["benign"]
            elif action == "Change Score":
                diff = self.change_score
            else:
                raise ValueError(f"Unsupported action {action}")

            if self.update_score:
                if "x_opencti_score" not in obj:
                    obj["x_opencti_score"] = 0

                new_score = obj["x_opencti_score"]
                if new_score < diff:
                    new_score = 0
                else:
                    new_score = new_score - diff
                obj["x_opencti_score"] = new_score
                obj = OpenCTIStix2.put_attribute_in_extension(
                    obj, STIX_EXT_OCTI_SCO, "score", new_score
                )

            if self.update_confidence:
                new_confidence = obj["confidence"]
                if new_confidence < diff:
                    new_confidence = 0
                else:
                    new_confidence = new_confidence - diff
                obj["confidence"] = new_confidence
            if self.detection_flag and action == "Drop":
                obj["x_opencti_detection"] = False
            obj = OpenCTIStix2.put_attribute_in_extension(
                obj, STIX_EXT_OCTI_SCO, "labels", labels, False
            )
        return stix_objects

    def _process_message(self, data: Dict) -> str:
        opencti_entity = data["enrichment_entity"]

        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError("TLP of the value is greater than MAX TLP")

        check = True
        if (
            self.connector_auto
            and self.created_by_filter
            and len(self.created_by_filter) > 0
        ):
            if (
                "createdBy" in data["enrichment_entity"]
                and data["enrichment_entity"]["createdBy"]
                and "name" in data["enrichment_entity"]["createdBy"]
            ):
                created_by = data["enrichment_entity"]["createdBy"]["name"]
                orgs_to_filter = self.created_by_filter.split(",")
                for i in orgs_to_filter:
                    if created_by == i:
                        check = False
                        break

        self.helper.log_debug(f"Data Entity {data}")

        if check:
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
            reponses = []
            for value in values:
                url = self.base_url + "/benign/lookup"
                headers = {
                    "Content-Type": "application/json",
                    "x-api-key": self.api_key,
                }
                params = {"value": value}
                r = requests.get(
                    url, headers=headers, params=params, timeout=self.timeout
                )
                r.raise_for_status()
                resp = r.json()
                reponses.append(resp)
                if resp.get("benign") == "true":
                    # do not check all 3 hashes if at least one is listed as benign
                    break

            resp = {}
            for first_found in reponses:
                if "benign" in first_found:
                    resp = first_found
                    break

            if "benign" in resp:
                self.helper.log_debug(f"Response {resp}")
                if resp["benign"] == "true":
                    stix_objects = data["stix_objects"]
                    stix_entry = data["stix_entity"]
                    if "labels" not in stix_entry:
                        stix_entry["labels"] = []
                    labels = stix_entry["labels"]
                    if resp["reason"].startswith("Drop"):
                        categories = resp["reason"].replace("Drop ", "")
                        for word in list(set(categories.lower().split("/"))):
                            labels.append(word)
                        labels.append("benign")
                        labels.append("rst-nc-action: drop")
                        if data["entity_type"] == "Indicator":
                            stix_objects = self.update_indicator(
                                stix_objects, labels, "Drop", data["entity_type"]
                            )
                        else:
                            stix_objects = self.update_observable(
                                stix_objects, labels, "Drop", data["entity_type"]
                            )
                    elif resp["reason"].startswith("Change Score"):
                        categories = resp["reason"].replace("Change Score ", "")
                        for word in list(set(categories.lower().split("/"))):
                            labels.append(word)
                        labels.append("noise")
                        labels.append("rst-nc-action: change score")
                        if data["entity_type"] == "Indicator":
                            stix_objects = self.update_indicator(
                                stix_objects,
                                labels,
                                "Change Score",
                                data["entity_type"],
                            )
                        else:
                            stix_objects = self.update_observable(
                                stix_objects,
                                labels,
                                "Change Score",
                                data["entity_type"],
                            )
                    else:
                        raise ValueError(f"Unsupported value: {resp}")
                    self.helper.log_debug(f"Result {stix_objects}")
                    serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
                    self.helper.send_stix2_bundle(serialized_bundle)
                    return f"[CONNECTOR] Sent STIX bundle to update: {resp['reason']}"
                elif resp["benign"] == "false":
                    pass
                else:
                    raise ValueError(f"Unsupported value: {resp}")
            else:
                raise ValueError(f"Communication error: {resp}")
            return "[CONNECTOR] No changes required"

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    RSTNoiseControlInstance = RSTNoiseControlConnector()
    RSTNoiseControlInstance.start()
