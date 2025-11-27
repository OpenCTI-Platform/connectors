import ipaddress
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

import requests
import yaml
from pycti import (
    STIX_EXT_OCTI_SCO,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    get_config_variable,
)


class ShadowTrackrConnector:
    def __init__(self):
        # Instantiate the connector helper from config

        config_file_path = str((Path(__file__).resolve().parent / "config.yml"))
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, True)

        self.api_key = str(
            get_config_variable(
                "SHADOWTRACKR_API_KEY",
                ["shadowtrackr", "api_key"],
                config,
                default=False,
            )
        )

        self.max_tlp = str(
            get_config_variable(
                "SHADOWTRACKR_MAX_TLP",
                ["shadowtrackr", "max_tlp"],
                config,
                default="TLP:AMBER",
            )
        )
        self.replace_with_lower_score = bool(
            get_config_variable(
                "SHADOWTRACKR_REPLACE_WITH_LOWER_SCORE",
                ["shadowtrackr", "replace_with_lower_score"],
                config,
                default=False,
            )
        )
        self.replace_valid_to_date = bool(
            get_config_variable(
                "SHADOWTRACKR_REPLACE_VALID_TO_DATE",
                ["shadowtrackr", "replace_valid_to_date"],
                config,
                default=False,
            )
        )
        self.helper.connector_logger.info(f"max_tlp: {self.max_tlp}")
        self.helper.connector_logger.info(
            f"replace_with_lower_score : {self.replace_with_lower_score}"
        )
        self.helper.connector_logger.info(
            f"replace_valid_to_date: {self.replace_valid_to_date}"
        )

        # Create Tags in OpenCTI for later use
        self.label_bogon = self.helper.api.label.read_or_create_unchecked(
            value="Bogon", color="#145578"
        )
        if self.label_bogon is None:
            raise ValueError(
                "The Bogon label could not be created. If your connector does not have the permission to create labels, "
                "please create it manually before launching"
            )

        self.label_cloud = self.helper.api.label.read_or_create_unchecked(
            value="cloud", color="#145578"
        )
        if self.label_cloud is None:
            raise ValueError(
                "The cloud label could not be created. If your connector does not have the permission to create labels, "
                "please create it manually before launching."
            )

        self.label_cdn = self.helper.api.label.read_or_create_unchecked(
            value="cdn", color="#145578"
        )
        if self.label_cdn is None:
            raise ValueError(
                "The cdn label could not be created. If your connector does not have the permission to create labels, "
                "please create it manually before launching"
            )

        self.label_vpn = self.helper.api.label.read_or_create_unchecked(
            value="vpn", color="#145578"
        )
        if self.label_vpn is None:
            raise ValueError(
                "The vpn label could not be created. If your connector does not have the permission to create labels, "
                "please create it manually before launching"
            )

        self.label_tor = self.helper.api.label.read_or_create_unchecked(
            value="tor", color="#145578"
        )
        if self.label_tor is None:
            raise ValueError(
                "The tor label could not be created. If your connector does not have the permission to create labels, "
                "please create it manually before launching"
            )

        self.label_public_dns_server = self.helper.api.label.read_or_create_unchecked(
            value="public_dns_server", color="#145578"
        )
        if self.label_public_dns_server is None:
            raise ValueError(
                "The public dns server label could not be created. If your connector does not have the permission to "
                "create labels, please create it manually before launching"
            )

    def _process_entity(self, stix_objects, stix_entity, opencti_entity) -> str:
        # Search in ShadowTrackr
        is_indicator = False
        entity_type = opencti_entity["entity_type"]
        if entity_type == "Indicator":
            pattern = opencti_entity["pattern"]
            is_indicator = True

            if "ipv4-addr" in pattern or "ipv6-addr" in pattern:
                ip = pattern.split("'")[1]
            else:
                return f"No ip address in indicator, skipping {pattern} {entity_type}"

        else:
            ip = opencti_entity["observable_value"]

        if self._valid_ip(ip):
            score = opencti_entity["x_opencti_score"]
            old_score = score
            labels = [label["value"] for label in opencti_entity["objectLabel"]]
            markings = [
                marking["definition"]
                for marking in opencti_entity["objectMarking"]
                if marking["definition_type"] == "TLP"
            ]

            for tlp in markings:
                if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
                    raise ValueError(
                        f"Do not send any data, TLP of the observable is greater than MAX TLP: {tlp} > {self.max_tlp}"
                    )

            if is_indicator:
                description = opencti_entity["description"]
            else:
                description = opencti_entity["x_opencti_description"]

            if description is not None and "[ShadowTrackr] " in description:
                return (
                    "This ip is already processed by the ShadowTrackr connector. We're not doing it again, "
                    "that might mess up the score."
                )

            data = self._check_ip_in_shadowtrackr(ip, labels)
            if error := data.get("error"):
                raise ValueError(f"Error: [ShadowTrackr] {error}")

            score_lowered = False
            if self.replace_with_lower_score:
                false_positive_estimate = data["false_positive_estimate"]

                score_steps = [
                    (99, 60),
                    (89, 40),
                    (69, 20),
                    (50, 10),
                ]
                for threshold, decrement in score_steps:
                    if false_positive_estimate > threshold:
                        score -= decrement
                        score_lowered = True
                        break

                # set a lower boundary
                if score < 10:
                    score = 10

                # Update score
                OpenCTIStix2.put_attribute_in_extension(
                    stix_entity, STIX_EXT_OCTI_SCO, "score", score
                )

            # Observables don't have a valid until field, but indicators do
            date_shortened = False
            if is_indicator and (data["vpn"] or data["cdn"] or data["cloud"]):
                valid_from = datetime.fromisoformat(
                    opencti_entity["valid_from"].strip("Z")
                )
                valid_until = (valid_from + timedelta(days=1)).isoformat(
                    timespec="milliseconds"
                ) + "Z"
                OpenCTIStix2.put_attribute_in_extension(
                    stix_entity, STIX_EXT_OCTI_SCO, "valid_until", valid_until, True
                )
                date_shortened = True

            for label in ["vpn", "cdn", "cloud", "bogon", "tor", "public_dns"]:
                if data[label]:
                    if is_indicator:
                        stix_entity["labels"].append(label)
                    else:
                        OpenCTIStix2.put_attribute_in_extension(
                            stix_entity, STIX_EXT_OCTI_SCO, "labels", label, True
                        )

            text = ""
            if data["cdn"]:
                if data["cdn_provider"]:
                    text = f"This is an ip address in the {data['cdn_provider']} CDN."
                else:
                    text = "This is an ip address in a CDN."

                text += " CDN ip addresses change regularly, and are not very useful to track."
                if score_lowered:
                    if date_shortened:
                        text += " The score is adjusted downwards, and the valid until date set to 1 day."
                    else:
                        text += " The score is adjusted downwards."

            elif data["cloud"]:
                if data["cloud_provider"]:
                    text = (
                        f" This is an ip address in the {data['cloud_provider']} cloud."
                    )
                else:
                    text = " This is an ip address in a cloud."

                text += " Cloud ip addresses change regularly, and are not very useful to track."
                if score_lowered:
                    if date_shortened:
                        text += " The score is adjusted downwards, and the valid until date set to 1 day."
                    else:
                        text += " The score is adjusted downwards."

            elif data["vpn"]:
                text = (
                    "This ip address is a VPN. "
                    "VPN ip addresses change regularly, and are not very useful to track."
                )
                if score_lowered:
                    if date_shortened:
                        text += " The score is adjusted downwards, and the valid until date set to 1 day."
                    else:
                        text += " The score is adjusted downwards."

            elif data["public_dns"]:
                text = (
                    "This ip address is a public DNS server. "
                    "Public DNS servers are often used in malware to check for an internet connection, "
                    "and automated analysis tools regularly extract them as indicators. This is not very useful."
                )
                if self.replace_with_lower_score:
                    text += " The score is adjusted downwards."

            if text:
                description += f"\n[ShadowTrackr] {text}"
                if is_indicator:
                    stix_entity["description"] = description
                else:
                    OpenCTIStix2.put_attribute_in_extension(
                        stix_entity,
                        STIX_EXT_OCTI_SCO,
                        "description",
                        description,
                        False,
                    )

            if old_score == score:
                if date_shortened:
                    serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
                    self.helper.send_stix2_bundle(serialized_bundle)
                    return f"Found data on {ip}. Score not changed, but valid_until shortened to 1 day."
                else:
                    return f"Found data on {ip}. Score not changed."
            else:
                serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(serialized_bundle)
                if date_shortened:
                    return (
                        f"Found data on {ip}. Score changed from {old_score} to {score}, "
                        "valid_until shortened to 1 day."
                    )
                else:
                    return f"Found data on {ip}. Score changed from {old_score} to {score}."

        return f"Invalid ip: {ip}"

    def _process_message(self, data: dict) -> str:
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]
        return self._process_entity(stix_objects, stix_entity, opencti_entity)

    # Start the main loop
    def run(self):
        self.helper.listen(message_callback=self._process_message)

    def _check_ip_in_shadowtrackr(self, ip, labels=None) -> dict:
        if labels:
            labels = ",".join(labels)
        else:
            labels = ""

        base_url = "https://shadowtrackr.com/api/v3/ip_info"
        response = requests.get(
            base_url, params={"api_key": self.api_key, "ip": ip, "tags": labels or ""}
        )
        data = json.loads(response.text)
        return data

    def _valid_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except Exception as e:
            self.helper.connector_logger.error("Error validating ip", {"error": str(e)})
            return False


if __name__ == "__main__":
    ShadowTrackrInstance = ShadowTrackrConnector()
    ShadowTrackrInstance.run()
