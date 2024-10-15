import ipaddress
import json
import os
from datetime import datetime, timedelta
from typing import Dict

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

        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
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
        self.helper.log_info(f"max_tlp: {self.max_tlp}")
        self.helper.log_info(
            f"replace_with_lower_score : {self.replace_with_lower_score}"
        )
        self.helper.log_info(f"replace_valid_to_date: {self.replace_valid_to_date}")

        # Create Tags in OpenCTI for later use
        self.label_bogon = self.helper.api.label.read_or_create_unchecked(
            value="Bogon", color="#145578"
        )
        if self.label_bogon is None:
            raise ValueError(
                "The Bogon label could not be created. If your connector does not have the permission to create labels,"
                " please create it manually before launching"
            )
        self.label_cloud = self.helper.api.label.read_or_create_unchecked(
            value="cloud", color="#145578"
        )
        if self.label_cloud is None:
            raise ValueError(
                "The cloud label could not be created. If your connector does not have the permission to create labels,"
                " please create it manually before launching"
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
        if opencti_entity["entity_type"] == "Indicator":
            is_indicator = True
            if "ipv4-addr" in opencti_entity["pattern"]:
                ip = opencti_entity["pattern"].split("'")[1]
            elif "ipv6-addr" in opencti_entity["pattern"]:
                ip = opencti_entity["pattern"].split("'")[1]
            else:
                return (
                    "No ip address in indicator, skipping " + opencti_entity["pattern"]
                )
        else:
            ip = opencti_entity["observable_value"]

        if self._valid_ip(ip):
            score = opencti_entity["x_opencti_score"]
            old_score = score
            labels = [l["value"] for l in opencti_entity["objectLabel"]]
            markings = [
                l["definition"]
                for l in opencti_entity["objectMarking"]
                if l["definition_type"] == "TLP"
            ]

            for tlp in markings:
                if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
                    raise ValueError(
                        "Do not send any data, TLP of the observable is greater than MAX TLP"
                    )

            if is_indicator:
                description = opencti_entity["description"]
            else:
                description = opencti_entity["x_opencti_description"]

            if "[ShadowTrackr] " in description:
                return (
                    "This ip is already processed by the ShadowTrackr connector. We're not doing it again,"
                    " that might mess up the score"
                )

            data = self._check_ip_in_shadowtrackr(ip, labels)
            if "error" in data:
                raise Exception("Error: [ShadowTrackr] " + data["error"])

            score_lowered = False
            if self.replace_with_lower_score:
                if data["false_positive_estimate"] > 99:
                    score -= 60
                    score_lowered = True
                elif data["false_positive_estimate"] > 89:
                    score -= 40
                    score_lowered = True
                elif data["false_positive_estimate"] > 69:
                    score -= 20
                    score_lowered = True
                elif data["false_positive_estimate"] > 50:
                    score -= 10
                    score_lowered = True
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
                    stix_entity,
                    STIX_EXT_OCTI_SCO,
                    "valid_until",
                    valid_until,
                    True,
                )
                date_shortened = True

            if data["vpn"]:
                if is_indicator:
                    stix_entity["labels"].append("vpn")
                else:
                    OpenCTIStix2.put_attribute_in_extension(
                        stix_entity,
                        STIX_EXT_OCTI_SCO,
                        "labels",
                        "vpn",
                        True,
                    )
            if data["cdn"]:
                if is_indicator:
                    stix_entity["labels"].append("cdn")
                else:
                    OpenCTIStix2.put_attribute_in_extension(
                        stix_entity,
                        STIX_EXT_OCTI_SCO,
                        "labels",
                        "cdn",
                        True,
                    )
            if data["cloud"]:
                if is_indicator:
                    stix_entity["labels"].append("cloud")
                else:
                    OpenCTIStix2.put_attribute_in_extension(
                        stix_entity,
                        STIX_EXT_OCTI_SCO,
                        "labels",
                        "cloud",
                        True,
                    )
            if data["bogon"]:
                if is_indicator:
                    stix_entity["labels"].append("bogon")
                else:
                    OpenCTIStix2.put_attribute_in_extension(
                        stix_entity,
                        STIX_EXT_OCTI_SCO,
                        "labels",
                        "bogon",
                        True,
                    )
            if data["tor"]:
                if is_indicator:
                    stix_entity["labels"].append("tor")
                else:
                    OpenCTIStix2.put_attribute_in_extension(
                        stix_entity,
                        STIX_EXT_OCTI_SCO,
                        "labels",
                        "tor",
                        True,
                    )
            if data["public_dns"]:
                if is_indicator:
                    stix_entity["labels"].append("public dns server")
                else:
                    OpenCTIStix2.put_attribute_in_extension(
                        stix_entity,
                        STIX_EXT_OCTI_SCO,
                        "labels",
                        "public dns server",
                        True,
                    )

            text = ""
            if data["cdn"]:
                if data["cdn_provider"]:
                    text = (
                        "This is an ip address in the " + data["cdn_provider"] + " CDN."
                    )
                else:
                    text = "This is an ip address in a CDN."
                text += " CDN ip addresses change regularly, and are not very useful to track. "
                if score_lowered and date_shortened:
                    text += " The score is adjusted downwards, and the valid until date set to 1 day."
                elif score_lowered:
                    text += " The score is adjusted downwards."

            elif data["cloud"]:
                if data["cloud_provider"]:
                    text = (
                        "This is an ip address in the "
                        + data["cloud_provider"]
                        + " cloud."
                    )
                else:
                    text = "This is an ip address in a cloud."
                text += " Cloud ip addresses change regularly, and are not very useful to track. "
                if score_lowered and date_shortened:
                    text += " The score is adjusted downwards, and the valid until date set to 1 day."
                elif score_lowered:
                    text += " The score is adjusted downwards."

            elif data["vpn"]:
                text = "This ip address is a VPN."
                text += " VPN ip addresses change regularly, and are not very useful to track. "
                if score_lowered and date_shortened:
                    text += " The score is adjusted downwards, and the valid until date set to 1 day."
                elif score_lowered:
                    text += " The score is adjusted downwards."

            elif data["public_dns"]:
                text = "This ip address is a public DNS server."
                text += " Public DNS servers are often used in malware to check for an internet connection, "
                text += "and automated analysis tools regularly extract them as indicators. This is not very useful."
                if self.replace_with_lower_score:
                    text += " The score is adjusted downwards."

            if text:
                description += "\n[ShadowTrackr] " + text
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
                    return (
                        "Found data on "
                        + ip
                        + ". Score not changed, but valid_until shortened to 1 day."
                    )
                else:
                    return "Found data on " + ip + ". Score not changed."
            else:
                serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(serialized_bundle)
                if date_shortened:
                    return (
                        "Found data on "
                        + ip
                        + ". Score changed from "
                        + str(old_score)
                        + " to "
                        + str(score)
                        + ", valid_until shortened to 1 day."
                    )
                else:
                    return (
                        "Found data on "
                        + ip
                        + ". Score changed from "
                        + str(old_score)
                        + " to "
                        + str(score)
                    )

        return "Invalid ip: " + ip

    def _process_message(self, data: Dict) -> str:
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]
        return self._process_entity(stix_objects, stix_entity, opencti_entity)

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)

    def _check_ip_in_shadowtrackr(self, ip, labels=None) -> dict:
        if labels:
            labels = ",".join(labels)
        else:
            labels = ""

        base_url = "https://shadowtrackr.com/api/v3/ip_info"
        full_url = (
            base_url + "?api_key=" + self.api_key + "&ip=" + ip + "&tags=" + labels
        )
        response = requests.get(full_url)
        data = json.loads(response.text)
        return data

    def _valid_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False


if __name__ == "__main__":
    ShadowTrackrInstance = ShadowTrackrConnector()
    ShadowTrackrInstance.start()
