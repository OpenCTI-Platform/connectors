from pycti import OpenCTIConnectorHelper
from datetime import datetime, timedelta


OBSERVABLE_TYPES = [
    "ipv4-addr",
    "ipv6-addr",
    "domain-name",
    "hostname",
    "url",
    "email-addr",
    "file",
]
IOC_TYPES = {
    "IPV4-ADDR": "networkIPv4",
    "IPV6-ADDR": "networkIPv6",
    "DOMAIN-NAME": "domainName",
    "EMAIL-ADDR": "email",
    "URL": "url",
    "FILE": "file",
}
THREAT_TYPES = {
    "BOTNET": "Botnet",
    "C2": "C2",
    "CRYPTOMINING": "CryptoMining",
    "DARKNET": "Darknet",
    "DDOS": "DDoS",
    "MALICIOUSURL": "MaliciousUrl",
    "MALWARE": "Malware",
    "PHISHING": "Phishing",
    "PROXY": "Proxy",
    "PUA": "PUA",
}


def is_stix_indicator(data) -> bool:
    return data["type"] == "indicator" and data["pattern_type"].startswith("stix")


def is_observable(data) -> bool:
    return data["type"] in OBSERVABLE_TYPES


def get_ioc_type(data) -> str:
    data_type = data["type"]
    return IOC_TYPES.get(data_type.upper(), None)


def get_threat_type(data) -> str:
    threat_type = "WatchList"
    labels = OpenCTIConnectorHelper.get_attribute_in_extension("labels", data)
    if labels is not None:
        for label in labels:
            threat_type = THREAT_TYPES.get(label.upper(), threat_type)
    return threat_type


def get_description(data) -> str:
    stix_description = OpenCTIConnectorHelper.get_attribute_in_extension(
        "description", data
    )
    return stix_description[0:99] if stix_description is not None else "No description"


def get_action(data):
    score = OpenCTIConnectorHelper.get_attribute_in_extension("score", data)
    if score is None:
        action = "unknown"
    elif score >= 50:  # self.config.confidence_levek == 50
        action = "block"
    elif score < 50 and score != 0:  # self.config.confidence_levek == 50
        action = "alert"
    elif score == 0:
        action = "allow"
    else:
        action = "unknown"
    return action


def get_expiration_datetime(data, expiration_time: int):
    updated_at = OpenCTIConnectorHelper.get_attribute_in_extension("updated_at", data)
    datetime_object = datetime.strptime(updated_at, "%Y-%m-%dT%H:%M:%S.%fZ")
    age = timedelta(expiration_time)
    expire_datetime = datetime_object + age
    expiration_datetime = expire_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
    return expiration_datetime


def get_tlp_level(data) -> str:
    if "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed" in str(data):
        tlp_level = "red"
    elif "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37" in str(
        data
    ) or "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82" in str(data):
        tlp_level = "amber"
    elif "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da" in str(data):
        tlp_level = "green"
    elif "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9" in str(data):
        tlp_level = "white"
    else:
        tlp_level = "unknown"
    return tlp_level


def get_tags(data) -> list[str]:
    tags = ["opencti"]
    labels = OpenCTIConnectorHelper.get_attribute_in_extension("labels", data)
    return tags + labels if labels is not None else tags


def get_hash_type(data) -> str:
    if data["type"] != "file":
        raise ValueError("Data type is not file")

    if "MD5" in data["hashes"]:
        return "md5"
    if "SHA-1" in data["hashes"]:
        return "sha1"
    if "SHA-256" in data["hashes"]:
        return "sha256"


def get_hash_value(data) -> str:
    if data["type"] != "file":
        raise ValueError("Data type is not file")

    if "MD5" in data["hashes"]:
        return data["hashes"]["MD5"]
    if "SHA-1" in data["hashes"]:
        return data["hashes"]["SHA-1"]
    if "SHA-256" in data["hashes"]:
        return data["hashes"]["SHA-256"]
