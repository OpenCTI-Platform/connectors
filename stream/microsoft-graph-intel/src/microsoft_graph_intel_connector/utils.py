from datetime import datetime, timedelta

from pycti import OpenCTIConnectorHelper
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE

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
TLP_AMBER_STRICT_ID = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"

NETWORK_ATTRIBUTES_LIST = [
    "domain-name",
    "hostname",
    "ipv4-addr",
    "ipv6-addr",
    "url",
    "email-addr",
]

FILE_HASH_TYPES_MAPPER = {
    "md5": "md5",
    "sha-1": "sha1",
    "sha1": "sha1",
    "sha-256": "sha256",
    "sha256": "sha256",
}


def is_stix_indicator(data: dict) -> bool:
    """
    Check if data represents a STIX Indicator.
    :param data: Data to check
    :return: True if data represents a STIX Indicator, False otherwise
    """
    return data["type"] == "indicator" and data["pattern_type"].startswith("stix")


def is_observable(data: dict) -> bool:
    """
    Check if data represents a STIX Observable.
    :param data: Data to check
    :return: True if data represents a STIX Observable, False otherwise
    """
    return data["type"] in OBSERVABLE_TYPES


def get_ioc_type(data: dict) -> str | None:
    """
    Get valid IOC type for Sentinel from data.
    :param data: Data to get IOC type from
    :return: IOC type if found, None otherwise
    """
    data_type = data["type"]
    return IOC_TYPES.get(data_type.upper(), None)


def get_threat_type(data: dict) -> str | None:
    """
    Get valid threat type for Sentinel from data.
    :param data: Data to get threat type from
    :return: Threat type if found, None otherwise
    """
    threat_type = "WatchList"
    labels = OpenCTIConnectorHelper.get_attribute_in_extension("labels", data)
    if labels is not None:
        for label in labels:
            threat_type = THREAT_TYPES.get(label.upper(), threat_type)
    return threat_type


def get_description(data: dict) -> str:
    """
    Get a description according to observable.
    :param data: Observable data to extract description from
    :return: Observable description summary or "No Description"
    """
    stix_description = OpenCTIConnectorHelper.get_attribute_in_extension(
        "description", data
    )
    return stix_description[0:99] if stix_description is not None else "No description"


def get_action(data: dict) -> str:
    """
    Get an action according to observable score.
    :param data: Observable data to get action from
    :return: Action name or "unknown"
    """
    score = OpenCTIConnectorHelper.get_attribute_in_extension("score", data)
    action = "unknown"
    if score >= 50:
        action = "block"
    elif 0 < score < 50:
        action = "alert"
    elif score == 0:
        action = "allow"
    return action


def get_severity(data: dict) -> str:
    """
    Get severity according to observable score.
    :param data: Observable data to get action from
    :return: Severity or "unknown"
    """
    score = OpenCTIConnectorHelper.get_attribute_in_extension("score", data)
    if score >= 70:
        severity = 5
    elif score >= 50:
        severity = 4
    elif score >= 30:
        severity = 3
    elif score >= 10:
        severity = 2
    elif score > 0:
        severity = 1
    else:
        severity = 0
    return severity


def get_expiration_datetime(data: dict, expiration_time: int) -> str:
    """
    Get an expiration datetime for an observable.
    :param data: Observable data to calculate expiration with
    :param expiration_time: Duration after which observable is considered as expired
    :return: Datetime of observable expiration
    """
    updated_at = OpenCTIConnectorHelper.get_attribute_in_extension("updated_at", data)
    datetime_object = datetime.fromisoformat(updated_at)
    age = timedelta(expiration_time)
    expire_datetime = datetime_object + age
    expiration_datetime = expire_datetime.isoformat()
    return expiration_datetime


def get_tlp_level(data: dict) -> str:
    """
    Get a TLP level for an observable.
    :param data: Observable data to extract TLP level from
    :return: TLP level or "unknown"
    """
    tlp_level = "unknown"
    if "object_marking_refs" in data:
        marking_refs = data["object_marking_refs"]
        if TLP_RED.id in marking_refs:
            tlp_level = "red"
        elif TLP_AMBER.id in marking_refs or TLP_AMBER_STRICT_ID in marking_refs:
            tlp_level = "amber"
        elif TLP_GREEN.id in marking_refs:
            tlp_level = "green"
        elif TLP_WHITE.id in marking_refs:
            tlp_level = "white"
    return tlp_level


def get_tags(data: dict) -> list[str]:
    """
    Get tags for an observable.
    :param data: Observable data to extract tags from
    :return: List of tags
    """
    tags = ["opencti"]
    labels = OpenCTIConnectorHelper.get_attribute_in_extension("labels", data)
    return tags + labels if labels is not None else tags


def get_hash_type(data: dict) -> str | None:
    """
    Get hash type for a file.
    :param data: File data to get hash type for
    :return: Hash type
    """
    if data["type"] != "file":
        raise ValueError("Data type is not file")

    hash_type = None

    # data["hashes"] contains only one item
    for key in data["hashes"]:
        hash_type = FILE_HASH_TYPES_MAPPER[key]

    return hash_type


def get_hash_value(data: dict) -> str | None:
    """
    Get hash value for a file.
    :param data: File data to get hash value for
    :return: Hash value
    """
    if data["type"] != "file":
        raise ValueError("Data type is not file")

    hash_value = None

    for key in data["hashes"]:
        hash_type = FILE_HASH_TYPES_MAPPER[key]
        hash_value = data["hashes"].get(hash_type)
    return hash_value
