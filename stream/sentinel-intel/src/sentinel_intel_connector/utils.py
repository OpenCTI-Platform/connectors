from datetime import datetime, timedelta

from pycti import OpenCTIConnectorHelper

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


def get_expiration_datetime(data: dict, expiration_time: int) -> str:
    """
    Get an expiration datetime for an observable.
    :param data: Observable data to calculate expiration with
    :param expiration_time: Duration after which observable is considered as expired
    :return: Datetime of observable expiration
    """
    updated_at = OpenCTIConnectorHelper.get_attribute_in_extension("updated_at", data)
    datetime_object = datetime.strptime(updated_at, "%Y-%m-%dT%H:%M:%S.%fZ")
    age = timedelta(expiration_time)
    expire_datetime = datetime_object + age
    expiration_datetime = expire_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
    return expiration_datetime


def get_tlp_level(data: dict) -> str:
    """
    Get a TLP level for an observable.
    :param data: Observable data to extract TLP level from
    :return: TLP level or "unknown"
    """
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


def get_tags(data: dict) -> list[str]:
    """
    Get tags for an observable.
    :param data: Observable data to extract tags from
    :return: List of tags
    """
    tags = ["opencti"]
    labels = OpenCTIConnectorHelper.get_attribute_in_extension("labels", data)
    return tags + labels if labels is not None else tags


def get_hash_type(data: dict) -> str:
    """
    Get hash type for a file.
    :param data: File data to get hash type for
    :return: Hash type
    """
    if data["type"] != "file":
        raise ValueError("Data type is not file")

    if "MD5" in data["hashes"]:
        return "md5"
    if "SHA-1" in data["hashes"]:
        return "sha1"
    if "SHA-256" in data["hashes"]:
        return "sha256"


def get_hash_value(data: dict) -> str:
    """
    Get hash value for a file.
    :param data: File data to get hash value for
    :return: Hash value
    """
    if data["type"] != "file":
        raise ValueError("Data type is not file")

    if "MD5" in data["hashes"]:
        return data["hashes"]["MD5"]
    if "SHA-1" in data["hashes"]:
        return data["hashes"]["SHA-1"]
    if "SHA-256" in data["hashes"]:
        return data["hashes"]["SHA-256"]
