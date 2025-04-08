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
    "ipv4-addr": "IpAddress",
    "ipv6-addr": "IpAddress",
    "domain-name": "DomainName",
    "hostname": "DomainName",
    "url": "Url",
    "md5": "FileMd5",
    "sha1": "FileSha1",
    "sha256": "FileSha256",
}

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
    Get valid IOC type for Defender from data.
    :param data: Data to get IOC type from
    :return: IOC type if found, None otherwise
    """
    data_type = data["type"]
    return IOC_TYPES.get(data_type.upper(), None)


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
    action = "Audit"
    if score >= 60:
        action = "Block"
    elif 30 < score < 60:
        action = "Alert"
    elif 0 < score < 30:
        action = "Warn"
    elif score == 0:
        action = "Audit"
    return action


def get_severity(data: dict) -> str:
    """
    Get severity according to observable score.
    :param data: Observable data to get action from
    :return: Severity or "unknown"
    """
    score = OpenCTIConnectorHelper.get_attribute_in_extension("score", data)
    if score >= 60:
        severity = "High"
    elif score >= 40:
        severity = "Medium"
    elif score >= 20:
        severity = "Low"
    else:
        severity = "Informational"
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
