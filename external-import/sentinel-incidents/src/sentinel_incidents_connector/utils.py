import ipaddress
from datetime import datetime

import stix2
from dateutil.parser import parse

CASE_INCIDENT_PRIORITIES = {
    "unknown": "P3",
    "informational": "P4",
    "low": "P3",
    "medium": "P2",
    "high": "P1",
    "unknownFutureValue": "P3",
}


def format_datetime(date_str: str | None) -> str:
    """
    Formats a date string in ISO 8601 format to ensure compatibility with STIX format by removing microseconds and
    replacing the '+00:00' timezone suffix with 'Z'. If `date_str` is `None` or empty, returns the current UTC time
    in ISO 8601 format with 'Z' as the timezone indicator.

    :param date_str: The date string to be formatted, expected in ISO 8601 format.
    :return: The formatted date string in ISO 8601 format with 'Z' as the timezone indicator.
    """
    if date_str is not None and date_str.strip():
        from_iso_format = datetime.fromisoformat(date_str)
        iso_date_str = (
            from_iso_format.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )
        return iso_date_str
    else:
        now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        return now


def format_incident(incident: dict) -> dict:
    """
    Parse and format Microsoft Sentinel incident so it's compliant with connector expectations.
    :param incident: Microsoft Sentinel incident to format
    :return: Formatted incident
    """
    incident_last_update_timestamp = parse(incident["lastUpdateDateTime"]).timestamp()
    incident["lastUpdateDateTime"] = int(round(incident_last_update_timestamp))

    return incident


def validate_incident(incident: dict, last_incident_date: int) -> bool:
    """
    Validate incident according to its state or creation date.
    :param incident: Incident to validate
    :param last_incident_date: Last imported incident date
    :return: True if the incident is still valid, otherwise False
    """
    if incident["status"] == "resolved":
        return False

    return incident["lastUpdateDateTime"] > last_incident_date


def is_ipv4(value: str) -> bool:
    """
    Determine whether the provided IP string is IPv4 or not
    :param value: Value in string
    :return: True is value is a valid IP address, otherwise False
    """
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def find_matching_file_ids(malware_name: str, stix_objects: list) -> list | None:
    """
    Find and return the list of STIX 2.1 File objects that match the given malware name.
    :param malware_name: The name of the malware to search for. This is compared to the 'name' field
                         of STIX `File` objects within the provided list.
    :param stix_objects: A list of STIX 2.1 objects, which may include `File` objects and other STIX
                         object types. Only `File` objects will be considered.

    :return: A list of STIX `File` objects that have a `name` matching the provided malware name.
             If no matching files are found, an empty list is returned.
    """
    matching_stix_files = []
    for stix_object in stix_objects:
        if isinstance(stix_object, stix2.File):
            stix_file_name = stix_object.get("name")
            if stix_file_name == malware_name:
                matching_stix_files.append(stix_object)

    return matching_stix_files
