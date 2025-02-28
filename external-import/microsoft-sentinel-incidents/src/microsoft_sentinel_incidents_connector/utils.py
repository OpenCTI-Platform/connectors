from datetime import datetime

import stix2
from dateutil.parser import parse

CASE_INCIDENT_PRIORITIES = {
    "Unknown": "P3",
    "Informational": "P4",
    "Low": "P3",
    "Medium": "P2",
    "High": "P1",
    "UnknownFutureValue": "P3",
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
        # some 'CreatedTimeUtc' date doesn't contains 'Z' (see malware evidence)
        if not date_str.endswith("Z"):
            date_str += 'Z'
        from_iso_format = datetime.fromisoformat(date_str)
        iso_date_str = (
            from_iso_format.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )
        return iso_date_str
    else:
        now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        return now


def format_date(date: str) -> int:
    incident_last_update_timestamp = parse(date).timestamp()
    return int(round(incident_last_update_timestamp))


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
