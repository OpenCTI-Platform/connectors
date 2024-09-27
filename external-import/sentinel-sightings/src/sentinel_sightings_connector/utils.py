from dateutil.parser import parse
import ipaddress

CASE_INCIDENT_PRIORITIES = {
    "unknown": "P3",
    "informational": "P4",
    "low": "P3",
    "medium": "P2",
    "high": "P1",
    "unknownFutureValue": "P3",
}


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
