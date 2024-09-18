import json

import pytz
from dateutil.parser import parse


def format_alert(alert) -> dict:
    """
    Parse and format Tanium alert so it's compliant with connector expectations.
    :param alert: Tanium alert to format
    :return: Formatted alert
    """
    alert_date = parse(alert["createdAt"]).astimezone(pytz.UTC)
    alert_details = json.loads(alert["details"])
    alert_intel_doc_id = str(alert["intelDocId"])
    alert_description = "Type: " + alert["type"] + " | MatchType:" + alert["matchType"]

    alert["createdAt"] = alert_date
    alert["details"] = alert_details
    alert["intelDocId"] = alert_intel_doc_id
    alert["description"] = alert_description
    return alert


def validate_alert(alert, last_alert_date) -> bool:
    """
    Validate alert according to its state or creation date.
    :param alert: Alert to validate
    :param last_alert_date: Last imported alert date
    :return: True if the alert is still valid, otherwise False
    """
    if alert["state"] == "suppressed":
        return False
    return alert["createdAt"] > last_alert_date


def has_user_details(alert) -> bool:
    """
    Check if alert contains user details.
    :param alert: Alert to check details for
    :return: True if user details have been found, otherwise False
    """
    try:
        match = alert["details"]["match"]  # "match" can be None
        if not match:
            return False
        return bool(match["properties"]["user"])
    except AttributeError:
        return False


def has_file_details(alert) -> bool:
    """
    Check if alert contains file details.
    :param alert: Alert to check details for
    :return: True if file details have been found, otherwise False
    """
    try:
        match = alert["details"]["match"]  # "match" can be None
        if not match:
            return False
        file = match["properties"]["file"]
        if not file:
            return False
        return ("md5" in file) or ("sha256" in file) or ("sha1" in file)
    except AttributeError:
        return False


def has_mitre_attack_details(intel) -> bool:
    """
    Check if alert's intelligence contains MITRE attack details.
    :param intel: Alert's intel to check details for
    :return: True if MITRE attack details have been found, otherwise False
    """
    try:
        mitre_attack = intel["mitreAttack"]  # "mitreAttack" can be None
        if not mitre_attack:
            return False
        return "techniques" in mitre_attack
    except AttributeError:
        return False
