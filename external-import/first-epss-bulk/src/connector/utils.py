"""Connector Utils."""

import re
from datetime import datetime


def is_cve_format(string: str) -> bool:
    """Check if string is in CVE identifier format
    :param string: String to be checked
    :return: True if string is in CVE identifier format. False otherwise.
    """

    regex = r"^CVE-\d{4}-\d{4,7}$"
    if re.match(regex, string):
        return True

    return False


def time_from_unixtime(timestamp: int):
    return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
