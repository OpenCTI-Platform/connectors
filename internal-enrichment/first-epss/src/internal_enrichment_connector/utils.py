#  Utilities: helper functions, classes, or modules that provide common, reusable functionality across a codebase
import re


def is_cve_format(string: str) -> bool:
    """
    Check if a string is in CVE identifier format
    :param string: String to be checked
    :return: True if the string is in CVE identifier format, False otherwise
    """

    regex = r"^CVE-\d{4}-\d{4,7}$"  # represents CVE id format (CVE-YYYY-NNNNNNN)
    if re.match(regex, string):
        return True

    return False
