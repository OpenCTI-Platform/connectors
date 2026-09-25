#  Utilities: helper functions, classes, or modules that provide common, reusable functionality across a codebase
import re

# CrowdStrike returns nanosecond precision timestamps (2026-06-04T02:44:44.587772921Z)
# while STIX only accepts up to microseconds.
_OVER_PRECISE_FRACTION = re.compile(r"(\.\d{6})\d+")


def normalize_timestamp(value):
    """
    Truncate the fractional seconds of a CrowdStrike timestamp so that it can be
    used in a STIX object
    :param value: Timestamp as returned by the API
    :return: Timestamp usable by the stix2 library, or None
    """
    if not value:
        return None
    return _OVER_PRECISE_FRACTION.sub(r"\1", str(value).strip())


def extract_directory_path(filepath, filename=None):
    """
    Extract the directory of a CrowdStrike file path.

    CrowdStrike is not consistent: `filepath` holds the full path including the
    file name for the triggering process, but only the directory in the
    `files_written` entries. The file name is therefore stripped only when the
    path actually ends with it.

    :param filepath: Path as returned by the API, e.g.
        \Device\HarddiskVolume4\Windows\System32\powershell.exe
    :param filename: File name as returned by the API, e.g. powershell.exe
    :return: Directory path, or None when there is nothing usable
    """
    if not filepath:
        return None

    path = str(filepath).rstrip("\\/")
    if filename:
        separator = "\\" if "\\" in path else "/"
        if path.lower().endswith(f"{separator}{str(filename).lower()}"):
            path = path[: -(len(str(filename)) + 1)]

    path = path.rstrip("\\/")
    return path or None


def detect_ip_version(value):
    if re.match(
            r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}(\/([1-9]|[1-2]\d|3[0-2]))?$",
            value,
    ):
        return "ipv4"
    else:
        return "ipv6"
