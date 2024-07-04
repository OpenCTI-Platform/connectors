import hashlib
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Union

import pandas as pd
from stix2.base import _Observable as Observable

from .constants import REQUEST_DATE_FORMAT, SEVERITY_MAP, TLP_MAP


# Function to calculate different hashes
def calculate_hashes(data: bytes) -> Dict[str, str]:
    """
    Calculate MD5, SHA-1, SHA-256, and SHA-512 hashes for the given data.

    Args:
        data (bytes): The data to hash.

    Returns:
        dict: A dictionary with the hashes.
    """
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA-1": hashlib.sha1(data).hexdigest(),
        "SHA-256": hashlib.sha256(data).hexdigest(),
        "SHA-512": hashlib.sha512(data).hexdigest(),
    }


def validate_date_format(date_string: str) -> bool:
    """
    Validate the format of a date string.

    Args:
        date_string (str): The date string to validate.

    Returns:
        bool: True if the date string is in the correct format, False otherwise.
    """
    try:
        datetime.strptime(date_string, REQUEST_DATE_FORMAT)
        return True
    except ValueError:
        return False


def validate_marking_refs(marking_refs: str) -> bool:
    """
    Validate the marking references.

    Args:
        marking_refs (str): The marking references to validate.

    Returns:
        bool: True if the marking references are valid, False otherwise.
    """
    if marking_refs in TLP_MAP:
        return True
    raise ValueError(f"Invalid marking references: {marking_refs}")


def datetime_to_string(dt: datetime) -> Optional[str]:
    """
    Converts a datetime object to a string representation in the format "YYYY-MM-DDTHH:MM:SS.sssZ".

    Args:
        dt (datetime): The datetime object to be converted.

    Returns:
        str: The string representation of the datetime object in the specified format. If an error occurs during the conversion, None is returned.
    """
    try:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except AttributeError:
        return None


def string_to_datetime(date_string: str) -> Optional[datetime]:
    """
    Converts a string representation of a date to a datetime object.

    Args:
        date_string (str): The string representation of the date in the format 'YYYY-MM-DD'.

    Returns:
        datetime: The datetime object representing the input date, or None if the input format is incorrect.
    """
    try:
        return datetime.strptime(date_string.split(" ")[0], "%Y-%m-%d")
    except ValueError:
        return None


def note_timestamp_to_datetime(date_string: str) -> datetime:
    """
    Converts a string representation of a timestamp to a datetime object.

    Args:
        date_string (str): The string representation of the timestamp in the format 'YYYY-MM-DD HH:MM:SSZ'.

    Returns:
        datetime: The datetime object representing the input timestamp.
    """
    return datetime.strptime(date_string, "%Y-%m-%d %H:%M:%SZ")


def dicts_to_markdown(dicts_list: Union[List[Dict], Dict]) -> str:
    """
    Converts a list of dictionaries or a single dictionary to a Markdown formatted string.

    Args:
        dicts_list (list of dict or dict): A list of dictionaries or a single dictionary to be converted to Markdown.

    Returns:
        str: A Markdown string representing all the dictionaries.
    """
    if isinstance(dicts_list, dict):
        dicts_list = [dicts_list]

    markdown_output = ""
    for data_dict in dicts_list:
        cleaned_dict = {k: v for k, v in data_dict.items() if v}
        df = pd.DataFrame(cleaned_dict, index=[0]).T.reset_index()
        df.columns = ["Key", "Value"]
        markdown_output += df.to_markdown(index=False) + "\n\n"

    return markdown_output


def check_ip_address(ip_str: str) -> str:
    """
    Check the type of IP address or network from a string.

    Args:
        ip_str (str): The IP address or network string.

    Returns:
        str: The type of IP address or network, or "Invalid IP/CIDR" if invalid.
    """
    try:
        if ipaddress.IPv6Address(ip_str):
            return "IPv6 address"
    except ValueError:
        pass

    try:
        if ipaddress.ip_address(ip_str):
            return "IPv4 address"
    except ValueError:
        pass

    try:
        if ipaddress.IPv6Network(ip_str, strict=False):
            return "IPv6 network (CIDR)"
    except ValueError:
        pass

    try:
        if ipaddress.ip_network(ip_str, strict=False):
            return "IPv4 network (CIDR)"
    except ValueError:
        pass

    return "Invalid IP/CIDR"


def clean_dict(original_dict: Dict) -> Dict:
    """
    Remove None and empty string values from a dictionary.

    Args:
        original_dict (dict): The original dictionary.

    Returns:
        dict: A dictionary with None and empty string values removed.
    """
    return {k: v for k, v in original_dict.items() if v is not None and v != ""}


def clean_list_of_dicts(data_list: List[Dict]) -> List[Dict]:
    """
    Remove None and empty string values from a list of dictionaries.

    Args:
        data_list (list of dict): The original list of dictionaries.

    Returns:
        list of dict: A list of dictionaries with None and empty string values removed.
    """
    return [clean_dict(d) for d in data_list]


def from_list_to_csv(data_list: List[Dict]) -> str:
    """
    Convert a list of dictionaries to a CSV formatted string.

    Args:
        data_list (list of dict): The original list of dictionaries.

    Returns:
        str: A CSV formatted string.
    """
    clean_list = clean_list_of_dicts(data_list)
    df = pd.DataFrame(clean_list)
    return df.to_csv(index=False)


def get_stix_id_precedence(stix_id_list: List[str]) -> Optional[str]:
    """
    Determine the precedence of STIX IDs.

    Args:
        stix_id_list (list of str): A list of STIX IDs.

    Returns:
        str or None: The STIX ID with the highest precedence, or None if the list is empty.
    """
    for stix_id in stix_id_list:
        if (
            stix_id.startswith("ipv4-addr")
            or stix_id.startswith("ipv6-addr")
            or stix_id.startswith("domain-name")
        ):
            return stix_id
    return None


def find_stix_object_by_id(
    stix_objects: List[Observable], target_id: str
) -> Optional[Union[str, None]]:
    """
    Search through a list of STIX2 objects and return the object with the specified ID.

    Args:
        stix_objects (list): A list of STIX2 objects.
        target_id (str): The ID of the STIX2 object to find.

    Returns:
        str or None: The value of the STIX2 object with the matching ID, or None if no match is found.
    """
    for obj in stix_objects:
        if obj.id == target_id:
            return obj.get("value", None)
    return None


def get_tlp_keys():
    """
    Get the TLP keys from the TLP_MAP dictionary.

    Returns:
        list: A list of TLP keys.
    """
    return list(TLP_MAP.keys())


def compare_severity(severity1, severity2):
    """
    Compare two severity values and return the higher severity..

    Args:
        severity1 (str): The first severity value.
        severity2 (str): The second severity value.

    Returns:
        str: The higher severity value.
    """
    if SEVERITY_MAP.get(severity1, 4) <= SEVERITY_MAP.get(severity2, 4):
        return severity1
    else:
        return severity2


def check_keys(dictionary, required_keys):
    """
    Checks if all required keys are present in the dictionary.

    Parameters:
        dictionary (dict): The dictionary to check.
        required_keys (list): A list of keys that are required.

    Returns:
        bool: True if all required keys are present, False otherwise.
    """
    return all(key in dictionary for key in required_keys)
