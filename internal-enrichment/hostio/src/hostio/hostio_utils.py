import logging
import re
from ipaddress import (
    AddressValueError,
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
)
from json import loads

from pandas import DataFrame
from pycti import Identity as pycti_identity
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE, Identity, MarkingDefinition

LOGGER = logging.getLogger(__name__)

TLP_MAP = {
    "TLP:WHITE": TLP_WHITE,
    "TLP:GREEN": TLP_GREEN,
    "TLP:AMBER": TLP_AMBER,
    "TLP:RED": TLP_RED,
}
UNSUPPORTED_VALUES = ["", "None", None, [], {}]


def is_json_string(json_string: str):
    """Determine whether the provided string is a valid JSON string."""
    try:
        loads(json_string)
        return True
    except Exception:
        return False


def is_ipv6(ip_str):
    """Determine whether the provided string is an IPv6 address or valid IPv6 CIDR."""
    try:
        IPv6Address(ip_str)  # Check for individual IP
        return True
    except AddressValueError:
        try:
            IPv6Network(ip_str, strict=False)  # Check for CIDR notation
            return False
        except Exception:
            return False
    except Exception:
        return False


def is_ipv4(ip_str):
    """Determine whether the provided string is an IPv4 address or valid IPv4 CIDR."""
    try:
        IPv4Address(ip_str)  # Check for individual IP
        return True
    except AddressValueError:
        try:
            IPv4Network(ip_str, strict=False)  # Check for CIDR notation
            return False
        except Exception:
            return False
    except Exception:
        return False


def is_valid_token(token):
    """Determine whether the provided string is a valid token."""
    if isinstance(token, str) and len(token) == 14 and token.isalnum():
        return True
    else:
        return False


def validate_tlp_marking(tlp):
    """Determine whether the provided string is a valid TLP marking."""
    if isinstance(tlp, str) and tlp.upper() in TLP_MAP.keys():
        return True
    else:
        raise ValueError(
            f"Invalid TLP marking: {tlp}, valid markings: {TLP_MAP.keys()}"
        )


def validate_labels(labels):
    """Determine whether the provided string is a valid labels."""
    if isinstance(labels, str) and len(labels) > 0:
        return True
    elif isinstance(labels, list) and len(labels) > 0:
        return True
    elif isinstance(labels, (list, str)) and len(labels) == 0:
        return True
    else:
        raise ValueError(
            f"Invalid labels: {labels}, valid labels: list or comma-separated string"
        )


def get_tlp_marking(tlp):
    """Validate TLP marking and return STIX2 TLP marking."""
    if validate_tlp_marking(tlp):
        return TLP_MAP.get(tlp.upper())
    else:
        raise ValueError(
            f"Invalid TLP marking: {tlp}, valid markings: {TLP_MAP.keys()}"
        )


def lookup_tlp_string(tlp_value):
    """
    Lookup the string key for a given TLP value.
    """
    if isinstance(tlp_value, MarkingDefinition):
        for key, value in TLP_MAP.items():
            if value == tlp_value:
                return key
    return None


def format_labels(labels):
    """Validate labels and return list of labels."""
    if not validate_labels(labels):
        raise ValueError(
            f"Invalid labels: {labels}, valid labels: list or comma-separated string"
        )
    if isinstance(labels, str) and len(labels) > 0:
        return labels.split(",")
    elif isinstance(labels, list) and len(labels) > 0:
        return labels
    elif isinstance(labels, (list, str)) and len(labels) == 0:
        return []
    else:
        raise ValueError(
            f"Invalid labels: {labels}, valid labels: list or comma-separated string"
        )


def can_be_int(string):
    """Determine whether the provided string can be converted to an integer."""
    try:
        if isinstance(string, bool):
            return False
        if isinstance(string, (str, int)):
            int(string)
            return True
    except ValueError:
        return False
    except Exception:
        return False
    return False


def extract_asn_number(asn_string):
    """
    Extracts the ASN number from a string using regex.
    For example, if the input is 'AS15169', it will return '15169'.
    """
    try:
        if not isinstance(asn_string, str):
            LOGGER.error(f"Error extracting ASN number from {asn_string}")
            return None
        match = re.search(r"(\d+)$", asn_string)
        if match:
            return int(match.group(1))  # Returns only the number part
        LOGGER.error(f"Error extracting ASN number from {asn_string}")
        return None  # Return None if no match is found
    except Exception as e:
        LOGGER.error(f"Error extracting ASN number from {asn_string}, error: {e}")
        return None


def format_list(value: list) -> str:
    """
    Formats a list as a Markdown string.
    """
    return "\n".join(str(item) for item in value)


def format_dict(header: str, value: dict) -> list:
    """
    Formats a dictionary as a pretty Markdown string.
    """
    return dict_to_pretty_markdown(header=header, obj=value)


def format_value(key: str, value) -> list:
    """
    Formats a single value based on its type.
    """
    LOGGER.debug(f"Formatting value for key: {key}, value: {value}")
    if isinstance(value, dict):
        return format_dict(header=key, value=value)
    elif isinstance(value, list):
        formatted_list = format_list(value)
        return [f"**{key}**:\n\n```\n{formatted_list}\n```"]
    elif isinstance(value, str) and is_json_string(value):
        return format_dict(header=key, value=loads(value))
    elif isinstance(value, str) and "\n" in value:
        return [f"**{key}**:\n\n```\n{value}\n```"]
    else:
        return [f"**{key}**:\n\n```{value}```"]


def dict_to_pretty_markdown(header: str, obj: dict) -> list:
    """
    Converts a dictionary to a pretty Markdown-formatted list.
    Handles nested dictionaries, lists, and basic data types.

    Parameters:
    header (str): The header for the Markdown content.
    obj (dict): The dictionary to convert.

    Returns:
    list: A list of Markdown-formatted strings.
    """
    if not isinstance(obj, dict):
        raise ValueError("Input must be a dictionary.")

    note_content = []
    table_content = []

    for key, value in obj.items():
        if value in UNSUPPORTED_VALUES:
            LOGGER.debug(f"Skipping unsupported value for key: {key}")
            continue
        try:
            if isinstance(value, (str, int, float, bool)):
                table_content.append({"key": key, "value": value})
            else:
                formatted_value = format_value(key, value)
                note_content.extend(formatted_value)
        except Exception as e:
            LOGGER.error(f"Error formatting key {key} with value {value}: {e}")

    markdown_output = []
    if table_content:
        df = DataFrame(data=table_content)
        markdown_output.append(
            f"**{header.capitalize()}**:\n\n{df.to_markdown(index=False)}"
        )

    markdown_output.extend(note_content)
    return list(filter(None, markdown_output))


def create_author():
    """Creates HostIO Author"""
    LOGGER.debug("Add Identity Author.")
    return Identity(
        id=pycti_identity.generate_id("HostIO", "organization"),
        name="HostIO Connector",
        identity_class="organization",
    )
