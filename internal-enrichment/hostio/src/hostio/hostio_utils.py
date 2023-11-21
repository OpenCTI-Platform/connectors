from ipaddress import (
    AddressValueError,
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
)
import re
import json
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE

TLP_MAP = {
    "TLP:WHITE": TLP_WHITE,
    "TLP:GREEN": TLP_GREEN,
    "TLP:AMBER": TLP_AMBER,
    "TLP:RED": TLP_RED,
}


def is_ipv6(ip_str):
    """Determine whether the provided string is an IPv6 address or valid IPv6 CIDR."""
    try:
        IPv6Address(ip_str)  # Check for individual IP
        return True
    except AddressValueError:
        try:
            IPv6Network(ip_str, strict=False)  # Check for CIDR notation
            return True
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
            return True
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
        return TLP_MAP[tlp.upper()]
    else:
        raise ValueError(
            f"Invalid TLP marking: {tlp}, valid markings: {TLP_MAP.keys()}"
        )


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
            return None
        match = re.search(r'(\d+)$', asn_string)
        if match:
            return int(match.group(1))  # Returns only the number part
        return None  # Return None if no match is found
    except:
        return None
    
def object_to_pretty_json(obj):
    """Return a pretty JSON string from a Python object."""
    return json.dumps(obj, sort_keys=True, indent=4, separators=(",", ": "))