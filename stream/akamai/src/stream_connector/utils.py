import ipaddress
import re


def is_ip(value: str) -> bool:
    """
    Validate whether a string is a valid IP address or CIDR.
    """
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def is_asn(value: str) -> bool:
    """
    Validate whether a string matches ASN format (e.g. AS12345).
    """
    return re.match(r"^AS\d+$", value.upper()) is not None
