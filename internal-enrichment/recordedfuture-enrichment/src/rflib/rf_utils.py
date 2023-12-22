import ipaddress
import re


def validate_mitre_attack_pattern(pattern):
    """
    Validate a MITRE ATT&CK pattern based on known technique, tactic, and sub-technique IDs.

    Args:
        pattern (str): The MITRE ATT&CK pattern string to validate.

    Returns:
        bool: True if the pattern is valid, False otherwise.
    """
    # Expression will parse the following patterns
    # MITRE ATT&CK Technique IDs (e.g., T1234, T1059.001)
    # MITRE ATT&CK Tactic IDs (e.g., TA0001, )
    mitre_regex_pattern = r"^(T\d{4}(\.\d{3})?|TA\d{4})$"
    # Regular expression for MITRE ATT&CK Technique IDs (e.g., T1234) and Sub-Technique IDs (e.g., T1234.001)
    regex_pattern = re.compile(mitre_regex_pattern)

    # Check if the pattern matches either a technique/sub-technique or tactic ID
    if isinstance(pattern, str) and regex_pattern.match(pattern.upper()):
        return True
    else:
        return False


def extract_and_combine_links(dict_list):
    """
    Extracts 'links' lists from a list of dictionaries and combines them into a single list.

    Args:
        dict_list (list): A list of dictionaries, each potentially containing a 'links' key.

    Returns:
        list: A combined list of all 'links' from the dictionaries.
    """
    combined_links = []

    for d in dict_list:
        links = d.get("links", [])
        combined_links.extend(links)

    return combined_links


def validate_ip_or_cidr(input_str):
    """
    Validate whether a string is a valid IPv4 or IPv6 address, or a CIDR notation.

    Args:
        input_str (str): The IP address or CIDR to validate.

    Returns:
        str: 'IPv4 Address', 'IPv6 Address', 'IPv4 CIDR', 'IPv6 CIDR' if valid,
             'Invalid' if it's neither.
    """
    try:
        # Attempt to parse as an IP address
        ip_addr = ipaddress.ip_address(input_str)
        if isinstance(ip_addr, ipaddress.IPv4Address):
            return "IPv4 Address"
        elif isinstance(ip_addr, ipaddress.IPv6Address):
            return "IPv6 Address"
    except ValueError:
        try:
            # If the above fails, attempt to parse as a network (CIDR)
            network = ipaddress.ip_network(input_str, strict=False)
            if isinstance(network, ipaddress.IPv4Network):
                return "IPv4 CIDR"
            elif isinstance(network, ipaddress.IPv6Network):
                return "IPv6 CIDR"
        except ValueError:
            return "Invalid"
