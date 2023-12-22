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
