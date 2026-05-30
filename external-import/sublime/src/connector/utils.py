def sanitize_email(email):
    """
    Sanitize email address by removing Unicode BOM and other problematic characters.

    Args:
        email (str): Raw email address

    Returns:
        str: Sanitized email address
    """
    if not email:
        return email

    # Remove Unicode BOM (Byte Order Mark) characters
    sanitized = (
        email.replace("\ufeff", "")
        .replace("\ufffe", "")
        .replace("\u00ef\u00bb\u00bf", "")
    )

    # Strip leading/trailing whitespace
    sanitized = sanitized.strip()

    return sanitized


def map_attack_score_to_level(
    set_priority, set_severity, attack_score_verdict, mapping_type
):
    """
    Map Sublime attack score verdict to OpenCTI priority or severity level.

    Attack score verdicts: benign, unknown, graymail, suspicious, malicious, spam

    Args:
        attack_score_verdict (str): Sublime attack score verdict
        mapping_type (str): Either 'priority' or 'severity'

    Returns:
        str: Mapped level (low, medium, high, critical) or None if not configured
    """
    if mapping_type == "priority" and not set_priority:
        return None
    if mapping_type == "severity" and not set_severity:
        return None

    # Verdict to level mapping - OpenCTI expects different values for priority vs severity
    if mapping_type == "priority":
        # Priority uses P1/P2/P3/P4 format (P1 = highest priority)
        verdict_mapping = {
            "malicious": "P1",  # Highest priority
            "suspicious": "P2",  # High priority
            "spam": "P3",  # Medium priority
            "graymail": "P3",  # Medium priority
            "unknown": "P4",  # Low priority
            "benign": "P4",  # Low priority
        }
    else:
        # Severity mapping
        verdict_mapping = {
            "malicious": "high",
            "suspicious": "medium",
            "spam": "low",
            "graymail": "low",
            "unknown": "low",
            "benign": "low",
        }

    verdict = (attack_score_verdict or "unknown").lower()
    default_value = "P4" if mapping_type == "priority" else "low"
    return verdict_mapping.get(verdict, default_value)


def lookup_MDM_value(MDM, value):
    """
    Lookup values in MDM based on their rule structure.
    This may seem overcomplicated compared to parsing JSON but it easier correlates to MQL rule structure.

    Args:
        MDM (dict): Message data to search
        value (str): Dot-separated path (e.g., 'sender.email.email')

    Returns:
        Any: Value at the path, or None if path doesn't exist
    """
    keys = value.split(".")
    value = MDM
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        else:
            return None
    return value
