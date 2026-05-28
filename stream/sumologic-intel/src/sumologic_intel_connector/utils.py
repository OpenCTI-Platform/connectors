#  Utilities: helper functions, classes, or modules that provide common, reusable functionality across a codebase


def is_stix_indicator(data: dict) -> bool:
    """
    Check if data represents a STIX Indicator.
    :param data: Data to check
    :return: True if data represents a STIX Indicator, False otherwise
    """
    return data["type"] == "indicator" and data["pattern_type"].startswith("stix")
