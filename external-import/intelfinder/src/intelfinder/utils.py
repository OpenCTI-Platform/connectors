from datetime import datetime

from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE

TLP_MAP = {
    "TLP:WHITE": TLP_WHITE,
    "TLP:GREEN": TLP_GREEN,
    "TLP:AMBER": TLP_AMBER,
    "TLP:RED": TLP_RED,
}


def validate_api_key(api_key):
    """Validate that the API key is in the correct format."""
    if api_key and isinstance(api_key, str) and len(api_key) == 24:
        return True
    else:
        raise ValueError(
            "API key must be a string of length 24. "
            "Please visit https://dash.intelfinder.io/integrations.php?i=api to get your API key."
        )


def format_datetime(timestamp):
    """formatting the date based on the provided timestamp and time_format."""
    # Parse the timestamp string into a datetime object
    return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")


def create_markdown_table(data):
    """Creates a markdown table from a list of dictionaries, ensuring multiline values are handled correctly."""
    markdown_table = "\n| Label                   | Value                                               |\n"
    markdown_table += "|-------------------------|----------------------------------------------------|\n"
    for item in data:
        # Replace newline characters in the value with spaces
        value = str(item["value"]).replace("\n", "; ")
        markdown_table += f"| {item['label']}{' ' * (25 - len(item['label']))}| {value}{' ' * (50 - len(value))}|\n"
    markdown_table += "\n\n"
    return markdown_table


def validate_tlp_marking(tlp):
    """Determine whether the provided string is a valid TLP marking."""
    if isinstance(tlp, str) and tlp.upper() in TLP_MAP.keys():
        return True
    else:
        raise ValueError(
            f"Invalid TLP marking: {tlp}, valid markings: {TLP_MAP.keys()}"
        )


def get_tlp_marking(tlp):
    """Validate TLP marking and return STIX2 TLP marking."""
    if validate_tlp_marking(tlp):
        return TLP_MAP.get(tlp.upper())
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


def get_cursor_id(alert):
    """Get the cursor id from an alert"""
    if alert.get("update_id"):
        return alert.get("update_id")
    elif alert.get("_id"):
        return alert.get("_id")
    else:
        raise ValueError(f"Alert does not contain a cursor id, {alert}")
