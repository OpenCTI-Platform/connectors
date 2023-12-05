from datetime import datetime

from pandas import DataFrame

from .constants import TLP_MAPPINGS


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
    table_data = []
    pastebin_data = ""
    try:
        for element in data:
            label, value = element["label"], element["value"]
            if label.startswith("Paste"):
                pastebin_data += f"\n\nPastebin Data:\n\n```\n\n{value}\n\n```"
            else:
                table_data.append(element)

        markdown_table_str = DataFrame(data=table_data).to_markdown(index=False)
        return f"\n\n{markdown_table_str}{pastebin_data}"
    except Exception as e:
        return f"\n\nError creating markdown table: {e}"


def validate_tlp_marking(tlp):
    """Determine whether the provided string is a valid TLP marking."""
    if isinstance(tlp, str) and tlp.upper() in TLP_MAPPINGS.keys():
        return True
    else:
        raise ValueError(
            f"Invalid TLP marking: {tlp}, valid markings: {TLP_MAPPINGS.keys()}"
        )


def get_tlp_marking(tlp):
    """Validate TLP marking and return STIX2 TLP marking."""
    if validate_tlp_marking(tlp):
        return TLP_MAPPINGS.get(tlp.upper())
    else:
        raise ValueError(
            f"Invalid TLP marking: {tlp}, valid markings: {TLP_MAPPINGS.keys()}"
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
