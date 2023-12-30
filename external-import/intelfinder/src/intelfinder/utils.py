import logging
from datetime import datetime

from pandas import DataFrame
from pycti import Identity as pycti_identity
from stix2 import Identity

from .constants import RABBITMQ_MAX_DEFAULT, TLP_MAPPINGS, TRUNCATE_MESSAGE

LOGGER = logging.getLogger(__name__)


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


def create_markdown_table(name, data):
    """Creates a markdown table from a list of dictionaries, ensuring multiline values are handled correctly."""
    table_data = []
    append_data = str()
    markdown_table_str = "\n---\n"
    try:
        modified_data = truncate_data(name, data)
        for element in modified_data:
            label, value = element["label"], element["value"]
            # If value is multiline, append to the end of the table
            if "\n" in value:
                LOGGER.debug(f"Appending multiline data to ({name}) markdown table.")
                append_data += f"\n---\n**{label}**:\n\n```\n{value}\n```"
            else:
                table_data.append({"Label": f"**{label}**", "Value": f"{value}"})
        markdown_table_str += str(DataFrame(data=table_data).to_markdown(index=False))
        if append_data:
            LOGGER.debug(f"Appending data to ({name}) markdown table.")
            markdown_table_str += f"{append_data}\n---\n"
        return markdown_table_str
    except Exception as e:
        return f"\n\nError creating markdown table: {e}"


def truncate_data(name, content):
    """Markdownify content and truncate to RABBITMQ_MAX_DEFAULT"""
    if content and isinstance(content, dict):
        content_max = int(RABBITMQ_MAX_DEFAULT * 0.8)
        while len(str(content)) > content_max:
            largest_key = max(content, key=lambda k: len(str(content[k])))
            LOGGER.warning(
                f"Truncating ({largest_key}) from ({name}) due to size limit."
            )
            content[largest_key] = TRUNCATE_MESSAGE
        return content
    else:
        return content


def truncate_content(name, content):
    """Markdownify content and truncate to RABBITMQ_MAX_DEFAULT"""
    if content and isinstance(content, str):
        content_max = int(RABBITMQ_MAX_DEFAULT * 0.8)
        LOGGER.warning(
            f"Processing truncation for ({name}) content length ({len(content)}) max is set ({content_max})."
        )
        truncated = False
        while len(content) > content_max:
            LOGGER.debug(f"Truncating loop for ({name}) due to size limit.")
            truncated = True
            # Remove the last line
            content = content[: content.rfind("\n", 0, content_max)]
        if truncated:
            LOGGER.warning(f"Truncating ({name}) due to size limit.")
            content += f"\n\n{TRUNCATE_MESSAGE}"
        return content
    else:
        return content


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


def create_author():
    """Creates Intelfinder Author"""
    return Identity(
        id=pycti_identity.generate_id("Intelfinder", "organization"),
        name="Intelfinder Connector",
        identity_class="organization",
    )
