import logging
from datetime import datetime, timezone
from uuid import UUID

from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE

TLP_MAP = {
    "TLP:WHITE": TLP_WHITE,
    "TLP:GREEN": TLP_GREEN,
    "TLP:AMBER": TLP_AMBER,
    "TLP:RED": TLP_RED,
}

LOG_LEVEL = logging.INFO


def configure_logger(name):
    """Configure and return a custom logger for the given name."""
    logger = logging.getLogger(name)
    logger.setLevel(LOG_LEVEL)
    logger_handler = logging.StreamHandler()
    formatter = logging.Formatter("{message}", style="{")
    logger_handler.setFormatter(formatter)
    logger.addHandler(logger_handler)
    return logger


def convert_to_datetime(date_str):
    """Convert a date string to a datetime object."""
    LOGGER = configure_logger(__name__)
    try:
        return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")
    except ValueError as e:
        LOGGER.debug(f"Error converting date string: {date_str}:\n{e}")
        return None
    except TypeError as e:
        LOGGER.debug(f"Error converting date string: {date_str}:\n{e}")
        return None
    except Exception as e:
        LOGGER.debug(f"Error converting date string: {date_str}:\n{e}")
        return None


def is_valid_uuid(uuid_to_test: str):
    """Check to see if the given string is a valid UUID."""
    LOGGER = configure_logger(__name__)
    supperted_versions = [1, 3, 4, 5]
    try:
        if isinstance(uuid_to_test, UUID) or isinstance(uuid_to_test, str):
            for version in supperted_versions:
                if str(UUID(uuid_to_test, version=version)) == uuid_to_test:
                    return True
            return False
        else:
            return False
    except ValueError:
        LOGGER.debug(f"Error validating UUID: {uuid_to_test}")
        return False
    except AttributeError:
        LOGGER.debug(f"Error validating UUID: {uuid_to_test}")
        return False
    except Exception as e:
        LOGGER.debug(f"Error validating UUID: {uuid_to_test}:\n{e}")
        return False


def is_valid_stix_id(stix_id):
    """Check to see if the given string is a STIX ID."""
    if isinstance(stix_id, str) and "--" in stix_id:
        stix_id_list = stix_id.split("--")
        if is_valid_uuid(stix_id_list[1]) and len(stix_id_list) == 2:
            return True
    return False


def is_valid_entry_timestamp(entry_timestamp: str, min_datetime: datetime = None):
    """Check to see if entry timestamp is an accepted datetime"""
    if not entry_timestamp:
        return False
    if entry_timestamp and min_datetime is None:
        return True

    entry_datetime = datetime.fromisoformat(entry_timestamp).replace(
        tzinfo=timezone.utc
    )
    return entry_datetime > min_datetime
