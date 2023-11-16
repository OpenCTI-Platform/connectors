import logging
from datetime import datetime
from stix2 import TLP_WHITE, TLP_RED, TLP_AMBER, TLP_GREEN
from uuid import UUID

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
    formatter = logging.Formatter(
        "{message}", style="{"
    )
    logger_handler.setFormatter(formatter)
    logger.addHandler(logger_handler)
    return logger

def convert_to_datetime(date_str):
    """Convert a date string to a datetime object."""
    try:
        return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S')
    except ValueError as e:
        return None
    except TypeError as e:
        return None
    except Exception as e:
        return None

def is_valid_uuid(uuid_to_test: str):
    """Check to see if the given string is a valid UUID."""
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
        return False
    except AttributeError:
        return False
    except Exception as e:
        return False

def is_valid_stix_id(stix_id):
    """Check to see if the given string is a STIX ID."""
    if isinstance(stix_id, str) and '--' in stix_id:
        stix_id_list = stix_id.split('--')
        if is_valid_uuid(stix_id_list[1]) and len(stix_id_list) == 2:
            return True
    return False