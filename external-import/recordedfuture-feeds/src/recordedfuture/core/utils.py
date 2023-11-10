import ipaddress
import logging
import re
from enum import Enum


class HashTypes(Enum):
    UNKNOWN = "Unknown"
    UNSUPPORTED = "Unsupported"
    MD5 = "MD5"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"
    SHA3256 = "SHA3-256"
    SHA3512 = "SHA3-512"
    SSDEEP = "SSDEEP"
    TLSH = "TLSH"
    RIPEMD160 = "RIPEMD-160"
    CRC32 = "CRC-32"
    # ... Add other hash types as required ...


# supported hashes, https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_muftrcpnf89v
HASH_TYPE_MAPPING = {
    "CRC32": {"normalized": HashTypes.CRC32.value, "supported": False},
    "MD5": {"normalized": HashTypes.MD5.value, "supported": True},
    "SHA1": {"normalized": HashTypes.SHA1.value, "supported": True},
    "SHA256": {"normalized": HashTypes.SHA256.value, "supported": True},
    "SHA384": {"normalized": HashTypes.SHA384.value, "supported": False},
    "SHA512": {"normalized": HashTypes.SHA512.value, "supported": True},
    "SHA3256": {"normalized": HashTypes.SHA3256.value, "supported": True},
    "SHA3512": {"normalized": HashTypes.SHA3512.value, "supported": True},
    "SSDEEP": {"normalized": HashTypes.SSDEEP.value, "supported": True},
    "TLSH": {"normalized": HashTypes.TLSH.value, "supported": True},
    "RIPEMD160": {"normalized": HashTypes.RIPEMD160.value, "supported": False},
    # Add more hash type variations as needed
}

HASH_IDENTIFICATION_BY_LENGTH = {32: HashTypes.MD5, 40: HashTypes.SHA1}

STRIP_NON_ALPHANUMERIC = re.compile(r"[^a-zA-Z0-9]")  # Precompiled regex for efficiency


def configure_logger(name):
    """Configure and return a custom logger for the given name."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger_handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "{asctime} - {name} - {levelname} - {message}", style="{"
    )
    logger_handler.setFormatter(formatter)
    logger.addHandler(logger_handler)
    return logger


def is_ipv6(ip_str):
    """Determine whether the provided IP string is IPv6."""
    try:
        ipaddress.IPv6Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False


def is_ipv4(ip_str):
    """Determine whether the provided IP string is IPv6."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False


def is_url(value):
    """Check if the provided string is a URL."""
    return value.lower().startswith(("http://", "https://"))


def identify_hash(hash_value: str, hash_type: str = None) -> str:
    """Identify the type of hash based on its length and/or provided hash type."""
    logger = configure_logger(__name__)

    if hash_type:
        normalized_type = STRIP_NON_ALPHANUMERIC.sub("", hash_type).upper()
        hash_info = HASH_TYPE_MAPPING.get(normalized_type)

        # Check if hash_info exists
        if not hash_info:
            logger.warning(f"Unsupported hash_type ({hash_type}) for ({hash_value}).")
            return HashTypes.UNKNOWN.value

        if hash_info["supported"]:
            logger.debug(
                f"Mapped hash_type ({hash_info['normalized']}) for ({hash_value})."
            )
            return hash_info["normalized"]
        else:
            logger.debug(
                f"Mapped unsupported hash_type ({hash_info['normalized']}) for ({hash_value})."
            )
            return HashTypes.UNSUPPORTED.value

    # If no hash type is provided, fallback to length-based identification
    return HASH_IDENTIFICATION_BY_LENGTH.get(len(hash_value), HashTypes.UNKNOWN.value)


def validate_required_keys(data_entry, required_keys):
    """Validates if all the required keys are present in the data_entry dictionary."""
    logger = configure_logger(__name__)
    missing_keys = [key for key in required_keys if key not in data_entry]
    if missing_keys:
        logger.warning(f"Missing required keys: {', '.join(missing_keys)}.")
        return False
    else:
        return True
