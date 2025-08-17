from datetime import datetime

from validators import domain, hashes, ip_address, url  # type: ignore


def is_ipv4(value: str) -> bool:
    """
    Return whether given value is a valid IPv4 address.
    """
    return ip_address.ipv4(value) is True


def is_ipv6(value: str) -> bool:
    """
    Return whether given value is a valid IPv6 address.
    """
    return ip_address.ipv6(value) is True


def is_domain(value: str) -> bool:
    """
    Return whether given value is a valid Domain name.
    """
    return domain(value) is True


def is_url(value: str) -> bool:
    """
    Valid url
    :param value: Value in string
    :return: A boolean
    """
    is_valid_url = url(value)

    if is_valid_url:
        return True
    else:
        return False


def is_md5(value: str) -> bool:
    """
    Return whether given value is a valid MD5 hash.
    """
    return hashes.md5(value) is True


def is_sha1(value: str) -> bool:
    """
    Return whether given value is a valid SHA-1 hash.
    """
    return hashes.sha1(value) is True


def is_sha256(value: str) -> bool:
    """
    Return whether given value is a valid SHA-256 hash.
    """
    return hashes.sha256(value) is True


def is_sha512(value: str) -> bool:
    """
    Return whether given value is a valid SHA-512 hash.
    """
    return hashes.sha512(value) is True


def create_indicator_pattern(value: str) -> str:
    """
    Create indicator pattern
    :param value: Value in string
    :return: String of the pattern
    """
    if is_ipv6(value) is True:
        return f"[ipv6-addr:value = '{value}']"
    elif is_ipv4(value) is True:
        return f"[ipv4-addr:value = '{value}']"
    elif is_domain(value) is True:
        return f"[domain-name:value = '{value}']"
    elif is_url(value) is True:
        return f"[url:value = '{value}']"
    else:
        raise ValueError(
            f"This pattern value {value} is not a valid IPv4 or IPv6 address or Domain name nor URL"
        )


def convert_timestamp_to_iso_format(timestamp: str) -> datetime:
    """
    Convert timestamp to ISO format
    """
    return datetime.fromisoformat(timestamp)
