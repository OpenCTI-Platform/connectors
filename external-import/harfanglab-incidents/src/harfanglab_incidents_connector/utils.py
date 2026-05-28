from validators import domain, hashes, ip_address


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
    return domain.domain(value) is True


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
