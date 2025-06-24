"""The module defines an enumeration for various hashing algorithms."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class HashAlgorithmOV(BaseOV):
    """Hash Algorithm Enumeration."""

    MD5 = "MD5"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    SHA512 = "SHA-512"
    SHA3_256 = "SHA3-256"
    SHA3_512 = "SHA3-512"
    SSDEEP = "SSDEEP"
