"""The module defines an the stix2.1 account-type-ov."""

from enum import Enum


class AccountTypeOV(str, Enum):
    """Account Type OV Enum."""

    FACEBOOK = "facebook"
    LDAP = "ldap"
    NIS = "nis"
    OPENID = "openid"
    RADIUS = "radius"
    SKYPE = "skype"
    TACACS = "tacacs"
    TWITTER = "twitter"
    UNIX = "unix"
    WINDOWS_LOCAL = "windows-local"
    WINDOWS_DOMAIN = "windows-domain"
