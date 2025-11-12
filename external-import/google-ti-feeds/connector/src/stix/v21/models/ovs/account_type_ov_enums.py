"""The module defines an the stix2.1 account-type-ov."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class AccountTypeOV(BaseOV):
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
