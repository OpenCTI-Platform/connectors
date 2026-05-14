"""Static metadata for the IPQS enrichment connector.

Centralising endpoint slugs, label/colour mappings and per-endpoint field
maps keeps :mod:`client`, :mod:`builder` and :mod:`ipqs` free of magic
strings and makes adding new endpoints a one-file change.
"""

from enum import Enum

# Connector ----------------------------------------------------------------
SOURCE_NAME = "IPQS"

# IPQualityScore endpoint slugs.
IP_ENRICH = "ip"
URL_ENRICH = "url"
EMAIL_ENRICH = "email"
PHONE_ENRICH = "phone"
# ``leaked/<kind>`` family of endpoints. ``kind`` is decided at call time
# based on what is found on the User-Account observable (email / username /
# password).
LEAK_USERNAME_OR_EMAIL = "leaked-username-or-email"
LEAK_PASSWORD = "leaked-password"

# Per-endpoint field maps -------------------------------------------------
# ``key`` is the property name returned by IPQS, ``value`` is the human label
# rendered in the indicator description.
IP_ENRICH_FIELDS = {
    "zip_code": "Zip Code",
    "ISP": "ISP",
    "ASN": "ASN",
    "organization": "Organization",
    "is_crawler": "Is Crawler",
    "timezone": "Timezone",
    "mobile": "Mobile",
    "host": "Host",
    "proxy": "Proxy",
    "vpn": "VPN",
    "tor": "TOR",
    "active_vpn": "Active VPN",
    "active_tor": "Active TOR",
    "recent_abuse": "Recent Abuse",
    "bot_status": "Bot Status",
    "connection_type": "Connection Type",
    "abuse_velocity": "Abuse Velocity",
    "country_code": "Country Code",
    "region": "Region",
    "city": "City",
    "latitude": "Latitude",
    "longitude": "Longitude",
}

URL_ENRICH_FIELDS = {
    "unsafe": "Unsafe",
    "server": "Server",
    "domain_rank": "Domain Rank",
    "dns_valid": "DNS Valid",
    "parking": "Parking",
    "spamming": "Spamming",
    "malware": "Malware",
    "phishing": "Phishing",
    "suspicious": "Suspicious",
    "adult": "Adult",
    "category": "Category",
    "domain_age": "Domain Age",
    "domain": "IPQS: Domain",
    "ip_address": "IPQS: IP Address",
}

EMAIL_ENRICH_FIELDS = {
    "valid": "Valid",
    "disposable": "Disposable",
    "smtp_score": "SMTP Score",
    "overall_score": "Overall Score",
    "first_name": "First Name",
    "generic": "Generic",
    "common": "Common",
    "dns_valid": "DNS Valid",
    "honeypot": "Honeypot",
    "deliverability": "Deliverability",
    "frequent_complainer": "Frequent Complainer",
    "spam_trap_score": "Spam Trap Score",
    "catch_all": "Catch All",
    "timed_out": "Timed Out",
    "suspect": "Suspect",
    "recent_abuse": "Recent Abuse",
    "suggested_domain": "Suggested Domain",
    "leaked": "Leaked",
    "sanitized_email": "Sanitized Email",
    "domain_age": "Domain Age",
    "first_seen": "First Seen",
}

PHONE_ENRICH_FIELDS = {
    "formatted": "Formatted",
    "local_format": "Local Format",
    "valid": "Valid",
    "recent_abuse": "Recent Abuse",
    "VOIP": "VOIP",
    "prepaid": "Prepaid",
    "risky": "Risky",
    "active": "Active",
    "carrier": "Carrier",
    "line_type": "Line Type",
    "city": "City",
    "zip_code": "Zip Code",
    "dialing_code": "Dialing Code",
    "active_status": "Active Status",
    "leaked": "Leaked",
    "name": "Name",
    "timezone": "Timezone",
    "do_not_call": "Do Not Call",
    "country": "Country",
    "region": "Region",
}

# Risk model --------------------------------------------------------------


class RiskCriticality(Enum):
    """Symbolic risk levels rendered into ``IPQS:VERDICT`` labels.

    Malware / phishing / disposable verdicts map to :attr:`CRITICAL`
    directly at the call site (the IPQS UI exposes them under the same
    ``IPQS:VERDICT="CRITICAL"`` label). Adding distinct enum members
    with the same value would only create aliases (Python enums
    collapse members with the same value), so they live as call-site
    constants in :mod:`.builder` instead.
    """

    CLEAN = "CLEAN"
    LOW = "LOW RISK"
    MEDIUM = "MODERATE RISK"
    HIGH = "HIGH RISK"
    CRITICAL = "CRITICAL"
    INVALID = "INVALID"
    SUSPICIOUS = "SUSPICIOUS"


class RiskColor(Enum):
    """Hex colours used for the IPQS:VERDICT OpenCTI labels."""

    WHITE = "#CCCCCC"
    GREY = "#CDCDCD"
    YELLOW = "#FFCF00"
    RED = "#D10028"
