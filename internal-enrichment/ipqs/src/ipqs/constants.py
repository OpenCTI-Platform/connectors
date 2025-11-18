from enum import Enum

# Connector constants

SOURCE_NAME = "IPQS"

IP_ENRICH = "ip"
URL_ENRICH = "url"
EMAIL_ENRICH = "email"
PHONE_ENRICH = "phone"
LEAK_ENRICH_USERNAME = "username_email"
LEAK_ENRICH_PASSWORD = "leaked_Password"

# Enrichment field mappings

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


class RiskCriticality(Enum):
    CLEAN = "CLEAN"
    LOW = "LOW RISK"
    MEDIUM = "MODERATE RISK"
    HIGH = "HIGH RISK"
    CRITICAL = "CRITICAL"
    INVALID = "INVALID"
    SUSPICIOUS = "SUSPICIOUS"
    MALWARE = "CRITICAL"
    PHISHING = "CRITICAL"
    DISPOSABLE = "CRITICAL"


class RiskColor(Enum):
    WHITE = "#CCCCCC"
    GREY = "#CDCDCD"
    YELLOW = "#FFCF00"
    RED = "#D10028"
