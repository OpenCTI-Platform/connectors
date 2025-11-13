# -*- coding: utf-8 -*-
"""Constants for DomainTools."""

from enum import Enum


class EntityType(Enum):
    """Enumeration of possible entities."""

    AUTONOMOUS_SYSTEM = "Autonomous-System"
    DOMAIN_NAME = "Domain-Name"
    EMAIL_ADDRESS = "Email-Addr"
    IPV4 = "IPv4-Addr"


DOMAIN_FIELDS = {
    "mx": "mx-server",
    "name_server": "name-server",
}

IP_FIELDS = {"A": "domain-ip"}

EMAIL_FIELDS = {
    "email": "email",
    "soa_email": "DNS/SOA",
    "ssl_email": "SSL",
    "additional_whois_email": "whois",
    "admin_contact": "email-admin",
    "billing_contact": "email-billing",
    "registrant_contact": "email-registrant",
    "technical_contact": "email-technical",
}

DEFAULT_RISK_SCORE = 100
