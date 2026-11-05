"""Representative WhoisFreaks Live WHOIS API responses used across the tests."""

# A fully populated, registered domain with several contacts and name servers.
MOCK_WHOIS_FULL = {
    "status": True,
    "domain_name": "example.com",
    "query_time": "2024-08-02 10:11:12",
    "whois_server": "whois.iana.org",
    "domain_registered": "yes",
    "domain_handle": "2336799_DOMAIN_COM-VRSN",
    "create_date": "1995-08-14",
    "update_date": "2024-08-14",
    "expiry_date": "2025-08-13",
    "secure_dns": True,
    "domain_registrar": {
        "iana_id": "376",
        "handle": "",
        "status": "active",
        "registrar_name": "RESERVED-Internet Assigned Numbers Authority",
        "normalized_name": "iana",
        "whois_server": "whois.iana.org",
        "rdap_server": "https://rdap.iana.org",
        "website_url": "http://res-dom.iana.org",
        "email_address": "abuse@iana.org",
        "phone_number": "+1.3103015800",
    },
    "registrant_contact": {
        "name": "Admin Contact",
        "company": "Internet Assigned Numbers Authority",
        "street": "12025 Waterfront Drive",
        "city": "Los Angeles",
        "state": "CA",
        "zip_code": "90094",
        "country_name": "United States",
        "country_code": "US",
        "email_address": "registrant@example.com",
        "phone": "+1.3103015800",
    },
    "administrative_contact": {
        "name": "Admin Contact",
        "email_address": "admin@example.com",
    },
    "technical_contact": {
        "name": "Tech Contact",
        "email_address": "tech@example.com",
    },
    "billing_contact": {
        "name": "",
        "email_address": "",
    },
    "abuse_contact": {
        "email_address": "abuse@iana.org",
        "phone_number": "+1.3103015800",
    },
    "name_servers": ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"],
    "domain_status": [
        "clientTransferProhibited",
        "serverUpdateProhibited",
    ],
    "whois_raw_domain": "Domain Name: EXAMPLE.COM ...",
}

# A registered domain whose contacts are redacted for privacy.
MOCK_WHOIS_REDACTED = {
    "status": True,
    "domain_name": "privacy-domain.com",
    "domain_registered": "yes",
    "create_date": "2010-01-01",
    "update_date": "2023-01-01",
    "expiry_date": "2026-01-01",
    "secure_dns": False,
    "domain_registrar": {
        "iana_id": "146",
        "registrar_name": "GoDaddy.com, LLC",
        "website_url": "https://www.godaddy.com",
    },
    "registrant_contact": {
        "name": "REDACTED FOR PRIVACY",
        "company": "REDACTED FOR PRIVACY",
        "email_address": "Please query the RDDS service of the Registrar of Record",
    },
    "administrative_contact": {"email_address": "REDACTED FOR PRIVACY"},
    "technical_contact": {"email_address": "REDACTED FOR PRIVACY"},
    "name_servers": ["ns1.example-dns.com", "ns2.example-dns.com"],
    "domain_status": ["clientDeleteProhibited"],
}

# A domain that is not registered (available).
MOCK_WHOIS_UNREGISTERED = {
    "status": True,
    "domain_name": "this-domain-is-free-9z.com",
    "domain_registered": "no",
}
