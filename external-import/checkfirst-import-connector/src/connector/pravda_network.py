"""Static Pravda network infrastructure data.

All 36 domains share the same hosting IP (AS49352, Russia).
"""

PRAVDA_IP = {
    "IP": "178.21.15.85",
    "first_seen": "2023-09-01T00:00:00Z",
    "last_seen": "2024-12-31T00:00:00Z",
}

PRAVDA_DOMAINS = [
    {
        "domain": "pravda-de.com",
        "first_observed": "2023-06-24T00:00:00Z",
        "subdomains": [
            "deutsch.news-pravda.com",
            "germany.news-pravda.com",
            "austria.news-pravda.com",
            "switzerland.news-pravda.com",
        ],
    },
    {
        "domain": "pravda-en.com",
        "first_observed": "2023-06-24T00:00:00Z",
        "subdomains": [
            "news-pravda.com",
            "uk.news-pravda.com",
            "usa.news-pravda.com",
        ],
    },
    {
        "domain": "pravda-es.com",
        "first_observed": "2023-06-24T00:00:00Z",
        "subdomains": [
            "spanish.news-pravda.com",
            "spain.news-pravda.com",
        ],
    },
    {
        "domain": "pravda-fr.com",
        "first_observed": "2023-08-01T00:00:00Z",
        "subdomains": [
            "francais.news-pravda.com",
            "france.news-pravda.com",
        ],
    },
    {
        "domain": "pravda-pl.com",
        "first_observed": "2023-06-24T00:00:00Z",
        "subdomains": ["poland.news-pravda.com"],
    },
    {
        "domain": "pravda-nl.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": [
            "dutch.news-pravda.com",
            "netherlands.news-pravda.com",
            "belgium.news-pravda.com",
        ],
    },
    {
        "domain": "pravda-dk.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["denmark.news-pravda.com"],
    },
    {
        "domain": "pravda-se.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["sweden.news-pravda.com"],
    },
    {
        "domain": "pravda-fi.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["finland.news-pravda.com"],
    },
    {
        "domain": "pravda-ee.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["estonia.news-pravda.com"],
    },
    {
        "domain": "pravda-lt.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["lt.news-pravda.com"],
    },
    {
        "domain": "pravda-lv.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["latvia.news-pravda.com"],
    },
    {
        "domain": "pravda-cz.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["czechia.news-pravda.com"],
    },
    {
        "domain": "pravda-sk.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["slovakia.news-pravda.com"],
    },
    {
        "domain": "pravda-si.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["slovenia.news-pravda.com"],
    },
    {
        "domain": "pravda-hr.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["croatia.news-pravda.com"],
    },
    {
        "domain": "pravda-hu.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["hungary.news-pravda.com"],
    },
    {
        "domain": "pravda-ro.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["romania.news-pravda.com"],
    },
    {
        "domain": "pravda-bg.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["bulgaria.news-pravda.com"],
    },
    {
        "domain": "pravda-gr.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["greece.news-pravda.com"],
    },
    {
        "domain": "pravda-cy.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["cyprus.news-pravda.com"],
    },
    {
        "domain": "pravda-it.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["italy.news-pravda.com"],
    },
    {
        "domain": "pravda-ie.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["ireland.news-pravda.com"],
    },
    {
        "domain": "pravda-pt.com",
        "first_observed": "2024-03-20T00:00:00Z",
        "subdomains": ["portuguese.news-pravda.com", "portugal.news-pravda.com"],
    },
    {
        "domain": "pravda-al.com",
        "first_observed": "2024-03-26T00:00:00Z",
        "subdomains": ["albania.news-pravda.com"],
    },
    {
        "domain": "pravda-ba.com",
        "first_observed": "2024-03-26T00:00:00Z",
        "subdomains": ["bosnia-herzegovina.news-pravda.com"],
    },
    {
        "domain": "pravda-mk.com",
        "first_observed": "2024-03-26T00:00:00Z",
        "subdomains": ["north-macedonia.news-pravda.com"],
    },
    {
        "domain": "pravda-md.com",
        "first_observed": "2024-03-26T00:00:00Z",
        "subdomains": ["md.news-pravda.com"],
    },
    {
        "domain": "pravda-rs.com",
        "first_observed": "2024-03-26T00:00:00Z",
        "subdomains": ["serbia.news-pravda.com"],
    },
    {
        "domain": "pravda-no.com",
        "first_observed": "2024-03-26T00:00:00Z",
        "subdomains": ["norway.news-pravda.com"],
    },
    {
        "domain": "pravda-cf.com",
        "first_observed": "2024-03-26T00:00:00Z",
        "subdomains": ["rca.news-pravda.com"],
    },
    {
        "domain": "pravda-bf.com",
        "first_observed": "2024-03-26T00:00:00Z",
        "subdomains": ["burkina-faso.news-pravda.com"],
    },
    {
        "domain": "pravda-ne.com",
        "first_observed": "2024-03-26T00:00:00Z",
        "subdomains": ["niger.news-pravda.com"],
    },
    {
        "domain": "pravda-jp.com",
        "first_observed": "2024-03-26T00:00:00Z",
        "subdomains": ["japan.news-pravda.com"],
    },
    {
        "domain": "pravda-tw.com",
        "first_observed": "2024-03-26T00:00:00Z",
        "subdomains": ["taiwan.news-pravda.com"],
    },
    {
        "domain": "pravda-ko.com",
        "first_observed": "2024-03-26T00:00:00Z",
        "subdomains": [
            "korea.news-pravda.com",
            "south-korea.news-pravda.com",
            "dprk.news-pravda.com",
        ],
    },
]

# Reverse lookup: news-pravda.com subdomain → parent pravda-XX.com domain
SUBDOMAIN_TO_DOMAIN: dict[str, str] = {
    sub: entry["domain"] for entry in PRAVDA_DOMAINS for sub in entry["subdomains"]
}

# Set of all known pravda-XX.com domain values
PRAVDA_DOMAIN_VALUES: set[str] = {entry["domain"] for entry in PRAVDA_DOMAINS}
