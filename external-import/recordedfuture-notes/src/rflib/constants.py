from enum import Enum
from .rf_notes_to_stix2 import IPAddress, Domain, URL, FileHash

RISK_LIST_TYPE_MAPPER = {
    "IpAddress": {
        "class": IPAddress,
        "path": "/public/opencti/default_ip.csv"
    },
    "InternetDomainName": {
        "class": Domain,
        "path": "/public/opencti/default_domain.csv",
    },
    "URL": {
        "class": URL,
        "path": "/public/opencti/default_url.csv"
    },
    "Hash": {"class": FileHash, "path": "/public/opencti/default_hash.csv"},
}
