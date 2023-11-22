from enum import Enum


class RiskListPath(Enum):
    IP = "/public/opencti/default_ip.csv"
    DOMAIN = "/public/opencti/default_domain.csv"
    HASH = "/public/opencti/default_hash.csv"
    # URL = "/public/opencti/default_url.csv"
