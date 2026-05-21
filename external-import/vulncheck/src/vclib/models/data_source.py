from enum import Enum
from typing import Any, Callable

import requests
from vclib.sources.botnets import collect_botnets
from vclib.sources.epss import collect_epss
from vclib.sources.exploits import collect_exploits
from vclib.sources.initial_access import collect_initial_access
from vclib.sources.ipintel import collect_ipintel
from vclib.sources.nistnvd2 import collect_nistnvd2
from vclib.sources.ransomware import collect_ransomware
from vclib.sources.snort import collect_snort
from vclib.sources.suricata import collect_suricata
from vclib.sources.threat_actors import collect_threat_actors
from vclib.sources.vckev import collect_vckev
from vclib.sources.vcnvd2 import collect_vcnvd2

BOTNETS = "botnets"
EPSS = "epss"
EXPLOITS = "exploits"
INITIAL_ACCESS = "initial-access"
IPINTEL = "ipintel"
NIST_NVD2 = "nist-nvd2"
RANSOMWARE = "ransomware"
SNORT = "snort"
SURICATA = "suricata"
THREAT_ACTORS = "threat-actors"
VULNCHECK_KEV = "vulncheck-kev"
VULNCHECK_NVD2 = "vulncheck-nvd2"

INDEX_URL_PREFIX = "/index/"
RULES_URL_PREFIX = "/rules/initial-access/"


class DataSource(Enum):
    Botnets = (
        BOTNETS,
        collect_botnets,
        INDEX_URL_PREFIX,
    )
    Epss = (
        EPSS,
        collect_epss,
        INDEX_URL_PREFIX,
    )
    Exploits = (
        EXPLOITS,
        collect_exploits,
        INDEX_URL_PREFIX,
    )
    IPIntel = (
        IPINTEL,
        collect_ipintel,
        INDEX_URL_PREFIX,
    )
    InitialAccess = (
        INITIAL_ACCESS,
        collect_initial_access,
        INDEX_URL_PREFIX,
    )
    NistNVD2 = (
        NIST_NVD2,
        collect_nistnvd2,
        INDEX_URL_PREFIX,
    )
    Ransomware = (
        RANSOMWARE,
        collect_ransomware,
        INDEX_URL_PREFIX,
    )
    Snort = (
        SNORT,
        collect_snort,
        RULES_URL_PREFIX,
    )
    Suricata = (
        SURICATA,
        collect_suricata,
        RULES_URL_PREFIX,
    )
    ThreatActors = (
        THREAT_ACTORS,
        collect_threat_actors,
        INDEX_URL_PREFIX,
    )
    VulnCheckKEV = (
        VULNCHECK_KEV,
        collect_vckev,
        INDEX_URL_PREFIX,
    )
    VulnCheckNVD2 = (
        VULNCHECK_NVD2,
        collect_vcnvd2,
        INDEX_URL_PREFIX,
    )

    def __init__(
        self, name, collect_data_source: Callable[..., Any], test_api_prefix: str
    ):
        self._name = name
        self.collect_data_source = collect_data_source
        self.test_api_prefix = test_api_prefix

    @property
    def name(self):
        return self._name

    @classmethod
    def from_string(cls, name):
        for item in cls:
            if item.name == name:
                return item
        raise ValueError(f"Unknown Data Source name: {name}")

    @classmethod
    def get_all_data_source_strings(cls):
        return ",".join([item.name for item in cls])

    def validate(self, base_url: str, token: str) -> bool:
        """
        Validates the endpoint is accessible
        """
        test_url = f"{base_url.rstrip('/')}{self.test_api_prefix}{self.name}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "*/*",
        }

        try:
            resp: requests.Response = requests.head(
                test_url,
                headers=headers,
                allow_redirects=True,
                timeout=10,
            )
        except requests.RequestException as e:
            raise RuntimeError(f"error testing {self.name}") from e

        if 400 <= resp.status_code < 500:
            return False

        return True
