# -*- coding: utf-8 -*-
"""CrowdSec client module."""

from dataclasses import dataclass
from time import sleep
from urllib.parse import urljoin

import requests
from pycti import OpenCTIConnectorHelper

MAX_ATTEMPTS = 5


class QuotaExceedException(Exception):
    pass


class CrowdSecApiException(Exception):
    pass


@dataclass
class CrowdSecClient:
    """CrowdSec client."""

    helper: OpenCTIConnectorHelper
    url: str
    api_key: str

    def get_crowdsec_cti_for_ip(self, ip):
        for i in range(1, MAX_ATTEMPTS + 1):
            resp = requests.get(
                urljoin(self.url, f"smoke/{ip}"),
                headers={
                    "x-api-key": self.api_key,
                    "User-Agent": "crowdsec-opencti/v1.1.0",
                },
            )
            if resp.status_code == 404:
                return {"reputation": "unknown"}
            elif resp.status_code == 429:
                raise QuotaExceedException(
                    (
                        "Quota exceeded for CrowdSec CTI API. "
                        "Please visit https://www.crowdsec.net/pricing to upgrade your plan."
                    )
                )
            elif resp.status_code == 200:
                return resp.json()
            elif resp.status_code in (401, 403):
                raise CrowdSecApiException(
                    f"CrowdSec CTI returned {resp.status_code}. "
                    "Please check your CrowdSec CTI API key."
                )
            else:
                self.helper.log_info(f"CrowdSec CTI response {resp.text}")
                self.helper.log_warning(
                    f"CrowdSec CTI returned {resp.status_code} response status code."
                )
            if i < MAX_ATTEMPTS:
                sleep(2**i)
        raise CrowdSecApiException(
            f"CrowdSec CTI returned {resp.status_code} after {MAX_ATTEMPTS} attempts"
        )
