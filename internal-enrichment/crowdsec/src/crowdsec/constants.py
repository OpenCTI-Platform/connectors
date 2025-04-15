# -*- coding: utf-8 -*-
"""CrowdSec constants module."""

import re

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
MITRE_URL = "https://attack.mitre.org/techniques/"
CTI_URL = "https://app.crowdsec.net/cti/"
CTI_API_URL = "https://cti.api.crowdsec.net/"
FAKE_INDICATOR_ID = "indicator--51b92778-cef0-4a90-b7ec-ebd620d01ac8"
LAST_ENRICHMENT_PATTERN = "Last CrowdSec enrichment: "
