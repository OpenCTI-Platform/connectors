# -*- coding: utf-8 -*-
"""OpenCTI AlienVault utilities constants module."""

from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE  # type: ignore


TLP_MARKING_DEFINITION_MAPPING = {
    "white": TLP_WHITE,
    "green": TLP_GREEN,
    "amber": TLP_AMBER,
    "red": TLP_RED,
}

DEFAULT_TLP_MARKING_DEFINITION = TLP_WHITE


X_OPENCTI_ALIASES = "x_opencti_aliases"
X_OPENCTI_ORGANIZATION_TYPE = "x_opencti_organization_type"
X_OPENCTI_RELIABILITY = "x_opencti_reliability"
X_OPENCTI_LOCATION_TYPE = "x_opencti_location_type"
X_MITRE_ID = "x_mitre_id"
X_OPENCTI_REPORT_STATUS = "x_opencti_report_status"
X_OPENCTI_SCORE = "x_opencti_score"
X_OPENCTI_LABELS = "x_opencti_labels"

DEFAULT_X_OPENCTI_SCORE = 50
