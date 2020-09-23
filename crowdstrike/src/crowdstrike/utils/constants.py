# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike utilities constants module."""

from typing import TypeVar

from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE


T = TypeVar("T")


TLP_MARKING_DEFINITION_MAPPING = {
    "white": TLP_WHITE,
    "green": TLP_GREEN,
    "amber": TLP_AMBER,
    "red": TLP_RED,
}

DEFAULT_TLP_MARKING_DEFINITION = TLP_AMBER


X_OPENCTI_LOCATION_TYPE = "x_opencti_location_type"
X_OPENCTI_ALIASES = "x_opencti_aliases"
X_OPENCTI_REPORT_STATUS = "x_opencti_report_status"
X_OPENCTI_FILES = "x_opencti_files"
X_OPENCTI_SCORE = "x_opencti_score"

DEFAULT_X_OPENCTI_SCORE = 50
