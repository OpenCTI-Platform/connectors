# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike utilities constants module."""

from typing import TypeVar

from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE  # type: ignore

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
X_OPENCTI_LABELS = "x_opencti_labels"
X_OPENCTI_CREATED_BY_REF = "x_opencti_created_by_ref"
X_OPENCTI_MAIN_OBSERVABLE_TYPE = "x_opencti_main_observable_type"

DEFAULT_X_OPENCTI_SCORE = 50
