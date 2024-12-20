# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike utilities constants module."""

from typing import TypeVar

import stix2
from pycti import MarkingDefinition

T = TypeVar("T")


TLP_MARKING_DEFINITION_MAPPING = {
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "amber+strict": stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="TLP",
        x_opencti_definition="TLP:AMBER+STRICT",
    ),
    "red": stix2.TLP_RED,
}

DEFAULT_TLP_MARKING_DEFINITION = stix2.MarkingDefinition(
    id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
    definition_type="statement",
    definition={"statement": "custom"},
    allow_custom=True,
    x_opencti_definition_type="TLP",
    x_opencti_definition="TLP:AMBER+STRICT",
)


X_OPENCTI_LOCATION_TYPE = "x_opencti_location_type"
X_OPENCTI_ALIASES = "x_opencti_aliases"
X_OPENCTI_REPORT_STATUS = "x_opencti_report_status"
X_OPENCTI_FILES = "x_opencti_files"
X_OPENCTI_SCORE = "x_opencti_score"
X_OPENCTI_LABELS = "x_opencti_labels"
X_OPENCTI_CREATED_BY_REF = "x_opencti_created_by_ref"
X_OPENCTI_MAIN_OBSERVABLE_TYPE = "x_opencti_main_observable_type"

DEFAULT_X_OPENCTI_SCORE = 50
