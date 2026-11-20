"""Mark the objects of a STIX bundle with one TLP level."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from stix2.v21 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE, MarkingDefinition


class TLPLevel(StrEnum):
    """A TLP level, in OpenCTI's nomenclature.

    Parsed leniently: ``TLPLevel("amber+strict")`` is ``AMBER_STRICT``, and
    ``WHITE`` is another name of ``CLEAR``, as in OpenCTI, where both are the
    same marking. Any other value raises ``ValueError``.
    """

    CLEAR = "CLEAR"
    GREEN = "GREEN"
    AMBER = "AMBER"
    AMBER_STRICT = "AMBER+STRICT"
    RED = "RED"

    @classmethod
    def _missing_(cls, value: object) -> "TLPLevel | None":
        if not isinstance(value, str):
            return None
        name = value.upper()
        if name == "WHITE":
            name = "CLEAR"
        for level in cls:
            if level.value == name:
                return level
        return None


# STIX 2.1 defines no AMBER+STRICT: this is OpenCTI's custom TLP marking, with
# OpenCTI's static id. Its date is fixed, as the standard TLP objects' is, so
# the same input always gives the same bundle.
TLP_AMBER_STRICT = MarkingDefinition(
    id="marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
    created=datetime(2017, 1, 20, tzinfo=UTC),
    definition_type="statement",
    definition={"statement": "custom"},
    x_opencti_definition_type="TLP",
    x_opencti_definition="TLP:AMBER+STRICT",
    allow_custom=True,
)

# The marking definition of each level. Their ids are OpenCTI's static TLP
# ids, the ones the existing CrowdStrike connector uses: OpenCTI maps them to
# its built-in TLP markings. CLEAR is STIX's TLP:WHITE, whose id OpenCTI gives
# to TLP:CLEAR.
MARKING_DEFINITIONS: dict[TLPLevel, Any] = {
    TLPLevel.CLEAR: TLP_WHITE,
    TLPLevel.GREEN: TLP_GREEN,
    TLPLevel.AMBER: TLP_AMBER,
    TLPLevel.AMBER_STRICT: TLP_AMBER_STRICT,
    TLPLevel.RED: TLP_RED,
}
