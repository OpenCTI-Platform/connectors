"""Mark the objects of a STIX bundle with one TLP level."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from crowdstrike_indicators.transform.add_identity import author_identity
from stix2.exceptions import STIXError
from stix2.v21 import (
    TLP_AMBER,
    TLP_GREEN,
    TLP_RED,
    TLP_WHITE,
    Bundle,
    MarkingDefinition,
)

from shared.errors import ItemConversionError
from shared.transformer import AbstractTransformer


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


class CrowdStrikeAddTlpMarking(AbstractTransformer[Bundle, Bundle]):
    """Mark the objects of a STIX bundle with one TLP level.

    Runs after :class:`CrowdStrikeAddIdentity`. The returned bundle has the
    same id, holds the level's marking definition first, then every object of
    the input bundle, in order. Each object gets the marking id appended to
    its ``object_marking_refs``, except the marking definitions and the
    CrowdStrike author identity, which are left unmarked as in the existing
    CrowdStrike connector. Existing markings are kept, and the id is never
    repeated. Nothing else changes: custom properties are kept. The same
    input always gives the same output. No network call is made.
    """

    def __init__(self, level: TLPLevel | str) -> None:
        """Build the step for ``level``.

        :raises ValueError: if ``level`` is not a TLP level, naming it.
        """
        self.level = TLPLevel(level)
        self.marking = MARKING_DEFINITIONS[self.level]
        self._unmarked_id = author_identity().id

    def _marked(self, obj: Any) -> Any:
        if obj.type == "marking-definition" or obj.id == self._unmarked_id:
            return obj
        refs = list(obj.get("object_marking_refs", []))
        if self.marking.id in refs:
            return obj
        properties = {
            name: value for name, value in obj.items() if name != "object_marking_refs"
        }
        return type(obj)(
            **properties,
            object_marking_refs=[*refs, self.marking.id],
            allow_custom=obj.has_custom,
        )

    def convert(self, item: Bundle) -> Bundle:
        """Return ``item`` with the marking definition added and referenced.

        :raises ItemConversionError: if stix2 rejects an object or the
            bundle.
        """
        try:
            objects = [
                self._marked(obj)
                for obj in item.get("objects", [])
                if obj.id != self.marking.id
            ]
            return Bundle(
                id=item.id, objects=[self.marking, *objects], allow_custom=True
            )
        except STIXError as error:
            raise ItemConversionError(item.id, str(error)) from error
