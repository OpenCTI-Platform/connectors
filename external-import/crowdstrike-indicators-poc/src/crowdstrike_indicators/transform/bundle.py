"""Turn a CrowdStrike indicator bundle into a standard STIX 2.1 bundle."""

from collections.abc import Iterable, Iterator
from typing import Any

from crowdstrike_indicators.entities.ids import bundle_id
from crowdstrike_indicators.entities.stix import CrowdStrikeIndicatorBundle
from crowdstrike_indicators.transform.malware import crowdstrike_id
from stix2.exceptions import STIXError
from stix2.v21 import Bundle

from shared.errors import ItemConversionError
from shared.transformer import AbstractTransformer


def _references(obj: Any) -> Iterator[str]:
    """Yield the ids an object points to, through its top-level ``*_ref(s)``."""
    for name, value in obj.items():
        if name.endswith("_ref") and isinstance(value, str):
            yield value
        elif name.endswith("_refs") and isinstance(value, list):
            yield from (item for item in value if isinstance(item, str))


def missing_references(objects: Iterable[Any]) -> list[str]:
    """Return the referenced ids absent from ``objects``, in first-seen order."""
    objects = list(objects)
    known = {obj.id for obj in objects}
    missing: dict[str, None] = {}
    for obj in objects:
        for reference in _references(obj):
            if reference not in known:
                missing.setdefault(reference)
    return list(missing)


class MakeStixBundle(AbstractTransformer[CrowdStrikeIndicatorBundle, Bundle]):
    """Build the standard STIX 2.1 bundle of a CrowdStrike indicator bundle.

    The bundle holds the indicator, then the Malware objects, the
    AttackPatterns and the relationships, unchanged and with their custom
    properties. Its id is derived from the indicator's id, so the same input
    always gives the same bundle. Every reference must resolve inside the
    bundle, since consumers such as OpenCTI reject dangling references.
    """

    def convert(self, item: CrowdStrikeIndicatorBundle) -> Bundle:
        """Return the STIX bundle of ``item``.

        :raises ItemConversionError: if an object references an id
            missing from the bundle, or if stix2 rejects the bundle.
        """
        objects = [
            item.indicator,
            *item.malware,
            *item.attack_patterns,
            *item.relationships,
        ]
        missing = missing_references(objects)
        if missing:
            raise ItemConversionError(
                crowdstrike_id(item.indicator),
                "reference to an object missing from the bundle: " + ", ".join(missing),
            )
        try:
            return Bundle(
                id=bundle_id(item.indicator.id), objects=objects, allow_custom=True
            )
        except STIXError as error:
            raise ItemConversionError(
                crowdstrike_id(item.indicator), str(error)
            ) from error
