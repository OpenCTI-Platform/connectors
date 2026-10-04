"""pySigma helpers used to translate the Sigma rule of a hunt into a native query.

pySigma is an optional dependency of the SDK: install the ``hunt`` extra
(``connectors-sdk[hunt]``) or add ``pysigma`` and the backend packages to the
requirements of the hunt connector. The helpers import pySigma lazily so that
the rest of the SDK keeps working without it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from connectors_sdk.connectors.internal_hunt.errors import HuntTranslationError

if TYPE_CHECKING:
    from sigma.collection import SigmaCollection
    from sigma.conversion.base import Backend
    from sigma.processing.pipeline import ProcessingPipeline

NO_PIPELINE = "none"
"""Pipeline name that disables any processing pipeline."""

_PIPELINE_SEPARATOR = re.compile(r"[+,]")

PYSIGMA_MISSING_MESSAGE = (
    "pySigma is not installed: install 'connectors-sdk[hunt]' or add 'pysigma' "
    "and the backend package of the platform to the connector requirements."
)


def parse_sigma_rule(sigma_rule: str) -> SigmaCollection:
    """Parse the Sigma rule (YAML) of a hunt.

    Args:
        sigma_rule: Sigma rule document, possibly holding several rules.

    Returns:
        The parsed pySigma rule collection.

    Raises:
        HuntTranslationError: If pySigma is missing or the rule is invalid.
    """
    try:
        from sigma.collection import SigmaCollection
    except ImportError as err:
        raise HuntTranslationError(PYSIGMA_MISSING_MESSAGE) from err

    try:
        collection = SigmaCollection.from_yaml(sigma_rule)
    except Exception as err:
        raise HuntTranslationError(f"Invalid Sigma rule: {err}") from err
    if not collection.rules:
        raise HuntTranslationError("The Sigma rule document contains no rule.")
    return collection


def build_pipeline(
    name: str | None,
    registry: Mapping[str, Callable[[], ProcessingPipeline]],
) -> ProcessingPipeline | None:
    """Build a pySigma processing pipeline from its name.

    Several pipelines can be chained with ``+`` or ``,`` (e.g.
    ``"windows-logsources+splunk_windows"``); they are applied in order.

    Args:
        name: Pipeline name(s), or ``None`` / ``"none"`` for no pipeline.
        registry: Factories of the pipelines the connector supports, by name.

    Returns:
        The processing pipeline, or ``None`` when no pipeline is requested.

    Raises:
        HuntTranslationError: If a pipeline name is unknown.
    """
    if name is None or name.strip().lower() in ("", NO_PIPELINE):
        return None
    pipeline: ProcessingPipeline | None = None
    for part in _PIPELINE_SEPARATOR.split(name):
        part_name = part.strip()
        if not part_name:
            continue
        factory = registry.get(part_name)
        if factory is None:
            supported = ", ".join(sorted([*registry, NO_PIPELINE]))
            raise HuntTranslationError(
                f"Unknown pySigma pipeline '{part_name}' (supported: {supported})."
            )
        pipeline = factory() if pipeline is None else pipeline + factory()
    return pipeline


def convert_sigma(
    backend: Backend,
    collection: SigmaCollection,
    output_format: str | None = None,
) -> list[str]:
    """Convert a Sigma rule collection with a pySigma backend.

    Args:
        backend: The pySigma backend of the connector platform.
        collection: The parsed Sigma rules.
        output_format: Backend output format (backend default when ``None``).

    Returns:
        The non-empty queries produced by the backend. Structured outputs
        (e.g. query DSL dictionaries) are serialized as JSON.

    Raises:
        HuntTranslationError: If the backend cannot convert the rules.
    """
    try:
        output: Any = backend.convert(collection, output_format)
    except Exception as err:
        raise HuntTranslationError(f"Sigma conversion failed: {err}") from err
    items = output if isinstance(output, list) else [output]
    queries = [
        item if isinstance(item, str) else json.dumps(item, sort_keys=True)
        for item in items
        if item is not None
    ]
    return [query.strip() for query in queries if query.strip()]


def detection_fields(collection: SigmaCollection) -> tuple[str, ...]:
    """Return the field names referenced by the detections of the rules.

    Call it after the conversion: processing pipelines rename the fields of the
    rules in place, so the names returned match the platform field names.

    Args:
        collection: The (converted) Sigma rules.

    Returns:
        The field names, in order of first appearance, without duplicates.
    """
    from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

    fields: dict[str, None] = {}

    def _walk(item: SigmaDetection | SigmaDetectionItem) -> None:
        if isinstance(item, SigmaDetectionItem):
            if item.field:
                fields.setdefault(item.field, None)
            return
        for child in item.detection_items:
            _walk(child)

    for rule in collection.rules:
        if isinstance(rule, SigmaRule):
            for detection in rule.detection.detections.values():
                _walk(detection)
    return tuple(fields)
