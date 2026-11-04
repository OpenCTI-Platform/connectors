"""Enriched entity module.

This module provides ``EnrichedEntity``, which a processor returns from ``transform()``
with the new version of the entity it enriches, and the functions that merge it into
the entity received.

The entity does not have the same shape in every mode:

- Manual or automatic enrichment: OpenCTI attributes are at the top level of the
  object (``x_opencti_score``, ``x_opencti_labels``...).
- Playbook: they are in the OpenCTI extension of the object
  (``extensions[<OpenCTI extension id>]["score"]``, ``["labels"]``...).

At ingestion, pycti reads each attribute from one place only. A value written at the
top level of an object whose attribute lives in the extension is therefore ignored.
``merge_enriched_entity`` writes each value where the entity already holds it, whatever
the shape of the enriched entity (an SDK model, a stix2 object or a STIX dict).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

OPENCTI_SDO_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
OPENCTI_SCO_EXTENSION_ID = "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"


@dataclass(frozen=True)
class EnrichedEntity:
    """New version of the entity to enrich, returned by a processor's ``transform()``.

    Create it with ``message.enriched_entity(obj)``. The connector merges ``obj`` into
    the entity received instead of adding it to the bundle as a separate object, so
    the entity keeps its id, its author and every property ``obj`` does not provide.

    Attributes:
        entity: The enriched entity, as a connectors-sdk model, a stix2 object or a STIX dict.
    """

    entity: Any


@dataclass(frozen=True)
class _Attribute:
    """An OpenCTI attribute, which can be at the top level or in the OpenCTI extension.

    Attributes:
        top_level_keys: The keys of the attribute at the top level of an object.
        extension_key: The key of the attribute in the OpenCTI extension, if it can be there.
        is_list: ``True`` if new values are added to the existing ones,
            ``False`` if the new value replaces the existing one.
    """

    top_level_keys: tuple[str, ...]
    extension_key: str | None
    is_list: bool


_MERGED_ATTRIBUTES = (
    _Attribute(("labels", "x_opencti_labels"), "labels", is_list=True),
    _Attribute(
        ("external_references", "x_opencti_external_references"),
        "external_references",
        is_list=True,
    ),
    _Attribute(("object_marking_refs",), None, is_list=True),
    _Attribute(("x_opencti_score",), "score", is_list=False),
    _Attribute(("description", "x_opencti_description"), "description", is_list=False),
)

# Never taken from the enriched entity: the identity and authorship of the entity received
_KEPT_PROPERTIES = {
    "id",
    "type",
    "spec_version",
    "created",
    "modified",
    "created_by_ref",
    "x_opencti_created_by_ref",
    "x_opencti_id",
    "x_opencti_type",
    "extensions",
    "hashes",
}


def merge_enriched_entity(entity: dict[str, Any], enriched: dict[str, Any]) -> None:
    """Merge the enriched entity into the entity received, in place.

    - Labels, external references and markings: the enriched entity's values are added
      to the entity's ones, without duplicates.
    - Score and description: the enriched entity's value replaces the entity's one,
      when it provides one.
    - Hashes: the algorithms the entity does not have are added.
    - Any other property: added when the entity does not have it, never overwritten
      (a model rebuilt from the entity may carry defaults, such as a new ``valid_from``).
    - The id, the type, the author and the timestamps of the entity are kept.

    Args:
        entity: The entity received, as a STIX dict. It is modified in place.
        enriched: The enriched entity, as a STIX dict.
    """
    for attribute in _MERGED_ATTRIBUTES:
        new_value = _read(enriched, attribute)
        if new_value is not None and new_value != []:
            _write(entity, attribute, new_value, enriched)

    for algorithm, value in (enriched.get("hashes") or {}).items():
        entity.setdefault("hashes", {}).setdefault(algorithm, value)

    merged_keys = {key for attr in _MERGED_ATTRIBUTES for key in attr.top_level_keys}
    for key, value in enriched.items():
        if key not in _KEPT_PROPERTIES and key not in merged_keys:
            entity.setdefault(key, copy.deepcopy(value))


def replace_refs(stix_object: dict[str, Any], old_id: str, new_id: str) -> None:
    """Replace the references to ``old_id`` with ``new_id``, in place.

    Used when the enriched entity was built with another id than the entity received,
    so that the objects pointing to it (e.g. relationships built from the same model)
    point to the entity received instead.

    Args:
        stix_object: A STIX dict whose ``*_ref`` and ``*_refs`` properties are updated.
        old_id: The id to replace.
        new_id: The id to use instead.
    """
    for key, value in stix_object.items():
        if key.endswith("_ref") and value == old_id:
            stix_object[key] = new_id
        elif key.endswith("_refs") and isinstance(value, list):
            stix_object[key] = [new_id if ref == old_id else ref for ref in value]


def _opencti_extension(stix_object: dict[str, Any]) -> dict[str, Any] | None:
    """Return the OpenCTI extension of the object, or ``None`` if it has none."""
    extensions = stix_object.get("extensions") or {}
    for extension_id in (OPENCTI_SDO_EXTENSION_ID, OPENCTI_SCO_EXTENSION_ID):
        if extension_id in extensions:
            extension: dict[str, Any] = extensions[extension_id]
            return extension
    return None


def _read(stix_object: dict[str, Any], attribute: _Attribute) -> Any:
    """Return the value of the attribute in the object, wherever it is, or ``None``."""
    for key in attribute.top_level_keys:
        if stix_object.get(key) is not None:
            return stix_object[key]
    extension = _opencti_extension(stix_object)
    if extension is not None and attribute.extension_key is not None:
        return extension.get(attribute.extension_key)
    return None


def _write(
    entity: dict[str, Any],
    attribute: _Attribute,
    new_value: Any,
    enriched: dict[str, Any],
) -> None:
    """Write the new value of the attribute where pycti will read it in the entity.

    - Where the entity already holds the attribute (top level, extension, or both).
    - Otherwise in the entity's OpenCTI extension, if it has one and the attribute can
      be there.
    - Otherwise at the top level, under the key the enriched entity uses.
    """
    # Each place is a (dict, key) pair: the dict holding the attribute and its key
    places = [
        (entity, key) for key in attribute.top_level_keys if entity.get(key) is not None
    ]
    extension = _opencti_extension(entity)
    extension_key = attribute.extension_key
    if extension is not None and extension_key is not None:
        # In the extension if the entity holds it there, or holds it nowhere
        if extension.get(extension_key) is not None or not places:
            places.append((extension, extension_key))

    if not places:
        enriched_key = next(
            (key for key in attribute.top_level_keys if key in enriched),
            attribute.top_level_keys[-1],
        )
        places = [(entity, enriched_key)]

    for container, key in places:
        if attribute.is_list:
            container[key] = _add_missing(container.get(key) or [], new_value)
        else:
            container[key] = copy.deepcopy(new_value)


def _add_missing(current: list[Any], new_values: list[Any]) -> list[Any]:
    """Return ``current`` followed by the values of ``new_values`` it does not hold."""
    result = list(current)
    for value in new_values:
        if value not in result:
            result.append(copy.deepcopy(value))
    return result
