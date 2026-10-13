"""Normalise Hunter sigma rules so OpenCTI will accept them.

OpenCTI validates an Indicator's sigma pattern with pySigma
(``SigmaCollection.from_yaml``) and rejects the whole object when the rule does
not parse — which also breaks every relationship pointing at it. Hunter's rules
carry a few metadata quirks pySigma refuses:

* ``status: New`` — not one of the Sigma statuses.
* ``id`` values that are not UUIDs (e.g. ``a1b2c3d4-...-teampcp000024``).
* ``tags`` as a nested list (``[['optional', 'attack.t1059.001', 'etc']]``).

Every fix here touches *metadata only*: an offending optional key is dropped or
coerced, and the ``detection``/``logsource`` blocks — what the rule actually
matches — are passed through untouched.
"""

from __future__ import annotations

import logging
import uuid as uuid_lib
from typing import Any

import yaml

try:  # pragma: no cover - exercised via the installed dependency
    from sigma.collection import SigmaCollection
except ImportError:  # pragma: no cover - keeps the connector usable without it
    SigmaCollection = None  # type: ignore[assignment]

LOGGER = logging.getLogger(__name__)

# Optional metadata keys pySigma validates against a fixed vocabulary.
_VALID_STATUSES = {"unsupported", "deprecated", "experimental", "test", "stable"}
_VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


def normalise(sigma: str) -> str:
    """Return `sigma` with the metadata pySigma rejects removed or coerced.

    Returns an empty string when the input is not parseable YAML at all — the
    caller then emits no Indicator rather than one the platform will refuse.
    """
    if not sigma or not sigma.strip():
        return ""
    try:
        documents = [d for d in yaml.safe_load_all(sigma) if isinstance(d, dict)]
    except yaml.YAMLError as exc:
        LOGGER.warning("Sigma rule is not valid YAML, skipping: %s", exc)
        return ""
    if not documents:
        return ""

    changed = False
    for document in documents:
        changed |= _normalise_document(document)

    if changed:
        result = yaml.safe_dump_all(
            documents, sort_keys=False, default_flow_style=False, allow_unicode=True
        ).strip()
    else:
        result = sigma.strip()

    if not _parses(result):
        # Some other defect we do not know how to repair. Emitting it would make
        # OpenCTI reject the Indicator and every relationship pointing at it, so
        # drop the rule and say which one, loudly enough to chase upstream.
        LOGGER.warning(
            "Sigma rule %r is rejected by pySigma even after normalisation; "
            "emitting no Indicator for it",
            _title(documents),
        )
        return ""
    return result


def _title(documents: list[dict[str, Any]]) -> str:
    for document in documents:
        if document.get("title"):
            return str(document["title"])
    return "<untitled>"


def _parses(sigma: str) -> bool:
    """Whether OpenCTI's parser accepts the rule. When pySigma is unavailable we
    assume it does rather than silently dropping every rule."""
    if SigmaCollection is None:
        return True
    try:
        SigmaCollection.from_yaml(sigma)
        return True
    except Exception:  # noqa: BLE001 - pySigma raises a wide range of errors
        return False


def _normalise_document(document: dict[str, Any]) -> bool:
    """Fix one sigma document in place. Returns True if anything changed."""
    changed = False

    # `status` must come from the Sigma vocabulary; Hunter uses "New".
    status = document.get("status")
    if status is not None and str(status).lower() not in _VALID_STATUSES:
        LOGGER.debug("Dropping unsupported sigma status %r", status)
        document.pop("status")
        changed = True

    # `level`, same treatment.
    level = document.get("level")
    if level is not None and str(level).lower() not in _VALID_LEVELS:
        document.pop("level")
        changed = True

    # `id` must be a UUID. Hunter mints readable identifiers for some rules.
    rule_id = document.get("id")
    if rule_id is not None and not _is_uuid(rule_id):
        LOGGER.debug("Dropping non-UUID sigma id %r", rule_id)
        document.pop("id")
        changed = True

    # `tags` must be a flat list of `namespace.name` strings. Hunter sometimes
    # nests them and mixes in markers like "optional" / "required" / "etc".
    if "tags" in document:
        tags = _flatten_tags(document["tags"])
        if tags != document["tags"]:
            if tags:
                document["tags"] = tags
            else:
                document.pop("tags")
            changed = True

    return changed


def _is_uuid(value: Any) -> bool:
    try:
        uuid_lib.UUID(str(value))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def _flatten_tags(tags: Any) -> list[str]:
    """Flatten nested tag lists and keep only well-formed `namespace.name` tags."""
    flat: list[str] = []
    stack = [tags]
    while stack:
        item = stack.pop(0)
        if isinstance(item, (list, tuple)):
            stack = list(item) + stack
        elif isinstance(item, str) and "." in item:
            # pySigma splits on the first "." — a tag without one raises.
            if item not in flat:
                flat.append(item)
    return flat
