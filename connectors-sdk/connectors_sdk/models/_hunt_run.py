"""Identifiers of the knowledge found by a hunt run."""

import uuid

from stix2.canonicalization.Canonicalize import canonicalize

OPENCTI_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def scope_to_hunt_run(standard_id: str, hunt_run_id: str | None) -> str:
    """Return the identifier of an object found by a hunt run.

    The identifier derives from the standard identifier of the object and from
    the hunt run: two runs never share an object, while the attempts of one run
    produce the same identifier.

    Args:
        standard_id: Identifier derived from the properties of the object.
        hunt_run_id: OpenCTI id of the hunt run, or ``None`` outside of a hunt.

    Returns:
        The standard identifier without a hunt run, the run-scoped one otherwise.
    """
    if hunt_run_id is None:
        return standard_id
    stix_type = standard_id.split("--", 1)[0]
    name = canonicalize(
        {"id": standard_id, "x_opencti_hunt_run_id": hunt_run_id}, utf8=False
    )
    return f"{stix_type}--{uuid.uuid5(OPENCTI_NAMESPACE, name)}"
