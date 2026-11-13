"""Deterministic STIX ids for objects derived from CrowdStrike data.

Every id is ``<type>--<UUIDv5>`` in :data:`CROWDSTRIKE_NAMESPACE`, computed
from CrowdStrike data only, so no OpenCTI convention is involved. The
``malware:`` and ``indicates:`` prefixes keep the names of different object
kinds apart inside the one namespace.
"""

import uuid

# Derived from CrowdStrike's domain so anyone can recompute it.
CROWDSTRIKE_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "crowdstrike.com")


def indicator_id(crowdstrike_id: str) -> str:
    """Return the STIX id of the CrowdStrike indicator ``crowdstrike_id``.

    A STIX id must be ``indicator--<UUID>``, so the CrowdStrike id is turned
    into a UUIDv5. Converting it to an OpenCTI id belongs to a later,
    OpenCTI-specific stage.
    """
    return f"indicator--{uuid.uuid5(CROWDSTRIKE_NAMESPACE, crowdstrike_id)}"


def malware_id(name: str) -> str:
    """Return the STIX id of the malware family ``name``, case-sensitive."""
    return f"malware--{uuid.uuid5(CROWDSTRIKE_NAMESPACE, f'malware:{name}')}"


def indicates_id(source_id: str, target_id: str) -> str:
    """Return the STIX id of the ``indicates`` relationship between two ids."""
    name = f"indicates:{source_id}:{target_id}"
    return f"relationship--{uuid.uuid5(CROWDSTRIKE_NAMESPACE, name)}"
