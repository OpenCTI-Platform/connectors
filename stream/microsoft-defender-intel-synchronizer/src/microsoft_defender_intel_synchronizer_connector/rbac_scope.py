"""
RBAC scope resolution utilities.
"""

from typing import Any, Mapping

from .types import RBACScope


class RbacConfigError(RuntimeError):
    """
    Exception for RBAC config errors, with optional structured metadata.
    """

    def __init__(self, message: str, metadata: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.metadata: Mapping[str, Any] = metadata or {}

    def __str__(self) -> str:
        if self.metadata:
            keys = ", ".join(sorted(map(str, self.metadata.keys())))
            return f"{self.message} (metadata keys: {keys})"
        return self.message


def fetch_rbac_name_id_map(
    http_get, base_url: str, headers: dict
) -> tuple[dict[str, int], dict[int, str]]:
    """
    Fetch mapping of RBAC device group names to IDs from the API.
    Returns two dicts: name->id and id->name.
    """
    url = f"{base_url.rstrip('/')}/api/exposureScore/ByMachineGroups"
    name_to_id: dict[str, int] = {}
    id_to_name: dict[int, str] = {}

    top, skip = 1000, 0
    while True:
        r = http_get(url, headers=headers, params={"$top": top, "$skip": skip})
        r.raise_for_status()
        data = r.json() or {}
        items = data.get("value", []) or []

        for g in items:
            gid = int(g["rbacGroupId"])
            gname = str(g["rbacGroupName"])
            name_to_id[gname] = gid
            id_to_name[gid] = gname

        count = data.get("@odata.count")
        if count is not None:
            # stop once we've paged through the reported total
            if (skip + top) >= int(count):
                break
        else:
            # fallback: stop when the page isn't full
            if len(items) < top:
                break

        skip += top

    return name_to_id, id_to_name


def resolve_rbac_scope_or_abort(
    configured_names: list[str], name_to_id: dict[str, int]
) -> RBACScope | None:
    """
    Resolve RBAC scope from configured group names to their corresponding IDs.
    Returns None for tenant-wide scope if no names are configured.
    Raises RbacConfigError if any configured names are unknown.
    """
    # Trim and drop blanks early
    trimmed = [n.strip() for n in (configured_names or []) if n and n.strip()]
    if not trimmed:
        return None

    names: list[str] = []
    ids: list[int] = []
    missing: list[str] = []

    for n in trimmed:
        gid = name_to_id.get(n)
        if gid is None:
            missing.append(n)
            continue
        if gid in ids:
            continue  # dedupe by ID
        names.append(n)
        ids.append(gid)

    if missing:
        # fail closed: block the entire sync
        raise RbacConfigError("Unknown RBAC device groups", {"missing_groups": missing})

    return (names, ids) if names else None


__all__ = ["RbacConfigError", "fetch_rbac_name_id_map", "resolve_rbac_scope_or_abort"]
