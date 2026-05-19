"""Filter-composition helpers for the ``export-file-ods`` connector.

This module is intentionally dependency-free (no ``unogenerator`` / no
``pycti``) so the filter combinators that enforce marking restrictions on
``full`` and ``query`` exports can be unit-tested without LibreOffice being
available on the CI runner.

Two combinators are exposed:

* :func:`build_neighbor_filter` — combines a positive ``ids`` filter for
  the neighbour candidates with the request's optional ``access_filter``.
* :func:`build_query_filter` — combines the user-supplied list filter for a
  ``query`` export with the request's optional ``access_filter``.

Both treat ``access_filter`` as optional: when ``filters`` and
``filterGroups`` are both empty or missing the filter is considered absent
and the user filter is returned as-is (or, for the neighbour case, only the
``ids`` group is returned). This mirrors the behaviour of every other
internal-export connector in the repository.
"""

from typing import Any, Dict, List, Optional


def _access_filter_has_content(access_filter: Optional[Dict[str, Any]]) -> bool:
    """Return ``True`` if ``access_filter`` carries any usable content.

    An ``access_filter`` whose ``filters`` and ``filterGroups`` lists are
    both missing/empty is treated as absent — passing it to the platform
    would add a no-op AND clause to the request filter.
    """
    if not access_filter:
        return False
    return bool(
        (access_filter.get("filters") or [])
        or (access_filter.get("filterGroups") or [])
    )


def build_neighbor_filter(
    neighbor_ids: List[str],
    access_filter: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a filter selecting ``neighbor_ids`` and applying ``access_filter``.

    The neighbour ids are passed as a positive ``ids`` filter; the
    request's ``access_filter`` (when present and non-empty) is ANDed
    with it so the unified entity endpoint enforces the same marking
    restrictions the platform applied to the selected entities.
    """
    ids_filter_group: Dict[str, Any] = {
        "mode": "and",
        "filterGroups": [],
        "filters": [
            {
                "key": "ids",
                "values": neighbor_ids,
                "operator": "eq",
                "mode": "or",
            }
        ],
    }
    if _access_filter_has_content(access_filter):
        return {
            "mode": "and",
            "filterGroups": [ids_filter_group, access_filter],
            "filters": [],
        }
    return ids_filter_group


def build_query_filter(
    list_params_filters: Optional[Dict[str, Any]],
    access_filter: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Combine the user filter and the access (marking) filter.

    Either side may be missing or empty: when ``access_filter`` has no
    ``filters`` and no ``filterGroups`` it is treated as absent and the
    user filter is returned as-is (and vice versa). When both are
    populated they are ANDed together.
    """
    access_has_content = _access_filter_has_content(access_filter)
    if access_has_content and list_params_filters is not None:
        return {
            "mode": "and",
            "filterGroups": [list_params_filters, access_filter],
            "filters": [],
        }
    if not access_has_content:
        return list_params_filters
    return access_filter


__all__ = ("build_neighbor_filter", "build_query_filter")
