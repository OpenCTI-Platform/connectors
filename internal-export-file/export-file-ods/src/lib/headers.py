"""Spreadsheet-header construction helpers for the ``export-file-ods`` connector.

This module is intentionally dependency-free (no ``unogenerator`` / no
``pycti``) so the header logic — which decides the column layout of every
exported spreadsheet — can be unit-tested without LibreOffice being
available on the CI runner.

The public helper, :func:`build_headers`, returns the deterministic list
of spreadsheet headers for an export, with a few invariants:

* base columns are the union of every entity's keys, sorted
  alphabetically for a scannable layout;
* the raw ``hashes`` column is replaced by per-algorithm
  ``hashes.<ALGO>`` columns (the row generator only knows how to render
  the ``hashes.<ALGO>`` form, so a bare ``hashes`` header would always
  render as an empty cell);
* the per-algorithm column set is the union of a caller-supplied
  canonical algorithm list (kept in a stable order for the common
  algorithms even when the current export only exposes a subset) and
  every algorithm actually present on any ``entity["hashes"]`` value
  in the export, so non-canonical algorithms are not silently dropped;
* the union is built iteratively (``set.update`` per entity) rather
  than via ``set().union(*generator)`` so memory stays linear in the
  number of entities and we don't hit CPython's positional-argument
  unpacking limit on large exports.
"""

from typing import Any, Dict, Iterable, List

HASH_HEADER_PREFIX = "hashes."


def build_headers(
    entities_list: Iterable[Dict[str, Any]],
    canonical_hash_algorithms: Iterable[str],
) -> List[str]:
    """Return the deterministic header list for ``entities_list``.

    ``canonical_hash_algorithms`` is the ordered list of "common"
    algorithms the connector wants to surface even when the current
    export does not actually carry them. Extra algorithms present on
    the data are appended after the canonical ones in the order in
    which they are first encountered.
    """
    entities_seq = list(entities_list)

    header_set: set = set()
    for entity in entities_seq:
        header_set.update(entity.keys())
    headers: List[str] = sorted(header_set)
    if "hashes" not in headers:
        return headers
    headers.remove("hashes")

    algorithms: List[str] = list(canonical_hash_algorithms)
    seen_algorithms = set(algorithms)
    for entity in entities_seq:
        for hashed in entity.get("hashes") or []:
            algorithm = (hashed or {}).get("algorithm")
            if algorithm and algorithm not in seen_algorithms:
                algorithms.append(algorithm)
                seen_algorithms.add(algorithm)

    hash_headers = [f"{HASH_HEADER_PREFIX}{algorithm}" for algorithm in algorithms]
    return headers + [header for header in hash_headers if header not in headers]


__all__ = ("HASH_HEADER_PREFIX", "build_headers")
