"""Unit tests for :func:`lib.headers.build_headers`.

The connector's :meth:`ExportFileODSConnector._get_content` delegates the
header construction to :func:`build_headers`, which is dependency-free so
the contract can be pinned without LibreOffice being available on the CI
runner.

The pinned invariants are:

* base columns are the union of every entity's keys, sorted
  alphabetically;
* the raw ``hashes`` column is replaced by per-algorithm ``hashes.<ALGO>``
  columns appended **after** the sorted base headers;
* canonical algorithms always appear (in the caller-supplied order),
  even when the current export does not actually carry them;
* extra algorithms present on the data are appended after the canonical
  ones, in encounter order, so non-canonical algorithms are not silently
  dropped;
* the union is built iteratively (``set.update`` per entity) rather than
  via ``set().union(*generator)``, so we stay linear in memory and do
  not hit CPython's positional-argument unpacking limit on large
  exports (regression test below).
"""

import pytest
from lib.headers import HASH_HEADER_PREFIX, build_headers

_CANONICAL = ("MD5", "SHA-1", "SHA-256", "SHA-512", "SSDEEP")


class TestBaseHeaders:
    """Base columns are the alphabetically sorted union of entity keys."""

    def test_empty_entity_list_returns_empty_headers(self):
        assert build_headers([], _CANONICAL) == []

    def test_single_entity_with_no_hashes_returns_sorted_keys(self):
        entities = [{"name": "alice", "type": "Identity"}]
        assert build_headers(entities, _CANONICAL) == ["name", "type"]

    def test_keys_are_sorted_alphabetically(self):
        entities = [{"z_field": 1, "a_field": 2, "m_field": 3}]
        assert build_headers(entities, _CANONICAL) == [
            "a_field",
            "m_field",
            "z_field",
        ]

    def test_union_across_entities_with_disjoint_keys(self):
        entities = [{"a": 1}, {"b": 2}, {"c": 3}]
        assert build_headers(entities, _CANONICAL) == ["a", "b", "c"]

    def test_union_across_entities_with_overlapping_keys(self):
        entities = [{"a": 1, "b": 2}, {"b": 3, "c": 4}]
        assert build_headers(entities, _CANONICAL) == ["a", "b", "c"]


class TestHashHeaderExpansion:
    """The raw ``hashes`` column is replaced by ``hashes.<ALGO>`` columns."""

    def test_raw_hashes_column_is_removed(self):
        entities = [{"hashes": [{"algorithm": "MD5", "hash": "abc"}]}]
        headers = build_headers(entities, _CANONICAL)
        assert "hashes" not in headers

    def test_canonical_algorithms_appear_in_caller_supplied_order(self):
        entities = [{"hashes": []}]
        headers = build_headers(entities, _CANONICAL)
        assert headers == [f"{HASH_HEADER_PREFIX}{algo}" for algo in _CANONICAL]

    def test_canonical_algorithms_appear_even_without_hashes_payload(self):
        # The entity has the ``hashes`` key but no actual algorithms;
        # canonical columns must still be present so the spreadsheet
        # layout stays stable across exports.
        entities = [{"name": "x", "hashes": []}]
        headers = build_headers(entities, _CANONICAL)
        for algo in _CANONICAL:
            assert f"{HASH_HEADER_PREFIX}{algo}" in headers

    def test_base_columns_precede_hash_columns(self):
        entities = [{"name": "x", "hashes": [{"algorithm": "MD5", "hash": "a"}]}]
        headers = build_headers(entities, _CANONICAL)
        assert headers.index("name") < headers.index(f"{HASH_HEADER_PREFIX}MD5")

    def test_non_canonical_algorithm_is_appended_after_canonical_ones(self):
        entities = [
            {
                "hashes": [
                    {"algorithm": "MD5", "hash": "a"},
                    {"algorithm": "TLSH", "hash": "b"},
                ]
            }
        ]
        headers = build_headers(entities, _CANONICAL)
        # ``TLSH`` is present in the data but not in the canonical list.
        # It must be surfaced as its own column, **after** every canonical
        # column so the layout is predictable.
        assert headers[-1] == f"{HASH_HEADER_PREFIX}TLSH"
        for algo in _CANONICAL:
            assert headers.index(f"{HASH_HEADER_PREFIX}{algo}") < headers.index(
                f"{HASH_HEADER_PREFIX}TLSH"
            )

    def test_non_canonical_algorithms_are_emitted_in_encounter_order(self):
        entities = [
            {"hashes": [{"algorithm": "TLSH", "hash": "a"}]},
            {"hashes": [{"algorithm": "VHASH", "hash": "b"}]},
            # Re-encountering TLSH must NOT duplicate the column.
            {"hashes": [{"algorithm": "TLSH", "hash": "c"}]},
        ]
        headers = build_headers(entities, _CANONICAL)
        extra_headers = [
            header
            for header in headers
            if header not in {f"{HASH_HEADER_PREFIX}{algo}" for algo in _CANONICAL}
            and header.startswith(HASH_HEADER_PREFIX)
        ]
        assert extra_headers == [
            f"{HASH_HEADER_PREFIX}TLSH",
            f"{HASH_HEADER_PREFIX}VHASH",
        ]

    def test_hashes_entry_without_algorithm_is_ignored(self):
        entities = [{"hashes": [{"hash": "a"}, None, {"algorithm": "MD5"}]}]
        headers = build_headers(entities, _CANONICAL)
        # Canonical algorithms remain; no spurious ``hashes.None`` column
        # is emitted from the missing-algorithm / ``None`` entries.
        assert all(not header.endswith("None") for header in headers)

    def test_entity_with_none_hashes_value_is_safe(self):
        entities = [{"name": "x", "hashes": None}]
        headers = build_headers(entities, _CANONICAL)
        assert "name" in headers
        for algo in _CANONICAL:
            assert f"{HASH_HEADER_PREFIX}{algo}" in headers


class TestNoHashesColumn:
    """When no entity carries ``hashes`` the per-algorithm columns are not added."""

    def test_entities_without_hashes_key_skip_algorithm_columns(self):
        entities = [{"name": "alice"}, {"name": "bob"}]
        headers = build_headers(entities, _CANONICAL)
        assert headers == ["name"]
        assert all(not header.startswith(HASH_HEADER_PREFIX) for header in headers)


class TestLargeInputs:
    """``build_headers`` does not hit CPython's positional-argument limit.

    Copilot flagged that the previous ``set().union(*generator)`` could
    blow the argument list on large exports. ``build_headers`` builds
    the union iteratively (``set.update`` per entity), so even a list
    that would have overflowed the positional-argument limit on the
    previous implementation completes in linear memory.
    """

    def test_many_entities_completes_without_unpacking_overflow(self):
        # CPython's "too many positional arguments" call limit kicks in
        # somewhere below 1M arguments on most builds; we generate 10k
        # entities — large enough to be representative of a busy
        # export and small enough to stay fast in CI.
        entities = [{f"k_{i}": i} for i in range(10_000)]
        headers = build_headers(entities, _CANONICAL)
        assert len(headers) == 10_000
        assert headers == sorted(f"k_{i}" for i in range(10_000))


class TestCanonicalAlgorithmsArgument:
    """The caller controls the canonical algorithm list / order."""

    def test_canonical_algorithms_are_preserved_in_caller_order(self):
        entities = [{"hashes": []}]
        canonical = ("SHA-256", "MD5", "TLSH")
        headers = build_headers(entities, canonical)
        # Canonical algorithms appear in the caller-supplied order even
        # though the caller order is not alphabetical.
        assert headers == [
            f"{HASH_HEADER_PREFIX}SHA-256",
            f"{HASH_HEADER_PREFIX}MD5",
            f"{HASH_HEADER_PREFIX}TLSH",
        ]

    def test_empty_canonical_algorithms_still_surfaces_data_algorithms(self):
        entities = [{"hashes": [{"algorithm": "MD5", "hash": "a"}]}]
        headers = build_headers(entities, ())
        assert headers == [f"{HASH_HEADER_PREFIX}MD5"]


@pytest.mark.parametrize(
    "entities",
    [
        ({"name": "alice"} for _ in range(3)),  # generator, not list
        iter([{"name": "alice"}, {"type": "Identity"}]),
    ],
)
def test_build_headers_accepts_arbitrary_iterables(entities):
    """``build_headers`` accepts generators / iterators, not just lists."""
    headers = build_headers(entities, _CANONICAL)
    assert "name" in headers or "type" in headers
