from microsoft_defender_intel_synchronizer_connector.connector import (
    EPOCH_UTC,
    parse_modified,
    sort_key,
)


def mk(name, rank, conf, modified):
    return {
        "name": name,
        "_collection_rank": rank,
        "confidence": conf,
        "modified": modified,
    }


def test_rank_priority():
    A = mk("A", 0, 10, "2025-01-01T00:00:00Z")
    B = mk("B", 1, 100, "2025-01-02T00:00:00Z")
    C = mk("C", 2, 90, "2025-01-03T00:00:00Z")
    arr = [C, B, A]
    arr.sort(key=sort_key)
    assert [x["name"] for x in arr] == ["A", "B", "C"]


def test_confidence_priority_within_rank():
    A = mk("A", 0, 50, "2025-01-01T00:00:00Z")
    B = mk("B", 0, 80, "2025-01-02T00:00:00Z")
    arr = [A, B]
    arr.sort(key=sort_key)
    assert [x["name"] for x in arr] == ["B", "A"]


def test_modified_priority_within_rank_and_confidence():
    A = mk("A", 0, 80, "2025-01-01T00:00:00Z")
    B = mk("B", 0, 80, "2025-02-01T00:00:00Z")
    arr = [A, B]
    arr.sort(key=sort_key)
    assert [x["name"] for x in arr] == ["B", "A"]


class TestParseModifiedFallback:
    """``parse_modified`` falls back to ``updated_at`` / ``created_at``.

    The ``INDICATOR_QUERY`` aliases ``updated_at`` to ``modified`` only
    on the ``... on Indicator`` selection set. The other GraphQL
    fragments (``DomainName`` / ``Url`` / ``IPv4Addr`` / ``IPv6Addr`` /
    ``HashedObservable`` / ``X509Certificate``) only expose
    ``updated_at`` and ``created_at`` — and ``parse_modified`` runs
    before ``_convert_indicator_to_observables`` copies ``updated_at``
    into ``modified``. Without the fallback, every non-Indicator node
    sorts to ``EPOCH_UTC`` and is evicted by the global cap even when
    its timestamp is more recent than an Indicator that survived.
    """

    def test_falls_back_to_updated_at(self) -> None:
        observable_node = {"updated_at": "2025-02-01T00:00:00Z"}
        indicator_node = {"modified": "2025-01-01T00:00:00Z"}
        assert parse_modified(observable_node) > parse_modified(indicator_node)

    def test_falls_back_to_created_at(self) -> None:
        node = {"created_at": "2025-03-01T00:00:00Z"}
        assert parse_modified(node) > EPOCH_UTC

    def test_modified_wins_over_updated_at(self) -> None:
        """When both are present, ``modified`` is the authoritative one."""
        node = {
            "modified": "2025-02-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
        }
        expected = parse_modified({"modified": "2025-02-01T00:00:00Z"})
        assert parse_modified(node) == expected

    def test_empty_modified_skips_to_updated_at(self) -> None:
        """An empty / None ``modified`` is treated as missing."""
        node = {"modified": None, "updated_at": "2025-04-01T00:00:00Z"}
        assert parse_modified(node) > EPOCH_UTC

    def test_no_timestamp_returns_epoch(self) -> None:
        assert parse_modified({"id": "foo"}) == EPOCH_UTC

    def test_observable_node_sorts_ahead_of_older_indicator(self) -> None:
        """End-to-end: a recent non-Indicator no longer evicts itself.

        Pins the regression scenario described in the docstring of
        ``parse_modified``: an observable node coming back from the
        GraphQL query with only ``updated_at`` set should sort ahead
        of an older Indicator node, not behind it at ``EPOCH_UTC``.
        """
        observable = {
            "_collection_rank": 0,
            "confidence": 0,
            "updated_at": "2025-12-01T00:00:00Z",
        }
        indicator = {
            "_collection_rank": 0,
            "confidence": 0,
            "modified": "2025-01-01T00:00:00Z",
        }
        arr = [indicator, observable]
        arr.sort(key=sort_key)
        assert arr[0] is observable
