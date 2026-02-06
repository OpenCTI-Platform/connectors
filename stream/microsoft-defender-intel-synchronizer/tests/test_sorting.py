import os
import sys

# Ensure the 'src' directory is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from microsoft_defender_intel_synchronizer_connector.connector import sort_key


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
