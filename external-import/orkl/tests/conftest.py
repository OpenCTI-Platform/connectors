"""Pytest configuration and shared fixtures for ORKL tests."""

import sys
from pathlib import Path

# Add src/ to path so we can import the connector package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import copy  # noqa: E402
import json  # noqa: E402
from functools import lru_cache  # noqa: E402

import pytest  # noqa: E402

RESOURCES = Path(__file__).resolve().parent / "resources"


@lru_cache(maxsize=None)
def _load_resource(name: str):
    """Load and parse a JSON fixture file from the resources directory.

    Cached so each file (including the ~33,000-character real capture) is
    only read and parsed once per test session. The cached object itself is
    never handed out directly: every public fixture below returns
    `copy.deepcopy(...)` of it, so tests that mutate their fixture in place
    (e.g. `data.pop("title")`) cannot leak that mutation into later tests
    that share the same underlying file.

    Explicit UTF-8 encoding is required: on Windows the default encoding
    is not UTF-8, and the large real-world payload would otherwise fail
    to decode.
    """
    return json.loads((RESOURCES / name).read_text(encoding="utf-8"))


@pytest.fixture
def library_entry_full_response() -> dict:
    """Envelope for a real single library entry with 10 threat actors."""
    return copy.deepcopy(_load_resource("library_entry_full.json"))


@pytest.fixture
def library_entries_page_response() -> dict:
    """Envelope for a page of 4 library entries, sorted by updated_at desc."""
    return copy.deepcopy(_load_resource("library_entries_page.json"))


@pytest.fixture
def library_entries_empty_response() -> dict:
    """Envelope for an empty library entries listing (data is null)."""
    return copy.deepcopy(_load_resource("library_entries_empty.json"))


@pytest.fixture
def library_entry_deleted_response() -> dict:
    """Envelope for a single library entry that has been deleted."""
    return copy.deepcopy(_load_resource("library_entry_deleted.json"))


@pytest.fixture
def full_entry_data(library_entry_full_response: dict) -> dict:
    """The unwrapped `data` object of the real single-entry response.

    `library_entry_full_response` is already a fresh deep copy for this
    test, so slicing its `data` object out is safe: no other fixture or
    test holds a reference to it.
    """
    return library_entry_full_response["data"]


@pytest.fixture
def entries_page_data(library_entries_page_response: dict) -> list:
    """The unwrapped `data` list of the 4-entry page response.

    `library_entries_page_response` is already a fresh deep copy for this
    test, so slicing its `data` list out is safe: no other fixture or test
    holds a reference to it.
    """
    return library_entries_page_response["data"]
