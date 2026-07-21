"""Smoke test for the connector entry-point module."""

import importlib


def test_main_module_importable():
    """Verify main.py can be imported without side-effects."""
    mod = importlib.import_module("main")
    assert mod is not None
