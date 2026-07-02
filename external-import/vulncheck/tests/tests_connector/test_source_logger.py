"""Tests for SourceLogger — prepends a single ``[label] `` to every message."""

from unittest.mock import MagicMock

import pytest
from connector.util.source_logger import SourceLogger


@pytest.mark.parametrize("level", ["debug", "info", "warning", "error"])
def test_each_level_prefixes_label_and_delegates(level):
    inner = MagicMock()
    log = SourceLogger(inner, "vulncheck-nvd2")

    getattr(log, level)("query window", {"k": "v"})

    getattr(inner, level).assert_called_once_with(
        "[vulncheck-nvd2] query window", {"k": "v"}
    )


def test_meta_defaults_to_none():
    inner = MagicMock()
    SourceLogger(inner, "epss").info("no meta")
    inner.info.assert_called_once_with("[epss] no meta", None)
