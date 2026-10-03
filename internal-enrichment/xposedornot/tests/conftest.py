# -*- coding: utf-8 -*-
"""Shared test fixtures for the XposedOrNot connector."""

import os
import sys
from unittest.mock import MagicMock, Mock

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

PYCTI_LOGGER_METHODS = ["debug", "info", "warning", "error"]


def make_helper() -> MagicMock:
    """A helper mock whose logger rejects methods pycti does not have.

    pycti's AppLogger exposes only debug/info/warning/error. A bare MagicMock
    invents any attribute, so a call to something like `exception` would pass
    the suite and raise AttributeError in production.
    """
    helper = MagicMock()
    helper.connector_logger = Mock(spec=PYCTI_LOGGER_METHODS)
    helper.stix2_create_bundle.return_value = "BUNDLE"
    return helper


@pytest.fixture(name="mocked_helper")
def fixture_mocked_helper() -> MagicMock:
    return make_helper()
