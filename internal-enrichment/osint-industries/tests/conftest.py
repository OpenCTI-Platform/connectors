# -*- coding: utf-8 -*-
"""Shared pytest configuration: make the connector's `src/` importable."""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
