"""Pytest configuration and shared fixtures for ORKL tests."""

import sys
from pathlib import Path

# Add src/ to path so we can import the connector package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
