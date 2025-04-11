"""
Pytest configuration file that imports all fixtures from common_fixtures.py
"""

import sys
from pathlib import Path

parent_dir = str(Path(__file__).parent.parent.absolute())
src_dir = str(Path(__file__).parent.parent.joinpath("src").absolute())

if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from .common_fixtures import *  # noqa
