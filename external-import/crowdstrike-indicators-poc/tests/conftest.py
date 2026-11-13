"""Pytest configuration for the CrowdStrike indicators proof of concept."""

import sys
from pathlib import Path

# ``src`` goes first on the path so that ``import shared`` resolves to this
# proof of concept's ``src/shared`` package, not to the repository root
# ``shared`` package (CI tooling).
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))
