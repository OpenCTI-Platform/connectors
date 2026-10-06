import os
import sys

# Ensure the connector's ``src`` directory is importable even when this
# sub-package is collected on its own (mirrors the top-level tests/conftest.py).
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))
)
