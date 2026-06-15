import sys
from pathlib import Path

# Make the connector's ``src`` importable (reportimporter.*) during tests.
# Insert at the front (de-duplicated) so the connector's local ``src`` is
# imported first, ahead of any other ``reportimporter`` package that another
# connector's test suite may already have placed on sys.path.
_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
