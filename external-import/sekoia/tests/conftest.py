import os
import sys

# The connector uses absolute imports rooted at ``src`` (e.g.
# ``from src.connector.models import ConfigLoader``), so the connector root
# (the parent of ``src``) must be importable. We also expose the ``src``
# directory itself so ``import connector...`` resolves as well.
_HERE = os.path.dirname(os.path.abspath(__file__))
_CONNECTOR_ROOT = os.path.abspath(os.path.join(_HERE, ".."))
_SRC_DIR = os.path.join(_CONNECTOR_ROOT, "src")

for _path in (_CONNECTOR_ROOT, _SRC_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)
