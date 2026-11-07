import os
import sys

# Import the connector's local ``src`` ahead of anything else so its package
# (export_file_threat_hunting_rules_connector / main) is the one resolved.
_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
