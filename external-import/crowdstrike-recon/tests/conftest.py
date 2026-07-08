import os
import sys

# The connector is not packaged, so expose ``src`` on the import path to allow
# ``from connector...`` / ``from crowdstrike_client...`` imports in the tests.
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)
