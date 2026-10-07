import os
import sys

# Let test files import `spycloud_connector` and `main` from the connector's sources,
# the same way `main.py` does, rather than from an installed copy of the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
