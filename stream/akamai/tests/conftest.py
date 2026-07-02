"""Test bootstrap for the Akamai stream connector.

Adds the connector's ``src`` directory to ``sys.path`` so that tests
can import ``akamai_connector`` without installing it as a package.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
