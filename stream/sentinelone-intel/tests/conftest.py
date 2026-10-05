"""Test bootstrap for the SentinelOne Intel connector.

Adds the connector's ``src`` directory to ``sys.path`` so the tests can import
``sentinelone_connector`` and ``sentinelone_services``. ``client.py`` imports
``ConnectorSettings`` for type checking only, so both packages import in any order.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
