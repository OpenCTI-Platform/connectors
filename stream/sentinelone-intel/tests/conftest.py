"""Test bootstrap for the SentinelOne Intel connector.

* Adds the connector's ``src`` directory to ``sys.path`` so the tests
  can ``from sentinelone_services.client import ...``.
* Breaks the existing circular import between ``sentinelone_services``
  and ``sentinelone_connector`` so the regex constants under test can
  be imported directly.

The cycle exists in the production code:

* ``sentinelone_services/__init__.py`` imports ``SentinelOneClient``
  from ``.client``.
* ``client.py`` imports ``ConnectorSettings`` from
  ``sentinelone_connector.settings``.
* ``sentinelone_connector/__init__.py`` imports
  ``SentinelOneIntelConnector`` from ``.connector``.
* ``connector.py`` imports ``SentinelOneClient`` from
  ``sentinelone_services`` — but ``sentinelone_services/__init__.py``
  has not finished executing yet, so the binding does not exist.

The worker entry-point (``src/main.py``) avoids this at runtime
because it imports the packages in an order that pre-populates both
namespaces. Importing ``sentinelone_services.client`` *directly* from
a test does tickle the cycle, though — so we stub the
``sentinelone_connector`` package here. The regex constants under
test are module-level ``re.compile`` calls that do not depend on the
stubbed symbols.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

sys.modules.setdefault("sentinelone_connector", MagicMock())
sys.modules.setdefault("sentinelone_connector.settings", MagicMock())
