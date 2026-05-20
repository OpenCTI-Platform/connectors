"""Test bootstrap for the SentinelOne Intel connector.

* Adds the connector's ``src`` directory to ``sys.path`` so the tests
  can ``from sentinelone_services.client import ...``.
* Breaks the pre-existing circular import between
  ``sentinelone_services`` and ``sentinelone_connector`` by stubbing
  *only* the symbols ``client.py`` actually pulls in at module-import
  time. The stub is intentionally a real ``types.ModuleType`` (not a
  catch-all ``MagicMock``) so any *new* module-level access on
  ``sentinelone_connector.*`` introduced by a future ``client.py``
  refactor fails loudly with ``ModuleNotFoundError`` / ``AttributeError``
  at test collection — instead of silently returning a mock and
  hiding a regression of the import surface.

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
a test does tickle the cycle, though — hence the stub.
"""

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class _ConnectorSettingsStub:
    """Minimal placeholder for ``sentinelone_connector.settings.ConnectorSettings``.

    The regex constants under test are module-level ``re.compile`` calls
    that never touch ``ConnectorSettings``; the type only needs to exist
    as an importable name so ``client.py``'s ``from
    sentinelone_connector.settings import ConnectorSettings`` resolves.
    """


_connector_pkg = types.ModuleType("sentinelone_connector")
_connector_settings = types.ModuleType("sentinelone_connector.settings")
_connector_settings.ConnectorSettings = _ConnectorSettingsStub
_connector_pkg.settings = _connector_settings

sys.modules.setdefault("sentinelone_connector", _connector_pkg)
sys.modules.setdefault("sentinelone_connector.settings", _connector_settings)
