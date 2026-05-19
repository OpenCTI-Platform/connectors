"""Pytest configuration for the Matrix external-import connector tests.

The tests only exercise the dependency-free helpers exposed by
``src/lib/helpers.py``:

* ``TLP_MAP`` and :func:`resolve_tlp` — TLP normalisation and the
  marking-definition objects emitted with every bundle;
* :func:`media_content_id` — deterministic STIX id derivation for
  ``media-content`` observables;
* :func:`channel_display_name` — human-friendly fallback for the
  Channel SDO ``name``;
* :func:`publication_date_from_event` — timestamp coercion for
  malformed / synthetic Matrix events.

None of these depend on ``matrix-nio`` / the asyncio runtime / the
``libolm`` C library, so the suite runs on a vanilla CI runner. We
just put the connector ``src`` directory on ``sys.path`` so the test
modules can ``from lib.helpers import ...`` without pulling in
``main`` (which does require ``matrix-nio`` / ``libolm``).

``pycti`` and ``stix2`` are pulled in through the test requirements
file; ``matrix-nio`` / ``libolm`` are deliberately **not** required.
"""

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
