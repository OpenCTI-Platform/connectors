from __future__ import annotations

import sys
from unittest.mock import MagicMock

# Pre-stub libmagic-dependent modules so ``import pycti`` succeeds even
# when the system libmagic isn't installed. ``setdefault`` keeps the
# real module if it's importable (CI runners with libmagic installed).
sys.modules.setdefault("magic", MagicMock())
