import os
import sys
from unittest.mock import MagicMock

# pycti imports libmagic (a system library) at module load time; stub it out
# so unit tests don't require it to be installed on the host.
sys.modules.setdefault("magic", MagicMock())

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
