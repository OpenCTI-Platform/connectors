import os
import sys

# The connector imports its modules as `src.*`, so its root must be importable.
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
