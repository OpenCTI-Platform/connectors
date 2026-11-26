import os
import sys

# Add the connector root (parent of tests/) to the path so that `src.*` imports resolve.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
