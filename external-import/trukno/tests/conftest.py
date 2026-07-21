import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

FIXTURES = Path(__file__).resolve().parent / "fixtures"
