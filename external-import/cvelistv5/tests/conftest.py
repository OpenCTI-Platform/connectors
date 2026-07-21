import sys
from pathlib import Path

# Add connector src/ to sys.path so imports resolve.
_src_root = Path(__file__).resolve().parent.parent / "src"
if str(_src_root) not in sys.path:
    sys.path.insert(0, str(_src_root))
