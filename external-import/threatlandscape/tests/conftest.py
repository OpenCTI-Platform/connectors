import sys
from pathlib import Path

# Make src/ importable so test modules can use `from connector.* import ...`
_src_root = Path(__file__).resolve().parent.parent / "src"
if str(_src_root) not in sys.path:
    sys.path.insert(0, str(_src_root))
