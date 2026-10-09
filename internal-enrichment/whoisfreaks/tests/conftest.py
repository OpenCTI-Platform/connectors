import sys
from pathlib import Path

# Add the 'src' directory to sys.path so tests can import modules directly
src_path = Path(__file__).resolve().parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))
