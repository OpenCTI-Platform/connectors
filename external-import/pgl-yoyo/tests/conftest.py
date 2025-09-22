import sys
from pathlib import Path


def pytest_configure(config):
    # Ensure the `src` directory is on sys.path so tests can import package modules
    here = Path(__file__).resolve().parent
    src = here.parent / "src"
    src_path = str(src)
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
