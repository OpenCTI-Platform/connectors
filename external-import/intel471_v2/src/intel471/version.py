from pathlib import Path

_VERSION_FILE = Path(__file__).resolve().parents[1] / "__version__"


def get_version() -> str:
    return _VERSION_FILE.read_text().strip()
