import sys
from pathlib import Path

# Make the connector's ``src`` importable (reportimporter.*) during tests.
sys.path.append(str(Path(__file__).resolve().parent.parent / "src"))
