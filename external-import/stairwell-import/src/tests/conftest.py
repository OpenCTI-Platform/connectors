import pathlib
import sys

SRC = pathlib.Path(__file__).resolve().parents[1]
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
