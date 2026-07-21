import sys
from pathlib import Path

src_dir = str(Path(__file__).parent.parent.joinpath("src").absolute())
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)
