import os

__version__ = "5.12.17"
LOGGER_NAME = "elastic"
RE_DATEMATH = (
    r"\{(?P<modulo>.*now[^{]*)(?:\{(?P<format>[^|]*)(?:\|(?P<offset>[^}]+))?\})?\}"
)
DM_DEFAULT_FMT = "YYYY.MM.DD"
__DATA_DIR__: str = os.path.join(os.path.abspath(os.path.dirname(__file__)), "data")
