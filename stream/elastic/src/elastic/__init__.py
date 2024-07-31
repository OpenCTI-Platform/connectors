import os

__version__ = "6.2.9"
LOGGER_NAME = "elastic"
RE_DATEMATH = (
    r"\{(?P<modulo>.*now[^{]*)(?:\{(?P<format>[^|]*)(?:\|(?P<offset>[^}]+))?\})?\}"
)
DM_DEFAULT_FMT = "YYYY.MM.DD"
__DATA_DIR__: str = os.path.join(os.path.abspath(os.path.dirname(__file__)), "data")
