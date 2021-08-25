__version__ = "0.4.0"

LOGGER_NAME = "elastic-connector"
RE_DATEMATH = (
    r"\{(?P<modulo>.*now[^{]*)(?:\{(?P<format>[^|]*)(?:\|(?P<offset>[^}]+))?\})?\}"
)
DM_DEFAULT_FMT = "YYYY.MM.DD"
