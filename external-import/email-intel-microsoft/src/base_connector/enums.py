from enum import StrEnum


class LogLevelType(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"  # alias
    WARNING = "warning"
    ERROR = "error"
