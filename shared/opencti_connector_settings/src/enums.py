from enum import StrEnum


class LogLevelType(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ConnectorType(StrEnum):
    EXTERNAL_IMPORT = "EXTERNAL_IMPORT"
    INTERNAL_IMPORT_FILE = "INTERNAL_IMPORT_FILE"
    INTERNAL_ENRICHMENT = "INTERNAL_ENRICHMENT"
    INTERNAL_ANALYSIS = "INTERNAL_ANALYSIS"
    INTERNAL_EXPORT_FILE = "INTERNAL_EXPORT_FILE"
    STREAM = "STREAM"
