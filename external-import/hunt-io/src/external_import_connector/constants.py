"""Constants for the Hunt.IO connector."""

from typing import List


# API Configuration
class APIConstants:
    """API-related constants."""

    CONNECT_TIMEOUT = 30  # seconds
    READ_TIMEOUT = 120  # seconds
    RETRY_TOTAL = 3
    RETRY_BACKOFF_FACTOR = 1
    POOL_CONNECTIONS = 10
    POOL_MAXSIZE = 20
    RETRY_STATUS_CODES = [429, 500, 502, 503, 504]
    RETRY_METHODS = ["GET"]


# Processing Limits
class ProcessingLimits:
    """Processing and safety limits."""

    DEFAULT_BATCH_SIZE = 100
    EMERGENCY_MAX_ENTITIES = 5000
    MAX_FIRST_RUN = 1000
    MIN_ADAPTIVE_BATCH_SIZE = 25
    ADAPTIVE_BATCH_DIVISOR = 4


# Queue Management Thresholds
class QueueThresholds:
    """Queue health monitoring thresholds."""

    EMERGENCY_MESSAGE_THRESHOLD = 50000  # messages
    EMERGENCY_SIZE_THRESHOLD_MB = 100  # MB
    WARNING_MESSAGE_THRESHOLD = 20000  # messages
    WARNING_SIZE_THRESHOLD_MB = 50  # MB
    CRITICAL_MESSAGE_THRESHOLD = 100000  # messages
    CRITICAL_SIZE_THRESHOLD_MB = 200  # MB


# Retry Configuration
class RetryConfig:
    """Retry and backoff configuration."""

    MAX_RETRIES = 3
    BASE_DELAY = 1  # seconds
    EXPONENTIAL_BASE = 2
    BATCH_DELAY = 0.1  # seconds between batches


# STIX Objects
class STIXRelationships:
    """STIX relationship types."""

    CONTROLS = "controls"
    CONSISTS_OF = "consists-of"
    INDICATES = "indicates"


# Infrastructure Types
class InfrastructureTypes:
    """Infrastructure types for STIX objects."""

    COMMAND_AND_CONTROL = "command-and-control"


# Error Keywords for Retry Logic
class RetryableErrors:
    """Keywords that indicate retryable errors."""

    KEYWORDS: List[str] = [
        "connection",
        "stream",
        "timeout",
        "reset",
        "network",
        "rabbitmq",
        "pika",
        "503",
        "502",
        "500",
    ]


# Logging Prefixes
class LoggingPrefixes:
    """Standardized logging prefixes."""

    CONNECTOR = "[CONNECTOR]"
    API = "[API]"
    HTTP_RESILIENCE = "[HTTP-RESILIENCE]"
    QUEUE_MANAGEMENT = "[QUEUE-MANAGEMENT]"
    SEQUENTIAL_BATCH = "[SEQUENTIAL-BATCH]"
    PHASE_1 = "[PHASE-1]"
    PHASE_2 = "[PHASE-2]"
    PHASE_3 = "[PHASE-3]"
    CLIENT_FILTER = "[CLIENT-FILTER]"
    FIRST_RUN_LIMIT = "[FIRST-RUN-LIMIT]"
    EMERGENCY_LIMIT = "[EMERGENCY-LIMIT]"
    EMERGENCY_CONNECTOR_LIMIT = "[EMERGENCY-CONNECTOR-LIMIT]"
    DEBUG = "[DEBUG]"


# State Keys
class StateKeys:
    """State dictionary keys."""

    LAST_TIMESTAMP = "last_timestamp"
    LAST_RUN = "last_run"
    LAST_RUN_WITH_INGESTED_DATA = "last_run_with_ingested_data"
    ENTITIES_PROCESSED = "entities_processed"
    PROCESSING = "processing"
    QUEUE_WARNING_MODE = "queue_warning_mode"
    WARNING_QUEUE_SIZE = "warning_queue_size"
    LAST_EMERGENCY_STOP = "last_emergency_stop"
    EMERGENCY_QUEUE_SIZE = "emergency_queue_size"
    EMERGENCY_QUEUE_MB = "emergency_queue_mb"
    CRITICAL_QUEUE_STATE = "critical_queue_state"


# Network Protocol
class NetworkProtocols:
    """Network protocol constants."""

    TCP = "tcp"


# Date/Time Formats
class DateTimeFormats:
    """Date and time format strings."""

    STANDARD_FORMAT = "%Y-%m-%d %H:%M:%S"


# External References
class ExternalReferences:
    """External reference information."""

    SOURCE_NAME = "Hunt IO"
    URL = "https://hunt.io"
    DESCRIPTION = "Hunt IO"


# Author Information
class AuthorInfo:
    """Author/Identity information."""

    NAME = "Hunt IO"
    DESCRIPTION = "Hunt IO"
    IDENTITY_CLASS = "organization"


# Custom Properties
class CustomProperties:
    """Custom STIX properties."""

    CREATED_BY = "x_opencti_created_by_ref"
    CONNECTOR_VALUE = "hunt-io"


# UUID Namespace for Hunt.IO
class UUIDNamespace:
    """UUID namespace for deterministic ID generation."""

    HUNT_IO = "8cd73e6c-ae14-4c43-bbeb-33b44084a18c"
