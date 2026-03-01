"""OpenCTI connector configuration and constants."""

import os
import uuid

# OpenCTI namespace UUID for deterministic ID generation
OPENCTI_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

TLP_CLEAR_STIX_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
OPENCTI_SSL_VERIFY_DEFAULT = True

# Identity
AUTHOR_NAME = "PortSpoofPro CTI Platform"
AUTHOR_DESCRIPTION = (
    "Threat intelligence from PortSpoofPro Session Aggregator - "
    "Advanced deception platform with eBPF detection."
)

# External reference sources
SESSION_SOURCE_NAME = "portspoof-pro-session"
TOOL_SOURCE_NAME = "portspoof-pro-tool"
THREAT_ACTOR_SOURCE_NAME = "portspoof-pro-threat-actor"

ENVIRONMENT = os.getenv("PORTSPOOF_ENV", "production")

# Processing limits
MAX_TARGET_IPS_FOR_GRAPH = int(os.getenv("PS_MAX_TARGET_IPS_GRAPH", "100"))
MAX_BUNDLE_SIZE_DEFAULT = 1000
PREFETCH_COUNT_DEFAULT = 10
MAX_RETRIES_DEFAULT = 3

# Limits graph noise from mass scans while preserving visibility for focused attacks
MAX_STRATEGIC_TARGET_RELATIONSHIPS = int(
    os.getenv("PS_MAX_STRATEGIC_TARGET_RELATIONSHIPS", "10")
)

# RabbitMQ
FULL_STATE_EXCHANGE = "portspoof-full-state-updates"
DLQ_EXCHANGE = "opencti-connector-dlq"
DLQ_QUEUE = "opencti-connector-dlq-queue"
QUEUE_NAME_DEFAULT = "opencti-connector-queue"

INITIAL_RETRY_DELAY = 10
MAX_RETRY_DELAY = 300
RETRY_BACKOFF_MULTIPLIER = 2
SAFETY_SLEEP_SECONDS = 10

# Logging
STATS_MESSAGE_INTERVAL = 50
STATS_TIME_INTERVAL = 300
MAX_LOG_MESSAGE_LENGTH = 1000

# Threat levels
THREAT_LEVEL_MAP = {0: "Info", 1: "Suspicious", 2: "High", 3: "Critical"}
DEFAULT_THREAT_LEVEL = "Unknown"

# Connector defaults
CONNECTOR_TYPE_DEFAULT = "EXTERNAL_IMPORT"
CONNECTOR_NAME_DEFAULT = "PortSpoofPro"
CONNECTOR_CONFIDENCE_LEVEL_DEFAULT = 85
CONNECTOR_LOG_LEVEL_DEFAULT = "info"
CONNECTOR_QUEUE_PROTOCOL_DEFAULT = "api"
CONNECTOR_SCOPE_DEFAULT = (
    "Threat-Actor,Observed-Data,IPv4-Addr,IPv6-Addr,Tool,"
    "Attack-Pattern,Infrastructure,Report,Relationship,Sighting"
)

# Detection name prefixes
FINGERPRINT_PREFIX = "fingerprint:"
TECHNIQUE_PREFIX = "technique:"
BEHAVIOR_PREFIX = "behavior:"
ATTACK_PREFIX = "attack:"

VALID_EVENT_TYPES = {"scanner_detected", "scanner_update", "scanner_session_ended"}

# Namespace prefixes for deterministic UUID5 generation
PORTSPOOF_TOOL_NAMESPACE_PREFIX = "portspoof-tool"
PORTSPOOF_INDICATOR_NAMESPACE_PREFIX = "portspoof-indicator"
PORTSPOOF_TECHNIQUE_NAMESPACE_PREFIX = "portspoof-technique"
PORTSPOOF_BEHAVIOR_NAMESPACE_PREFIX = "portspoof-behavior"
PORTSPOOF_ATTACK_NAMESPACE_PREFIX = "portspoof-attack"
PORTSPOOF_MITRE_TTP_NAMESPACE_PREFIX = "mitre-ttp"

# MITRE ATT&CK
MITRE_ATTACK_BASE_URL = "https://attack.mitre.org/techniques"
MITRE_ATTACK_SOURCE_NAME = "mitre-attack"

SECONDS_PER_MINUTE = 60
