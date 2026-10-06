"""Internal hunt connectors.

This package provides the building blocks of the connectors of type ``INTERNAL_HUNT``:

- ``InternalHuntConnector``: base class (translation, execution limits, STIX mapping, reporting)
- Protocol models: ``HuntRequest`` and its parts, ``NativeQuery``, ``HuntEvent``, ``HuntResult``,
  ``HuntEvidence``, ``HuntRunReport``
- pySigma helpers: ``build_pipeline``, ``parse_sigma_rule``, ``convert_sigma``, ``detection_fields``
- Result helpers: ``flatten_fields``, ``value_strings``, ``build_evidence``, ``build_hit_evidence``,
  ``count_distinct_entities``
- Time helpers: ``RunDeadline`` (bound API calls and job polling), ``parse_timestamp``
- HTTP: ``HuntApiClient`` (deadline-bounded calls raising hunt errors), ``api_error_message``
- Errors: ``HuntError`` and its subclasses
"""

from connectors_sdk.connectors.internal_hunt.analysis import (
    DEFAULT_ENTITY_FIELDS,
    DEFAULT_HIT_FIELDS,
    HIT_IDENTITY_MAX_LENGTH,
    HIT_KEY_VERSION,
    HOST_FIELDS,
    BenignMatcher,
    HitFields,
    build_evidence,
    build_hit_evidence,
    build_hit_keys,
    count_distinct_entities,
    event_time_bounds,
    flatten_fields,
    hit_key,
    present_fields,
    sha256_hex,
    suppress_benign,
    value_strings,
)
from connectors_sdk.connectors.internal_hunt.api_client import (
    HuntApiClient,
    access_denied_message,
    api_error_message,
)
from connectors_sdk.connectors.internal_hunt.errors import (
    HuntAccessDeniedError,
    HuntError,
    HuntExecutionError,
    HuntQueryRejectedError,
    HuntRequestError,
    HuntTimeoutError,
    HuntTranslationError,
    HuntUnsupportedPyctiError,
    is_retryable,
)
from connectors_sdk.connectors.internal_hunt.indicators import (
    AGGREGATED_FIELDS,
    IocBatch,
    IocObservation,
    aggregated_observations,
    batch_iocs,
    build_indicator_objects,
    build_ioc_results,
    match_events,
    value_hit_keys,
    value_hits,
    value_pattern,
)
from connectors_sdk.connectors.internal_hunt.internal_hunt_connector import (
    InternalHuntConnector,
    ensure_pycti_hunt_support,
)
from connectors_sdk.connectors.internal_hunt.models import (
    HuntConnectionCheck,
    HuntDefinition,
    HuntEvent,
    HuntEvidence,
    HuntHitEvidence,
    HuntHitField,
    HuntIndicator,
    HuntIoc,
    HuntIocResult,
    HuntIocSource,
    HuntLimits,
    HuntNativeQuery,
    HuntRequest,
    HuntResult,
    HuntRunInfo,
    HuntRunMode,
    HuntRunReport,
    HuntRunStatus,
    HuntSecurityPlatform,
    HuntTarget,
    HuntTechnique,
    HuntTimeWindow,
    NativeQuery,
)
from connectors_sdk.connectors.internal_hunt.observables import (
    ObservableValue,
    extract_observables,
    is_public_domain,
    is_public_ip,
    to_observable_model,
)
from connectors_sdk.connectors.internal_hunt.stix_mapping import (
    build_observed_data,
    build_telemetry_objects,
    hunt_author,
    hunt_markings,
)
from connectors_sdk.connectors.internal_hunt.timing import RunDeadline, parse_timestamp
from connectors_sdk.connectors.internal_hunt.translation import (
    NO_PIPELINE,
    build_pipeline,
    convert_sigma,
    detection_fields,
    parse_sigma_rule,
)

__all__ = [
    # Connector
    "InternalHuntConnector",
    "ensure_pycti_hunt_support",
    # Protocol models
    "HuntConnectionCheck",
    "HuntDefinition",
    "HuntEvent",
    "HuntEvidence",
    "HuntHitEvidence",
    "HuntHitField",
    "HuntIndicator",
    "HuntIoc",
    "HuntIocResult",
    "HuntIocSource",
    "HuntLimits",
    "HuntNativeQuery",
    "HuntRequest",
    "HuntResult",
    "HuntRunInfo",
    "HuntRunMode",
    "HuntRunReport",
    "HuntRunStatus",
    "HuntSecurityPlatform",
    "HuntTarget",
    "HuntTechnique",
    "HuntTimeWindow",
    "NativeQuery",
    # pySigma helpers
    "NO_PIPELINE",
    "build_pipeline",
    "convert_sigma",
    "detection_fields",
    "parse_sigma_rule",
    # Result helpers
    "DEFAULT_ENTITY_FIELDS",
    "DEFAULT_HIT_FIELDS",
    "HIT_IDENTITY_MAX_LENGTH",
    "HIT_KEY_VERSION",
    "BenignMatcher",
    "HitFields",
    "build_evidence",
    "build_hit_evidence",
    "build_hit_keys",
    "count_distinct_entities",
    "event_time_bounds",
    "flatten_fields",
    "hit_key",
    "present_fields",
    "sha256_hex",
    "suppress_benign",
    "value_strings",
    # Indicator hunts
    "AGGREGATED_FIELDS",
    "HOST_FIELDS",
    "IocBatch",
    "IocObservation",
    "aggregated_observations",
    "batch_iocs",
    "build_indicator_objects",
    "build_ioc_results",
    "match_events",
    "value_hit_keys",
    "value_hits",
    "value_pattern",
    # Time helpers
    "RunDeadline",
    "parse_timestamp",
    # HTTP
    "HuntApiClient",
    "access_denied_message",
    "api_error_message",
    # Observables and STIX mapping
    "ObservableValue",
    "extract_observables",
    "is_public_domain",
    "is_public_ip",
    "to_observable_model",
    "build_observed_data",
    "build_telemetry_objects",
    "hunt_author",
    "hunt_markings",
    # Errors
    "HuntAccessDeniedError",
    "HuntError",
    "HuntExecutionError",
    "HuntQueryRejectedError",
    "HuntRequestError",
    "HuntTimeoutError",
    "HuntTranslationError",
    "HuntUnsupportedPyctiError",
    "is_retryable",
]
