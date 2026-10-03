"""Internal hunt connectors.

This package provides the building blocks of the connectors of type ``INTERNAL_HUNT``:

- ``InternalHuntConnector``: base class (translation, execution limits, STIX mapping, reporting)
- Protocol models: ``HuntRequest`` and its parts, ``NativeQuery``, ``HuntEvent``, ``HuntResult``,
  ``HuntEvidence``, ``HuntRunReport``
- pySigma helpers: ``build_pipeline``, ``parse_sigma_rule``, ``convert_sigma``, ``detection_fields``
- Result helpers: ``flatten_fields``, ``value_strings``, ``build_evidence``, ``count_distinct_entities``
- Time helpers: ``RunDeadline`` (bound API calls and job polling), ``parse_timestamp``
- Errors: ``HuntError`` and its subclasses
"""

from connectors_sdk.connectors.internal_hunt.analysis import (
    DEFAULT_ENTITY_FIELDS,
    BenignMatcher,
    build_evidence,
    count_distinct_entities,
    event_time_bounds,
    flatten_fields,
    sha256_hex,
    suppress_benign,
    value_strings,
)
from connectors_sdk.connectors.internal_hunt.errors import (
    HuntError,
    HuntExecutionError,
    HuntRequestError,
    HuntTimeoutError,
    HuntTranslationError,
    HuntUnsupportedPyctiError,
)
from connectors_sdk.connectors.internal_hunt.internal_hunt_connector import (
    InternalHuntConnector,
    ensure_pycti_hunt_support,
)
from connectors_sdk.connectors.internal_hunt.models import (
    HuntDefinition,
    HuntEvent,
    HuntEvidence,
    HuntIndicator,
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
    "HuntDefinition",
    "HuntEvent",
    "HuntEvidence",
    "HuntIndicator",
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
    "BenignMatcher",
    "build_evidence",
    "count_distinct_entities",
    "event_time_bounds",
    "flatten_fields",
    "sha256_hex",
    "suppress_benign",
    "value_strings",
    # Time helpers
    "RunDeadline",
    "parse_timestamp",
    # Observables and STIX mapping
    "ObservableValue",
    "extract_observables",
    "is_public_domain",
    "is_public_ip",
    "to_observable_model",
    "build_telemetry_objects",
    "hunt_author",
    "hunt_markings",
    # Errors
    "HuntError",
    "HuntExecutionError",
    "HuntRequestError",
    "HuntTimeoutError",
    "HuntTranslationError",
    "HuntUnsupportedPyctiError",
]
