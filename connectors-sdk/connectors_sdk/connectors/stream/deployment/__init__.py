"""Dissemination assurance: deployment write-back of stream connectors.

Stream connectors report to OpenCTI the lifecycle of each indicator on the
security platform they feed (``deployed-on`` relationship between the indicator
and the Security Platform entity: ``deployed``, ``active``, ``failed``,
``removed``), reconcile it periodically with the indicators read back from the
vendor, and report detection hits as sightings.

- ``DeploymentAssurance``: facade wiring the reporter and the reconciliation.
- ``DeploymentReporter``: feature detection, security platform resolution, single,
  batch and hit reports, listing of the deployments of the platform.
- ``DeploymentReconciler`` and ``DeploymentVendorAdapter``: reconciliation runner
  and the vendor operations a connector implements for it
  (``DeploymentPushAdapter`` when the vendor API cannot list the indicators: re-push
  of ``pending`` deployments and hits only).
- ``DeploymentConfig``, ``HitsConfig``, ``SecurityPlatformConfig``: settings
  namespaces (``DEPLOYMENT_*``, ``HITS_*``, ``SECURITY_PLATFORM_*`` variables).
"""

from connectors_sdk.connectors.stream.deployment.assurance import DeploymentAssurance
from connectors_sdk.connectors.stream.deployment.models import (
    LIVE_STATUSES,
    RECONCILED_STATUSES,
    REPORTABLE_STATUSES,
    DeploymentBatchResult,
    DeploymentReport,
    DeploymentReportError,
    DeploymentStatus,
    HitCollection,
    IndicatorDeployment,
    ReconciliationSummary,
    VendorHit,
    VendorIndicator,
)
from connectors_sdk.connectors.stream.deployment.reconciler import (
    LISTED_STATUSES,
    DeploymentPushAdapter,
    DeploymentReconciler,
    DeploymentVendorAdapter,
)
from connectors_sdk.connectors.stream.deployment.reporter import (
    MAX_BATCH_SIZE,
    DeploymentListingError,
    DeploymentReporter,
    is_rate_limit_error,
)
from connectors_sdk.connectors.stream.deployment.settings import (
    DeploymentAssuranceOptions,
    DeploymentConfig,
    HitsConfig,
    SecurityPlatformConfig,
)
from connectors_sdk.connectors.stream.deployment.utils import (
    OPENCTI_EXTENSION_ID,
    PatternValue,
    deployment_failure_reason,
    extract_pattern_values,
    get_opencti_indicator_id,
    is_stix_indicator,
    normalize_value,
    parse_datetime,
    parse_expiry,
    pattern_observable_values,
    to_stream_indicator,
)

__all__ = [
    "LISTED_STATUSES",
    "LIVE_STATUSES",
    "MAX_BATCH_SIZE",
    "OPENCTI_EXTENSION_ID",
    "RECONCILED_STATUSES",
    "REPORTABLE_STATUSES",
    "DeploymentAssurance",
    "DeploymentAssuranceOptions",
    "DeploymentBatchResult",
    "DeploymentConfig",
    "DeploymentListingError",
    "DeploymentPushAdapter",
    "DeploymentReconciler",
    "DeploymentReport",
    "DeploymentReportError",
    "DeploymentReporter",
    "DeploymentStatus",
    "DeploymentVendorAdapter",
    "HitCollection",
    "HitsConfig",
    "IndicatorDeployment",
    "PatternValue",
    "ReconciliationSummary",
    "SecurityPlatformConfig",
    "VendorHit",
    "VendorIndicator",
    "deployment_failure_reason",
    "extract_pattern_values",
    "get_opencti_indicator_id",
    "is_rate_limit_error",
    "is_stix_indicator",
    "normalize_value",
    "parse_datetime",
    "parse_expiry",
    "pattern_observable_values",
    "to_stream_indicator",
]
