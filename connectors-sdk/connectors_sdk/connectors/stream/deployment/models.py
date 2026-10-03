"""Data models of the deployment write-back."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from connectors_sdk.connectors.stream.deployment.utils import (
    extract_pattern_values,
    format_datetime,
    normalize_value,
    parse_datetime,
)


class DeploymentStatus(StrEnum):
    """Lifecycle status of an indicator on a security platform.

    ``expired`` is set by OpenCTI only and can never be reported by a connector.
    """

    PENDING = "pending"
    DEPLOYED = "deployed"
    ACTIVE = "active"
    FAILED = "failed"
    REMOVED = "removed"
    EXPIRED = "expired"


REPORTABLE_STATUSES = frozenset(
    {
        DeploymentStatus.PENDING,
        DeploymentStatus.DEPLOYED,
        DeploymentStatus.ACTIVE,
        DeploymentStatus.FAILED,
        DeploymentStatus.REMOVED,
    }
)
"""Statuses a connector may report."""

RECONCILED_STATUSES = (
    DeploymentStatus.PENDING,
    DeploymentStatus.DEPLOYED,
    DeploymentStatus.ACTIVE,
    DeploymentStatus.FAILED,
)
"""Statuses of the deployments checked by a reconciliation."""

LIVE_STATUSES = frozenset({DeploymentStatus.DEPLOYED, DeploymentStatus.ACTIVE})
"""Statuses meaning that the indicator is expected on the security platform."""


@dataclass(frozen=True, slots=True)
class DeploymentReport:
    """A deployment status report for one indicator.

    Attributes:
        indicator_id: OpenCTI internal id, standard id or STIX id of the indicator.
        status: The deployment status (any status but ``expired``).
        external_id: The id of the indicator on the vendor side.
        error_message: The vendor error, stored when ``status`` is ``failed``.
        deployed_at: First successful push (defaults to now on the platform side).
        synced_at: Last confirmation of the state (defaults to now).
        removed_at: Removal confirmation (defaults to now when ``removed``).
    """

    indicator_id: str
    status: DeploymentStatus
    external_id: str | None = None
    error_message: str | None = None
    deployed_at: datetime | str | None = None
    synced_at: datetime | str | None = None
    removed_at: datetime | str | None = None

    def __post_init__(self) -> None:
        """Validate and normalize the report.

        Raises:
            ValueError: If the indicator id is empty or the status is unknown or not
                reportable (``expired``).
        """
        if not isinstance(self.indicator_id, str) or not self.indicator_id.strip():
            raise ValueError("A deployment report requires an indicator id.")
        status = DeploymentStatus(self.status)
        if status not in REPORTABLE_STATUSES:
            raise ValueError(
                f"Status '{status}' cannot be reported by a connector (set by OpenCTI only)."
            )
        object.__setattr__(self, "status", status)

    @classmethod
    def from_mapping(cls, report: Mapping[str, Any]) -> "DeploymentReport":
        """Build a report from the dictionary shape used by the pycti helpers.

        Args:
            report: A mapping with ``indicator_id``, ``status`` and the optional
                ``external_id``, ``error_message``, ``deployed_at``, ``synced_at``
                and ``removed_at`` keys.

        Returns:
            The validated report.
        """
        return cls(
            indicator_id=report.get("indicator_id"),  # type: ignore[arg-type]
            status=report.get("status"),  # type: ignore[arg-type]
            external_id=report.get("external_id"),
            error_message=report.get("error_message"),
            deployed_at=report.get("deployed_at"),
            synced_at=report.get("synced_at"),
            removed_at=report.get("removed_at"),
        )

    def metadata_input(self) -> dict[str, str] | None:
        """Return the ``IndicatorDeploymentMetadataInput`` of the report, if any."""
        metadata = {
            "deployed_at": format_datetime(self.deployed_at),
            "last_sync_at": format_datetime(self.synced_at),
            "removed_at": format_datetime(self.removed_at),
            "error_message": self.error_message,
        }
        filtered = {key: value for key, value in metadata.items() if value is not None}
        return filtered or None

    def to_graphql_input(self) -> dict[str, Any]:
        """Return the ``IndicatorDeploymentReportInput`` of the report."""
        report_input: dict[str, Any] = {
            "indicatorId": self.indicator_id,
            "status": self.status.value,
        }
        if self.external_id is not None:
            report_input["externalId"] = self.external_id
        metadata = self.metadata_input()
        if metadata is not None:
            report_input["metadata"] = metadata
        return report_input

    def to_helper_kwargs(self) -> dict[str, Any]:
        """Return the keyword arguments of the pycti helpers for this report."""
        return {
            "indicator_id": self.indicator_id,
            "status": self.status.value,
            "external_id": self.external_id,
            "error_message": self.error_message,
            "deployed_at": format_datetime(self.deployed_at),
            "synced_at": format_datetime(self.synced_at),
            "removed_at": format_datetime(self.removed_at),
        }


@dataclass(frozen=True, slots=True)
class DeploymentReportError:
    """An error returned by OpenCTI for one report of a batch.

    Attributes:
        indicator_id: The indicator id of the rejected report.
        message: The reason of the rejection.
    """

    indicator_id: str
    message: str


@dataclass(frozen=True, slots=True)
class DeploymentBatchResult:
    """Outcome of one or several ``indicatorReportDeployments`` calls.

    Attributes:
        processed: Reports handled (created + updated + unchanged).
        created: ``deployed-on`` relationships created.
        updated: Relationships whose status or external id changed.
        unchanged: Relationships whose ``last_sync_at`` only was refreshed.
        errors: Reports rejected by OpenCTI or not sent because of an error.
    """

    processed: int = 0
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    errors: tuple[DeploymentReportError, ...] = ()

    @classmethod
    def from_graphql(cls, data: Mapping[str, Any] | None) -> "DeploymentBatchResult":
        """Build a result from an ``IndicatorDeploymentBatchResult`` payload.

        Args:
            data: The GraphQL payload, or ``None``.

        Returns:
            The parsed result (empty when ``data`` is ``None``).
        """
        if not data:
            return cls()
        errors = tuple(
            DeploymentReportError(
                indicator_id=str(error.get("indicatorId") or error.get("indicator_id")),
                message=str(error.get("message")),
            )
            for error in data.get("errors") or []
        )
        return cls(
            processed=int(data.get("processed") or 0),
            created=int(data.get("created") or 0),
            updated=int(data.get("updated") or 0),
            unchanged=int(data.get("unchanged") or 0),
            errors=errors,
        )

    @classmethod
    def failure(
        cls, reports: list[DeploymentReport], message: str
    ) -> "DeploymentBatchResult":
        """Build the result of reports that could not be sent.

        Args:
            reports: The reports that were not sent.
            message: The reason.

        Returns:
            A result with one error per report.
        """
        return cls(
            errors=tuple(
                DeploymentReportError(indicator_id=report.indicator_id, message=message)
                for report in reports
            )
        )

    def merge(self, other: "DeploymentBatchResult") -> "DeploymentBatchResult":
        """Return the sum of two results.

        Args:
            other: The result to add.

        Returns:
            A new result.
        """
        return DeploymentBatchResult(
            processed=self.processed + other.processed,
            created=self.created + other.created,
            updated=self.updated + other.updated,
            unchanged=self.unchanged + other.unchanged,
            errors=self.errors + other.errors,
        )


@dataclass(frozen=True, slots=True)
class IndicatorDeployment:
    """A ``deployed-on`` relationship of the security platform, with its indicator.

    Attributes:
        relationship_id: The OpenCTI id of the ``deployed-on`` relationship.
        status: The current deployment status.
        indicator_id: The OpenCTI internal id of the indicator.
        indicator_standard_id: The STIX id of the indicator.
        external_id: The id of the indicator on the vendor side.
        revoked: ``True`` when an analyst requested the withdrawal.
        last_sync_at: Last confirmation of the state.
        last_hit_at: Last hit already reported.
        hit_count: Hits already reported.
        indicator_name: The indicator name.
        pattern: The indicator pattern.
        pattern_type: The indicator pattern type.
        indicator_revoked: ``True`` when the indicator itself is revoked.
        valid_until: End of validity of the indicator.
        main_observable_type: The main observable type of the indicator.
    """

    relationship_id: str
    status: str
    indicator_id: str
    indicator_standard_id: str | None = None
    external_id: str | None = None
    revoked: bool = False
    last_sync_at: datetime | None = None
    last_hit_at: datetime | None = None
    hit_count: int = 0
    indicator_name: str | None = None
    pattern: str | None = None
    pattern_type: str | None = None
    indicator_revoked: bool = False
    valid_until: datetime | None = None
    main_observable_type: str | None = None

    @classmethod
    def from_node(cls, node: Mapping[str, Any]) -> "IndicatorDeployment | None":
        """Build a deployment from a ``stixCoreRelationships`` node.

        Args:
            node: The relationship node (GraphQL shape, ``from`` being the indicator).

        Returns:
            The deployment, or ``None`` when the node has no indicator (for example
            when the indicator is not readable by the connector user).
        """
        indicator = node.get("from")
        if not isinstance(indicator, Mapping) or not indicator.get("id"):
            return None
        return cls(
            relationship_id=str(node.get("id")),
            status=str(node.get("deployment_status") or DeploymentStatus.PENDING),
            indicator_id=str(indicator["id"]),
            indicator_standard_id=indicator.get("standard_id"),
            external_id=node.get("external_id"),
            revoked=bool(node.get("revoked")),
            last_sync_at=parse_datetime(node.get("last_sync_at")),
            last_hit_at=parse_datetime(node.get("last_hit_at")),
            hit_count=int(node.get("hit_count") or 0),
            indicator_name=indicator.get("name"),
            pattern=indicator.get("pattern"),
            pattern_type=indicator.get("pattern_type"),
            indicator_revoked=bool(indicator.get("revoked")),
            valid_until=parse_datetime(indicator.get("valid_until")),
            main_observable_type=indicator.get("x_opencti_main_observable_type"),
        )

    @property
    def is_live(self) -> bool:
        """Tell whether the indicator is expected on the platform (deployed or active)."""
        return self.status in LIVE_STATUSES

    def is_expired(self, now: datetime) -> bool:
        """Tell whether the indicator validity ended.

        Args:
            now: The reference time (timezone-aware).

        Returns:
            ``True`` when ``valid_until`` is in the past.
        """
        return self.valid_until is not None and self.valid_until < now

    def requires_removal(self, now: datetime) -> bool:
        """Tell whether the indicator must be withdrawn from the platform.

        Args:
            now: The reference time (timezone-aware).

        Returns:
            ``True`` when the withdrawal was requested, the indicator is revoked or
            its validity ended.
        """
        return self.revoked or self.indicator_revoked or self.is_expired(now)

    @property
    def identifiers(self) -> frozenset[str]:
        """Return the normalized OpenCTI identifiers of the indicator."""
        return frozenset(
            identifier
            for identifier in (
                normalize_value(self.indicator_id),
                normalize_value(self.indicator_standard_id),
            )
            if identifier
        )

    @property
    def values(self) -> frozenset[str]:
        """Return the normalized observable values of the indicator (pattern values)."""
        if self.pattern_type not in (None, "stix"):
            return frozenset()
        return frozenset(
            normalized
            for pattern_value in extract_pattern_values(self.pattern)
            if (normalized := normalize_value(pattern_value.value))
        )


@dataclass(frozen=True, slots=True)
class VendorIndicator:
    """An indicator read back from the security platform.

    Give at least one of ``indicator_id``, ``external_id`` or ``value``: the
    reconciliation matches vendor indicators with deployments in that order.

    Attributes:
        indicator_id: The OpenCTI id (internal or STIX id) of the indicator, when the
            vendor stores it. Only set it when it is known to be an indicator id:
            vendor indicators carrying an id with no matching deployment are reported
            as ``active`` (which creates the ``deployed-on`` relationship).
        external_id: The id of the indicator on the vendor side.
        value: The observable value of the indicator.
        raw: The vendor payload, available to ``remove_vendor_indicator``.
    """

    indicator_id: str | None = None
    external_id: str | None = None
    value: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False)


@dataclass(frozen=True, slots=True)
class VendorHit:
    """A detection observed on the security platform for an indicator.

    Attributes:
        timestamp: When the detection happened.
        indicator_id: The OpenCTI id of the indicator, when known.
        external_id: The vendor id of the indicator, when known.
        value: The observable value that matched, when known.
        count: The number of hits represented by this entry.
    """

    timestamp: datetime
    indicator_id: str | None = None
    external_id: str | None = None
    value: str | None = None
    count: int = 1


@dataclass(slots=True)
class ReconciliationSummary:
    """Counters of one reconciliation run.

    Attributes:
        skipped: ``True`` when the run did not happen.
        reason: Why the run was skipped or aborted.
        vendor_indicators: Indicators read back from the platform.
        vendor_listing_truncated: ``True`` when the read-back hit its limit; absence
            based decisions are then skipped.
        deployments: Deployments of the platform checked.
        confirmed_active: Deployments confirmed live (reported ``active``).
        discovered: Vendor indicators reported ``active`` with no previous deployment.
        marked_removed: Deployments found absent and reported ``removed``.
        deferred: Absent deployments confirmed after the read-back started (pushed
            meanwhile by the stream), left to the next run.
        repushed: ``pending`` deployments pushed again successfully.
        repush_failed: ``pending`` deployments whose push failed again.
        withdrawn: Indicators removed from the platform (withdrawal or expiry).
        withdrawal_failed: Indicators whose removal failed.
        hits_reported: Indicators with new hits reported.
        report_errors: Reports rejected by OpenCTI.
    """

    skipped: bool = False
    reason: str | None = None
    vendor_indicators: int = 0
    vendor_listing_truncated: bool = False
    deployments: int = 0
    confirmed_active: int = 0
    discovered: int = 0
    marked_removed: int = 0
    deferred: int = 0
    repushed: int = 0
    repush_failed: int = 0
    withdrawn: int = 0
    withdrawal_failed: int = 0
    hits_reported: int = 0
    report_errors: int = 0

    def as_log_meta(self) -> dict[str, Any]:
        """Return the summary as logging metadata."""
        return {
            "skipped": self.skipped,
            "reason": self.reason,
            "vendor_indicators": self.vendor_indicators,
            "vendor_listing_truncated": self.vendor_listing_truncated,
            "deployments": self.deployments,
            "confirmed_active": self.confirmed_active,
            "discovered": self.discovered,
            "marked_removed": self.marked_removed,
            "deferred": self.deferred,
            "repushed": self.repushed,
            "repush_failed": self.repush_failed,
            "withdrawn": self.withdrawn,
            "withdrawal_failed": self.withdrawal_failed,
            "hits_reported": self.hits_reported,
            "report_errors": self.report_errors,
        }
