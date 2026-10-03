"""Dissemination assurance facade for stream connectors."""

import time
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from connectors_sdk.connectors.stream.deployment.models import DeploymentBatchResult
from connectors_sdk.connectors.stream.deployment.reconciler import (
    DeploymentPushAdapter,
    DeploymentReconciler,
)
from connectors_sdk.connectors.stream.deployment.reporter import DeploymentReporter
from connectors_sdk.connectors.stream.deployment.settings import (
    DeploymentAssuranceOptions,
)
from connectors_sdk.settings.base_settings import BaseConnectorSettings
from pycti import OpenCTIConnectorHelper


class DeploymentAssurance:
    """Deployment write-back of a stream connector: reporter plus reconciliation.

    Example:
        >>> assurance = DeploymentAssurance.from_settings(
        ...     helper, settings, adapter=MyVendorAdapter(client)
        ... )
        >>> assurance.start()
        >>> # in the stream callback, after each vendor call:
        >>> assurance.report_pushed(stix_indicator, external_id=vendor_id)
        >>> assurance.report_push_failed(stix_indicator, error)
        >>> assurance.report_removed(stix_indicator)
    """

    def __init__(
        self,
        reporter: DeploymentReporter,
        adapter: DeploymentPushAdapter | None = None,
        **reconciler_kwargs: Any,
    ) -> None:
        """Initialize the facade.

        Args:
            reporter: The deployment reporter.
            adapter: The vendor adapter: a ``DeploymentVendorAdapter`` for the full
                reconciliation, a ``DeploymentPushAdapter`` when the vendor API cannot
                read indicators back (re-push of ``pending`` deployments and hits), or
                ``None`` (push outcomes are reported, no reconciliation).
            **reconciler_kwargs: Extra arguments of ``DeploymentReconciler``.
        """
        self.reporter = reporter
        self.reconciler = (
            DeploymentReconciler(reporter, adapter, **reconciler_kwargs)
            if adapter is not None
            else None
        )

    @classmethod
    def from_options(
        cls,
        helper: OpenCTIConnectorHelper,
        options: DeploymentAssuranceOptions,
        adapter: DeploymentPushAdapter | None = None,
        *,
        reporter_kwargs: Mapping[str, Any] | None = None,
        **reconciler_kwargs: Any,
    ) -> "DeploymentAssurance":
        """Build the facade from resolved options.

        Args:
            helper: The connector helper.
            options: The deployment write-back options.
            adapter: The vendor adapter (see ``DeploymentAssurance``), if any.
            reporter_kwargs: Extra arguments of ``DeploymentReporter``.
            **reconciler_kwargs: Extra arguments of ``DeploymentReconciler``.

        Returns:
            The facade.
        """
        reporter = DeploymentReporter(helper, options, **dict(reporter_kwargs or {}))
        return cls(reporter, adapter, **reconciler_kwargs)

    @classmethod
    def from_settings(
        cls,
        helper: OpenCTIConnectorHelper,
        settings: BaseConnectorSettings,
        adapter: DeploymentPushAdapter | None = None,
        *,
        reporter_kwargs: Mapping[str, Any] | None = None,
        **reconciler_kwargs: Any,
    ) -> "DeploymentAssurance":
        """Build the facade from connector settings.

        Args:
            helper: The connector helper.
            settings: Connector settings declaring the ``security_platform``
                namespace (and optionally ``deployment`` and ``hits``).
            adapter: The vendor adapter (see ``DeploymentAssurance``), if any.
            reporter_kwargs: Extra arguments of ``DeploymentReporter``.
            **reconciler_kwargs: Extra arguments of ``DeploymentReconciler``.

        Returns:
            The facade.
        """
        return cls.from_options(
            helper,
            DeploymentAssuranceOptions.from_settings(settings),
            adapter,
            reporter_kwargs=reporter_kwargs,
            **reconciler_kwargs,
        )

    @property
    def enabled(self) -> bool:
        """Tell whether the deployment write-back is enabled by configuration."""
        return self.reporter.enabled

    def start(self) -> bool:
        """Start the write-back and the periodic reconciliation.

        Returns:
            ``True`` when the write-back is operational.
        """
        operational = self.reporter.start()
        if self.reconciler is not None and self.reporter.enabled:
            self.reconciler.start()
        return operational

    def stop(self, timeout: float | None = None) -> None:
        """Stop the reconciliation and flush the queued reports.

        Args:
            timeout: Seconds to wait for a running reconciliation to finish, the
                reports it holds included (``None`` waits until it ends).
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        if self.reconciler is not None:
            self.reconciler.stop(timeout)
        self.reporter.close(
            timeout=None if deadline is None else deadline - time.monotonic()
        )

    def flush(self) -> DeploymentBatchResult:
        """Send the queued reports now.

        Returns:
            The result of the batch.
        """
        return self.reporter.flush()

    def report_pushed(
        self,
        stix_object: Mapping[str, Any],
        *,
        external_id: str | None = None,
        deployed_at: datetime | str | None = None,
    ) -> bool:
        """Queue a ``deployed`` report (see ``DeploymentReporter.report_pushed``).

        Args:
            stix_object: The STIX indicator of the stream event.
            external_id: The id of the indicator on the vendor side.
            deployed_at: Time of the push.

        Returns:
            ``True`` when a report was queued.
        """
        return self.reporter.report_pushed(
            stix_object, external_id=external_id, deployed_at=deployed_at
        )

    def report_push_failed(
        self,
        stix_object: Mapping[str, Any],
        error: BaseException | str,
        *,
        external_id: str | None = None,
    ) -> bool:
        """Queue a ``failed`` report (see ``DeploymentReporter.report_push_failed``).

        Args:
            stix_object: The STIX indicator of the stream event.
            error: The vendor error.
            external_id: The id of the indicator on the vendor side, if any.

        Returns:
            ``True`` when a report was queued.
        """
        return self.reporter.report_push_failed(
            stix_object, error, external_id=external_id
        )

    def report_removed(
        self,
        stix_object: Mapping[str, Any],
        *,
        external_id: str | None = None,
        removed_at: datetime | str | None = None,
    ) -> bool:
        """Queue a ``removed`` report (see ``DeploymentReporter.report_removed``).

        Args:
            stix_object: The STIX indicator of the stream event.
            external_id: The id of the indicator on the vendor side.
            removed_at: Time of the removal.

        Returns:
            ``True`` when a report was queued.
        """
        return self.reporter.report_removed(
            stix_object, external_id=external_id, removed_at=removed_at
        )
