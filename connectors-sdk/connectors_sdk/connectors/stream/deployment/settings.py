"""Configuration of the deployment write-back.

Stream connectors add three namespaces to their ``BaseConnectorSettings``, which
gives the documented environment variables:

- ``deployment`` -> ``DEPLOYMENT_REPORTING_ENABLED``, ``DEPLOYMENT_RECONCILIATION_INTERVAL``
- ``hits`` -> ``HITS_REPORTING_ENABLED`` (only for connectors able to read hits back)
- ``security_platform`` -> ``SECURITY_PLATFORM_NAME``, ``SECURITY_PLATFORM_TYPE``,
  ``SECURITY_PLATFORM_ID``

Example:
    >>> class MySecurityPlatformConfig(SecurityPlatformConfig):
    ...     name: str = Field(default="My EDR", min_length=2, description="...")
    ...     type: str | None = Field(default="EDR", description="...")
    ...
    >>> class ConnectorSettings(BaseConnectorSettings):
    ...     connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    ...     deployment: DeploymentConfig = Field(default_factory=DeploymentConfig)
    ...     hits: HitsConfig = Field(default_factory=HitsConfig)
    ...     security_platform: MySecurityPlatformConfig = Field(
    ...         default_factory=MySecurityPlatformConfig
    ...     )
"""

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Self

from connectors_sdk.settings.base_settings import (
    BaseConfigModel,
    BaseConnectorSettings,
)
from pydantic import Field


class DeploymentConfig(BaseConfigModel):
    """Deployment write-back options (``DEPLOYMENT_*`` variables)."""

    reporting_enabled: bool = Field(
        default=True,
        description=(
            "Report to OpenCTI the deployment status of every indicator pushed to the "
            "security platform (deployed, failed, removed), stored on the 'deployed-on' "
            "relationship between the indicator and the Security Platform entity. "
            "Ignored (no-op) on OpenCTI platforms that do not support the deployment write-back."
        ),
    )
    reconciliation_interval: int = Field(
        default=60,
        ge=0,
        description=(
            "Interval in minutes between two reconciliations of the deployment statuses "
            "with the indicators read back from the security platform. 0 disables the reconciliation."
        ),
    )


class HitsConfig(BaseConfigModel):
    """Hit reporting options (``HITS_*`` variables)."""

    reporting_enabled: bool = Field(
        default=True,
        description=(
            "Report to OpenCTI the detections (hits) of deployed indicators observed on the "
            "security platform, as a sighting of the indicator on the Security Platform entity. "
            "Hits are collected during each reconciliation."
        ),
    )


class SecurityPlatformConfig(BaseConfigModel):
    """Identity of the security platform in OpenCTI (``SECURITY_PLATFORM_*`` variables).

    Connectors subclass it to give their default ``name`` and ``type``.
    """

    name: str = Field(
        min_length=2,
        description=(
            "Name of the Security Platform entity representing the platform in OpenCTI. "
            "The entity is created if it does not exist (upsert by name)."
        ),
    )
    type: str | None = Field(
        default=None,
        description=(
            "Type of the Security Platform entity (open vocabulary "
            "'security_platform_type_ov', e.g. EDR, XDR, SIEM, SOAR, NDR, ISPM)."
        ),
    )
    id: str | None = Field(
        default=None,
        description=(
            "Id of an existing Security Platform entity in OpenCTI. When set, it is used "
            "instead of resolving the entity by name."
        ),
    )


@dataclass(frozen=True, slots=True)
class DeploymentAssuranceOptions:
    """Resolved deployment write-back options of a connector.

    Attributes:
        security_platform_name: Name of the Security Platform entity.
        security_platform_type: Type of the Security Platform entity.
        security_platform_id: Id of an existing Security Platform entity.
        reporting_enabled: Whether the deployment write-back is enabled.
        reconciliation_interval: Minutes between two reconciliations (0 disables).
        hits_reporting_enabled: Whether hits are reported.
    """

    security_platform_name: str
    security_platform_type: str | None = None
    security_platform_id: str | None = None
    reporting_enabled: bool = True
    reconciliation_interval: int = 60
    hits_reporting_enabled: bool = True

    @classmethod
    def from_configs(
        cls,
        *,
        deployment: DeploymentConfig,
        security_platform: SecurityPlatformConfig,
        hits: HitsConfig | None = None,
    ) -> Self:
        """Build the options from the configuration models.

        Args:
            deployment: The ``deployment`` namespace.
            security_platform: The ``security_platform`` namespace.
            hits: The ``hits`` namespace, ``None`` when the connector cannot report hits.

        Returns:
            The resolved options.
        """
        return cls(
            security_platform_name=security_platform.name,
            security_platform_type=security_platform.type or None,
            security_platform_id=security_platform.id or None,
            reporting_enabled=deployment.reporting_enabled,
            reconciliation_interval=deployment.reconciliation_interval,
            hits_reporting_enabled=(
                hits.reporting_enabled if hits is not None else False
            ),
        )

    @classmethod
    def from_settings(cls, settings: BaseConnectorSettings) -> Self:
        """Build the options from connector settings declaring the namespaces.

        Args:
            settings: The connector settings. ``security_platform`` is required,
                ``deployment`` defaults to its default values and a missing ``hits``
                namespace disables hit reporting.

        Returns:
            The resolved options.

        Raises:
            ValueError: If the settings do not declare a ``security_platform`` namespace.
        """
        security_platform = getattr(settings, "security_platform", None)
        if not isinstance(security_platform, SecurityPlatformConfig):
            raise ValueError(
                "The connector settings must declare a 'security_platform' namespace "
                "(SecurityPlatformConfig) to report deployments."
            )
        deployment = getattr(settings, "deployment", None)
        hits = getattr(settings, "hits", None)
        return cls.from_configs(
            deployment=(
                deployment
                if isinstance(deployment, DeploymentConfig)
                else DeploymentConfig()
            ),
            security_platform=security_platform,
            hits=hits if isinstance(hits, HitsConfig) else None,
        )

    @classmethod
    def from_legacy_config(
        cls,
        config: Mapping[str, Any] | None,
        *,
        default_platform_name: str,
        default_platform_type: str | None = None,
        hits_supported: bool = True,
    ) -> Self:
        """Build the options for a connector still loading its configuration by hand.

        Values are read from the environment variables first, then from the
        ``config.yml`` content (``deployment.reporting_enabled``...), then the
        defaults, and validated with the same models as SDK-based connectors.

        Args:
            config: The parsed ``config.yml`` content, if any.
            default_platform_name: The default ``SECURITY_PLATFORM_NAME``.
            default_platform_type: The default ``SECURITY_PLATFORM_TYPE``.
            hits_supported: Whether the connector can report hits.

        Returns:
            The resolved options.
        """

        def read(namespace: str, field_name: str) -> Any:
            env_name = f"{namespace}_{field_name}".upper()
            if env_name in os.environ:
                return os.environ[env_name]
            return _read_path(config, (namespace, field_name))

        def values(namespace: str, field_names: Sequence[str]) -> dict[str, Any]:
            raw = {name: read(namespace, name) for name in field_names}
            return {name: value for name, value in raw.items() if value is not None}

        platform_values = {
            "name": default_platform_name,
            "type": default_platform_type,
            **values("security_platform", ("name", "type", "id")),
        }
        return cls.from_configs(
            deployment=DeploymentConfig(
                **values("deployment", ("reporting_enabled", "reconciliation_interval"))
            ),
            security_platform=SecurityPlatformConfig(**platform_values),
            hits=(
                HitsConfig(**values("hits", ("reporting_enabled",)))
                if hits_supported
                else None
            ),
        )


def _read_path(config: Mapping[str, Any] | None, path: Sequence[str]) -> Any:
    """Read a nested value of a configuration mapping.

    Args:
        config: The configuration mapping.
        path: The keys to follow.

    Returns:
        The value, or ``None`` when a key is missing.
    """
    node: Any = config
    for key in path:
        if not isinstance(node, Mapping):
            return None
        node = node.get(key)
    return node
