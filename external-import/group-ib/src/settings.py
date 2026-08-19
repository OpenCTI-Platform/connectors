"""Pydantic settings for the Group-IB connector (manager-supported mode).

This module mirrors the connector's existing configuration variables as validated
Pydantic settings so the connector becomes manager-supported. The deeply nested
``ti_api`` configuration is represented as flat fields on a single section because
the connectors-sdk settings loader only resolves two-level ``SECTION_FIELD`` env
vars; the original attribute names are preserved (e.g. ``ti_api_collections_
apt_threat_enable``) so the rest of the connector keeps working unchanged.
"""

import warnings
from datetime import timedelta
from typing import Any, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr, model_validator


class GroupIBConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector section configuration (mirror of the existing ``CONNECTOR_*`` vars)."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="696ac767-c12a-452b-9b77-993e1007eed6",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Group-IB Connector",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[
            "stix2",
            "ipv4-addr",
            "ipv6-addr",
            "vulnerability",
            "domain",
            "url",
            "StixFile",
        ],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="info",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector "
        "(ISO-8601 duration format).",
        default=timedelta(hours=4),  # PT4H
    )
    update_existing_data: bool = Field(
        description="Whether to update data already ingested into the platform.",
        default=True,
    )


class GroupIBTIApiConfig(BaseConfigModel):
    """Group-IB Threat Intelligence API configuration (mirror of the existing ``TI_API__*`` vars).

    The originally nested ``proxy``, ``extra_settings`` and ``collections`` sub-sections
    are flattened into prefixed fields so each value maps to a single env var.
    """

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_double_underscore_env_vars(cls, data: Any) -> Any:
        """Map legacy ``TI_API__*`` env vars to the flattened single-underscore fields.

        Before the manager-supported migration the deeply-nested ``ti_api`` config was
        exposed through double-underscore env vars (e.g. ``TI_API__PROXY__IP``,
        ``TI_API__COLLECTIONS__APT_THREAT__ENABLE``). Those now map to flattened fields
        using single underscores (``proxy_ip``, ``collections_apt_threat_enable``).

        The connectors-sdk loader still parses a legacy variable into this section but
        keeps its raw suffix (e.g. ``TI_API__PROXY__IP`` becomes the key
        ``_proxy__ip``). This validator renames such legacy keys to their canonical
        field name and emits a ``DeprecationWarning``. The canonical (new) variable wins
        when both are provided.
        """
        if not isinstance(data, dict):
            return data

        for legacy_key in [k for k in data if isinstance(k, str) and k.startswith("_")]:
            canonical_key = legacy_key.lstrip("_").replace("__", "_")
            if canonical_key == legacy_key or canonical_key not in cls.model_fields:
                continue

            legacy_env_var = f"TI_API_{legacy_key.upper()}"
            canonical_env_var = f"TI_API_{canonical_key.upper()}"
            warnings.warn(
                f"Environment variable '{legacy_env_var}' is deprecated and will be "
                f"removed in a future release; use '{canonical_env_var}' instead.",
                DeprecationWarning,
                stacklevel=2,
            )

            legacy_value = data.pop(legacy_key)
            if data.get(canonical_key) in (None, ""):
                data[canonical_key] = legacy_value

        return data

    url: str = Field(
        description="Base URL of the Group-IB Threat Intelligence API.",
        default="https://tap.group-ib.com/api/v2/",
    )
    username: str = Field(
        description="Username used to authenticate against the Group-IB TI API.",
    )
    token: SecretStr = Field(
        description="API token used to authenticate against the Group-IB TI API.",
    )

    # --- Proxy (optional; leave unset to disable) ---
    proxy_ip: str | None = Field(
        description="Optional proxy ip used to reach the Group-IB TI API.",
        default=None,
    )
    proxy_port: str | None = Field(
        description="Optional proxy port used to reach the Group-IB TI API.",
        default=None,
    )
    proxy_protocol: str | None = Field(
        description="Optional proxy protocol used to reach the Group-IB TI API.",
        default=None,
    )
    proxy_username: str | None = Field(
        description="Optional proxy username used to reach the Group-IB TI API.",
        default=None,
    )
    proxy_password: SecretStr | None = Field(
        description="Optional proxy password used to reach the Group-IB TI API.",
        default=None,
    )

    # --- Extra settings ---
    extra_settings_ignore_non_indicator_threat_reports: bool = Field(
        description="Extra setting 'ignore_non_indicator_threat_reports'.",
        default=False,
    )
    extra_settings_ignore_non_indicator_threats: bool = Field(
        description="Extra setting 'ignore_non_indicator_threats'.",
        default=False,
    )
    extra_settings_ignore_non_malware_ddos: bool = Field(
        description="Extra setting 'ignore_non_malware_ddos'.",
        default=True,
    )
    extra_settings_intrusion_set_instead_of_threat_actor: bool = Field(
        description="Extra setting 'intrusion_set_instead_of_threat_actor'.",
        default=False,
    )
    extra_settings_schedule_time: str = Field(
        description="Extra setting 'schedule_time'.",
        default="00:00",
    )
    extra_settings_time_output_format: str = Field(
        description="Extra setting 'time_output_format'.",
        default="%Y-%m-%d %H:%M:%S",
    )
    extra_settings_enable_statement_marking: bool = Field(
        description="Extra setting 'enable_statement_marking'.",
        default=False,
    )

    # --- Collections ---
    # apt/threat
    collections_apt_threat_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'apt/threat' collection; empty means last 3 days.",
        default=None,
    )
    collections_apt_threat_enable: bool = Field(
        description="Enable ingestion of the 'apt/threat' collection.",
        default=False,
    )
    collections_apt_threat_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'apt/threat' collection.",
        default=None,
    )
    collections_apt_threat_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'apt/threat' collection.",
        default=90,
    )
    collections_apt_threat_use_hunting_rules: bool = Field(
        description="Apply Group-IB hunting rules when importing the 'apt/threat' collection.",
        default=False,
    )
    # apt/threat_actor
    collections_apt_threat_actor_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'apt/threat_actor' collection; empty means last 3 days.",
        default=None,
    )
    collections_apt_threat_actor_enable: bool = Field(
        description="Enable ingestion of the 'apt/threat_actor' collection.",
        default=False,
    )
    collections_apt_threat_actor_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'apt/threat_actor' collection.",
        default=None,
    )
    collections_apt_threat_actor_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'apt/threat_actor' collection.",
        default=90,
    )
    # attacks/ddos
    collections_attacks_ddos_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'attacks/ddos' collection; empty means last 3 days.",
        default=None,
    )
    collections_attacks_ddos_enable: bool = Field(
        description="Enable ingestion of the 'attacks/ddos' collection.",
        default=False,
    )
    collections_attacks_ddos_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'attacks/ddos' collection.",
        default=None,
    )
    collections_attacks_ddos_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'attacks/ddos' collection.",
        default=30,
    )
    # attacks/deface
    collections_attacks_deface_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'attacks/deface' collection; empty means last 3 days.",
        default=None,
    )
    collections_attacks_deface_enable: bool = Field(
        description="Enable ingestion of the 'attacks/deface' collection.",
        default=False,
    )
    collections_attacks_deface_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'attacks/deface' collection.",
        default=None,
    )
    collections_attacks_deface_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'attacks/deface' collection.",
        default=30,
    )
    # attacks/phishing_group
    collections_attacks_phishing_group_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'attacks/phishing_group' collection; empty means last 3 days.",
        default=None,
    )
    collections_attacks_phishing_group_enable: bool = Field(
        description="Enable ingestion of the 'attacks/phishing_group' collection.",
        default=False,
    )
    collections_attacks_phishing_group_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'attacks/phishing_group' collection.",
        default=None,
    )
    collections_attacks_phishing_group_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'attacks/phishing_group' collection.",
        default=30,
    )
    # attacks/phishing_kit
    collections_attacks_phishing_kit_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'attacks/phishing_kit' collection; empty means last 3 days.",
        default=None,
    )
    collections_attacks_phishing_kit_enable: bool = Field(
        description="Enable ingestion of the 'attacks/phishing_kit' collection.",
        default=False,
    )
    collections_attacks_phishing_kit_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'attacks/phishing_kit' collection.",
        default=None,
    )
    collections_attacks_phishing_kit_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'attacks/phishing_kit' collection.",
        default=30,
    )
    # compromised/access
    collections_compromised_access_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'compromised/access' collection; empty means last 3 days.",
        default=None,
    )
    collections_compromised_access_enable: bool = Field(
        description="Enable ingestion of the 'compromised/access' collection.",
        default=False,
    )
    collections_compromised_access_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'compromised/access' collection.",
        default=None,
    )
    collections_compromised_access_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'compromised/access' collection.",
        default=90,
    )
    # compromised/account_group
    collections_compromised_account_group_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'compromised/account_group' collection; empty means last 3 days.",
        default=None,
    )
    collections_compromised_account_group_enable: bool = Field(
        description="Enable ingestion of the 'compromised/account_group' collection.",
        default=False,
    )
    collections_compromised_account_group_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'compromised/account_group' collection.",
        default=None,
    )
    collections_compromised_account_group_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'compromised/account_group' collection.",
        default=90,
    )
    # compromised/bank_card_group
    collections_compromised_bank_card_group_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'compromised/bank_card_group' collection; empty means last 3 days.",
        default=None,
    )
    collections_compromised_bank_card_group_enable: bool = Field(
        description="Enable ingestion of the 'compromised/bank_card_group' collection.",
        default=False,
    )
    collections_compromised_bank_card_group_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'compromised/bank_card_group' collection.",
        default=None,
    )
    collections_compromised_bank_card_group_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'compromised/bank_card_group' collection.",
        default=90,
    )
    # compromised/discord
    collections_compromised_discord_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'compromised/discord' collection; empty means last 3 days.",
        default=None,
    )
    collections_compromised_discord_enable: bool = Field(
        description="Enable ingestion of the 'compromised/discord' collection.",
        default=False,
    )
    collections_compromised_discord_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'compromised/discord' collection.",
        default=None,
    )
    collections_compromised_discord_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'compromised/discord' collection.",
        default=None,
    )
    # compromised/imei
    collections_compromised_imei_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'compromised/imei' collection; empty means last 3 days.",
        default=None,
    )
    collections_compromised_imei_enable: bool = Field(
        description="Enable ingestion of the 'compromised/imei' collection.",
        default=False,
    )
    collections_compromised_imei_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'compromised/imei' collection.",
        default=None,
    )
    collections_compromised_imei_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'compromised/imei' collection.",
        default=30,
    )
    # compromised/masked_card
    collections_compromised_masked_card_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'compromised/masked_card' collection; empty means last 3 days.",
        default=None,
    )
    collections_compromised_masked_card_enable: bool = Field(
        description="Enable ingestion of the 'compromised/masked_card' collection.",
        default=False,
    )
    collections_compromised_masked_card_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'compromised/masked_card' collection.",
        default=None,
    )
    collections_compromised_masked_card_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'compromised/masked_card' collection.",
        default=90,
    )
    # compromised/messenger
    collections_compromised_messenger_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'compromised/messenger' collection; empty means last 3 days.",
        default=None,
    )
    collections_compromised_messenger_enable: bool = Field(
        description="Enable ingestion of the 'compromised/messenger' collection.",
        default=False,
    )
    collections_compromised_messenger_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'compromised/messenger' collection.",
        default=None,
    )
    collections_compromised_messenger_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'compromised/messenger' collection.",
        default=None,
    )
    # compromised/mule
    collections_compromised_mule_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'compromised/mule' collection; empty means last 3 days.",
        default=None,
    )
    collections_compromised_mule_enable: bool = Field(
        description="Enable ingestion of the 'compromised/mule' collection.",
        default=False,
    )
    collections_compromised_mule_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'compromised/mule' collection.",
        default=None,
    )
    collections_compromised_mule_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'compromised/mule' collection.",
        default=30,
    )
    # hi/open_threats
    collections_hi_open_threats_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'hi/open_threats' collection; empty means last 3 days.",
        default=None,
    )
    collections_hi_open_threats_enable: bool = Field(
        description="Enable ingestion of the 'hi/open_threats' collection.",
        default=False,
    )
    collections_hi_open_threats_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'hi/open_threats' collection.",
        default=None,
    )
    collections_hi_open_threats_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'hi/open_threats' collection.",
        default=None,
    )
    # hi/threat
    collections_hi_threat_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'hi/threat' collection; empty means last 3 days.",
        default=None,
    )
    collections_hi_threat_enable: bool = Field(
        description="Enable ingestion of the 'hi/threat' collection.",
        default=False,
    )
    collections_hi_threat_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'hi/threat' collection.",
        default=None,
    )
    collections_hi_threat_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'hi/threat' collection.",
        default=90,
    )
    collections_hi_threat_use_hunting_rules: bool = Field(
        description="Apply Group-IB hunting rules when importing the 'hi/threat' collection.",
        default=False,
    )
    # hi/threat_actor
    collections_hi_threat_actor_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'hi/threat_actor' collection; empty means last 3 days.",
        default=None,
    )
    collections_hi_threat_actor_enable: bool = Field(
        description="Enable ingestion of the 'hi/threat_actor' collection.",
        default=False,
    )
    collections_hi_threat_actor_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'hi/threat_actor' collection.",
        default=None,
    )
    collections_hi_threat_actor_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'hi/threat_actor' collection.",
        default=90,
    )
    # ioc/common
    collections_ioc_common_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'ioc/common' collection; empty means last 3 days.",
        default=None,
    )
    collections_ioc_common_enable: bool = Field(
        description="Enable ingestion of the 'ioc/common' collection.",
        default=False,
    )
    collections_ioc_common_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'ioc/common' collection.",
        default=None,
    )
    collections_ioc_common_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'ioc/common' collection.",
        default=90,
    )
    # malware/cnc
    collections_malware_cnc_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'malware/cnc' collection; empty means last 3 days.",
        default=None,
    )
    collections_malware_cnc_enable: bool = Field(
        description="Enable ingestion of the 'malware/cnc' collection.",
        default=False,
    )
    collections_malware_cnc_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'malware/cnc' collection.",
        default=None,
    )
    collections_malware_cnc_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'malware/cnc' collection.",
        default=90,
    )
    # malware/config
    collections_malware_config_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'malware/config' collection; empty means last 3 days.",
        default=None,
    )
    collections_malware_config_enable: bool = Field(
        description="Enable ingestion of the 'malware/config' collection.",
        default=False,
    )
    collections_malware_config_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'malware/config' collection.",
        default=None,
    )
    collections_malware_config_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'malware/config' collection.",
        default=30,
    )
    # malware/malware
    collections_malware_malware_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'malware/malware' collection; empty means last 3 days.",
        default=None,
    )
    collections_malware_malware_enable: bool = Field(
        description="Enable ingestion of the 'malware/malware' collection.",
        default=False,
    )
    collections_malware_malware_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'malware/malware' collection.",
        default=None,
    )
    collections_malware_malware_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'malware/malware' collection.",
        default=None,
    )
    # malware/signature
    collections_malware_signature_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'malware/signature' collection; empty means last 3 days.",
        default=None,
    )
    collections_malware_signature_enable: bool = Field(
        description="Enable ingestion of the 'malware/signature' collection.",
        default=False,
    )
    collections_malware_signature_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'malware/signature' collection.",
        default=None,
    )
    collections_malware_signature_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'malware/signature' collection.",
        default=None,
    )
    # malware/yara
    collections_malware_yara_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'malware/yara' collection; empty means last 3 days.",
        default=None,
    )
    collections_malware_yara_enable: bool = Field(
        description="Enable ingestion of the 'malware/yara' collection.",
        default=False,
    )
    collections_malware_yara_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'malware/yara' collection.",
        default=None,
    )
    collections_malware_yara_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'malware/yara' collection.",
        default=None,
    )
    # osi/git_repository
    collections_osi_git_repository_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'osi/git_repository' collection; empty means last 3 days.",
        default=None,
    )
    collections_osi_git_repository_enable: bool = Field(
        description="Enable ingestion of the 'osi/git_repository' collection.",
        default=False,
    )
    collections_osi_git_repository_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'osi/git_repository' collection.",
        default=None,
    )
    collections_osi_git_repository_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'osi/git_repository' collection.",
        default=30,
    )
    # osi/public_leak
    collections_osi_public_leak_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'osi/public_leak' collection; empty means last 3 days.",
        default=None,
    )
    collections_osi_public_leak_enable: bool = Field(
        description="Enable ingestion of the 'osi/public_leak' collection.",
        default=False,
    )
    collections_osi_public_leak_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'osi/public_leak' collection.",
        default=None,
    )
    collections_osi_public_leak_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'osi/public_leak' collection.",
        default=30,
    )
    # osi/vulnerability
    collections_osi_vulnerability_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'osi/vulnerability' collection; empty means last 3 days.",
        default=None,
    )
    collections_osi_vulnerability_enable: bool = Field(
        description="Enable ingestion of the 'osi/vulnerability' collection.",
        default=False,
    )
    collections_osi_vulnerability_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'osi/vulnerability' collection.",
        default=None,
    )
    collections_osi_vulnerability_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'osi/vulnerability' collection.",
        default=30,
    )
    # suspicious_ip/open_proxy
    collections_suspicious_ip_open_proxy_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'suspicious_ip/open_proxy' collection; empty means last 3 days.",
        default=None,
    )
    collections_suspicious_ip_open_proxy_enable: bool = Field(
        description="Enable ingestion of the 'suspicious_ip/open_proxy' collection.",
        default=False,
    )
    collections_suspicious_ip_open_proxy_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'suspicious_ip/open_proxy' collection.",
        default=None,
    )
    collections_suspicious_ip_open_proxy_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'suspicious_ip/open_proxy' collection.",
        default=15,
    )
    # suspicious_ip/scanner
    collections_suspicious_ip_scanner_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'suspicious_ip/scanner' collection; empty means last 3 days.",
        default=None,
    )
    collections_suspicious_ip_scanner_enable: bool = Field(
        description="Enable ingestion of the 'suspicious_ip/scanner' collection.",
        default=False,
    )
    collections_suspicious_ip_scanner_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'suspicious_ip/scanner' collection.",
        default=None,
    )
    collections_suspicious_ip_scanner_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'suspicious_ip/scanner' collection.",
        default=15,
    )
    # suspicious_ip/socks_proxy
    collections_suspicious_ip_socks_proxy_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'suspicious_ip/socks_proxy' collection; empty means last 3 days.",
        default=None,
    )
    collections_suspicious_ip_socks_proxy_enable: bool = Field(
        description="Enable ingestion of the 'suspicious_ip/socks_proxy' collection.",
        default=False,
    )
    collections_suspicious_ip_socks_proxy_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'suspicious_ip/socks_proxy' collection.",
        default=None,
    )
    collections_suspicious_ip_socks_proxy_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'suspicious_ip/socks_proxy' collection.",
        default=2,
    )
    # suspicious_ip/tor_node
    collections_suspicious_ip_tor_node_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'suspicious_ip/tor_node' collection; empty means last 3 days.",
        default=None,
    )
    collections_suspicious_ip_tor_node_enable: bool = Field(
        description="Enable ingestion of the 'suspicious_ip/tor_node' collection.",
        default=False,
    )
    collections_suspicious_ip_tor_node_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'suspicious_ip/tor_node' collection.",
        default=None,
    )
    collections_suspicious_ip_tor_node_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'suspicious_ip/tor_node' collection.",
        default=30,
    )
    # suspicious_ip/vpn
    collections_suspicious_ip_vpn_default_date: str | None = Field(
        description="Start date (YYYY-MM-DD) for the first import of the 'suspicious_ip/vpn' collection; empty means last 3 days.",
        default=None,
    )
    collections_suspicious_ip_vpn_enable: bool = Field(
        description="Enable ingestion of the 'suspicious_ip/vpn' collection.",
        default=False,
    )
    collections_suspicious_ip_vpn_local_custom_tag: str | None = Field(
        description="Optional custom label added to objects from the 'suspicious_ip/vpn' collection.",
        default=None,
    )
    collections_suspicious_ip_vpn_ttl: int | None = Field(
        description="Time-to-live (in days) for indicators from the 'suspicious_ip/vpn' collection.",
        default=30,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the Group-IB connector."""

    connector: GroupIBConnectorConfig = Field(
        default_factory=GroupIBConnectorConfig,
    )
    ti_api: GroupIBTIApiConfig = Field(default_factory=GroupIBTIApiConfig)
