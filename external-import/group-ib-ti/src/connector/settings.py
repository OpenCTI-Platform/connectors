import logging
import os
import re
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

import yaml
from _data.iso3166 import COUNTRIES as _ISO3166_COUNTRIES
from ciaops.utils import FileHandler
from connector.logging_config import (
    _DEFAULT_LOG_BACKUP_COUNT,
    _DEFAULT_LOG_DIR,
    _DEFAULT_LOG_MAX_BYTES,
    FileLoggingConfig,
)
from connectors_sdk.settings.annotated_types import ListFromString
from connectors_sdk.settings.base_settings import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from dotenv import load_dotenv
from pycti import get_config_variable
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    create_model,
    model_validator,
)
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE, MarkingDefinition
from stix2.v21.vocab import MALWARE_TYPE

# ============================================================================
# Connector-wide constants
# Every magic number / lookup / regex used across modules lives here.
# ============================================================================

# Anchor date for deterministic STIX Note ID generation.
TI_NOTE_ID_ANCHOR = datetime(2020, 1, 1, tzinfo=timezone.utc)

# Hard cap on OpenCTI Note content (characters).
NOTE_MAX_CONTENT = 50_000

# Fallback Indicator lifetime when neither the upstream event nor the
# per-collection .env override carries a TTL.
DEFAULT_TTL_DAYS = 365

# ----- Regex patterns (cached at import time, used in hot paths) -----

# Control characters stripped from descriptions before stix2 serialization
# (keeps \n, \r, \t).
CTRL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

# Generic HTML tag stripper for description sanitization.
HTML_TAG_RE = re.compile("<.*?>")

# Email address validator. Single source of truth used by every handler
# that emits ``ds.Email`` (compromised/spd, attacks/phishing_kit,
# osi/git_repository, etc.). Mirrors the syntax OpenCTI itself accepts for
# Email-Addr observables (checkObservableSyntax): RFC-5322 local-part
# characters and ASCII letter/digit/hyphen domain labels — anything looser
# is rejected by the platform with "Observable is not correctly formatted".
EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)

# Domain-name validator. Mirrors the syntax OpenCTI accepts for
# Domain-Name observables: hyphen-safe ASCII labels plus a final label
# that is alphabetic (or punycode ``xn--``) — anything looser, e.g. an
# IPv4 address or a numeric TLD, is rejected by the platform with
# "Observable is not correctly formatted". IP addresses that arrive in
# domain fields are re-emitted as IP observables by the adapters.
DOMAIN_RE = re.compile(
    r"^(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+"
    r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59})$"
)

# Description-sanitation regexes (used by ``support.text_normalize``).
DESC_BR_RE = re.compile(r"<br\s*/?>", re.IGNORECASE)
DESC_CLOSE_P_RE = re.compile(r"</p\s*>", re.IGNORECASE)
DESC_OPEN_P_RE = re.compile(r"<p[^>]*>", re.IGNORECASE)
DESC_CLOSE_LI_RE = re.compile(r"</li\s*>", re.IGNORECASE)
DESC_OPEN_LI_RE = re.compile(r"<li[^>]*>", re.IGNORECASE)
DESC_TAG_RE = re.compile(r"<[^>]+>")
DESC_HSPACE_RE = re.compile(r"[ \t\xa0]+")
DESC_PARA_RE = re.compile(r"(?:\s*\n){2,}\s*")


# ----- Scoring tables -----

# Group-IB ``threatLevel`` -> (x_opencti_score, severity label).
#
# NOTE: There is no industry standard mapping from Group-IB's threat-level
# buckets to OpenCTI's 0-100 score. These values are connector-defined and
# intentionally bias toward "trustworthy enough to alert on": Medium=50
# stays visible without driving automation; Critical=90 leaves room for
# manual analyst override at 100.
THREAT_LEVEL_TO_SCORE: dict[str, tuple[int, str]] = {
    "low": (25, "severity:low"),
    "medium": (50, "severity:medium"),
    "medium-high": (65, "severity:medium-high"),
    "high": (75, "severity:high"),
    "critical": (90, "severity:critical"),
}

# Group-IB ``evaluation.severity`` colour -> OpenCTI Incident severity label.
SEVERITY_COLOR_MAP: dict[str, str] = {
    "red": "critical",
    "orange": "high",
    "amber": "high",
    "yellow": "medium",
    "green": "low",
}

# CVSS v3 base-score -> qualitative severity bands.
# Source: FIRST.org CVSS v3.1 specification, section 5
# https://www.first.org/cvss/v3.1/specification-document
CVSS_SEVERITY_LOW_MAX = 3.9  # 0.1 - 3.9   -> LOW
CVSS_SEVERITY_MEDIUM_MIN = 4.0
CVSS_SEVERITY_MEDIUM_MAX = 6.9  # 4.0 - 6.9   -> MEDIUM
CVSS_SEVERITY_HIGH_MIN = 7.0
CVSS_SEVERITY_HIGH_MAX = 8.9  # 7.0 - 8.9   -> HIGH
CVSS_SEVERITY_CRITICAL_MIN = 9.0  # 9.0 - 10.0  -> CRITICAL


# Group-IB collection slug -> collection label for OpenCTI.
COLLECTION_DISPLAY_LABEL: dict[str, str] = {
    "apt/threat": "collection:Nation-State Threat Report",
    "apt/threat_actor": "collection:Nation-State Threat Actor",
    "attacks/ddos": "collection:Attacks DDoS",
    "attacks/deface": "collection:Attacks Deface",
    "attacks/phishing_group": "collection:Attacks Phishing Group",
    "attacks/phishing_kit": "collection:Attacks Phishing Kit",
    "compromised/access": "collection:Compromised Shops",
    "compromised/account_group": "collection:Compromised Account",
    "compromised/bank_card_group": "collection:Compromised Group Card",
    "compromised/discord": "collection:Compromised Discord",
    "compromised/masked_card": "collection:Compromised Masked Card",
    "compromised/messenger": "collection:Compromised Telegram",
    "compromised/spd": "collection:Compromised SPD",
    "darkweb/forums": "collection:Compromised Darkweb",
    "hi/threat": "collection:Cybercriminals Threat Report",
    "hi/threat_actor": "collection:Cybercriminals Threat Actor",
    "hi/open_threats": "collection:Open Threats",
    "ioc/primary": "collection:IOC Primary",
    "malware/cnc": "collection:Malware C&C",
    "malware/config": "collection:Malware Config",
    "malware/malware": "collection:Malware Report",
    "malware/signature": "collection:Malware Signature",
    "malware/yara": "collection:Malware YARA",
    "osi/git_repository": "collection:OSI Git repository",
    "osi/public_leak": "collection:OSI Public Leak",
    "osi/vulnerability": "collection:OSI Vulnerability",
    "suspicious_ip/open_proxy": "collection:Suspicious IP Open Proxy",
    "suspicious_ip/scanner": "collection:Suspicious IP Scanner",
    "suspicious_ip/socks_proxy": "collection:Suspicious IP Socks Proxy",
    "suspicious_ip/tor_node": "collection:Suspicious IP Tor Node",
    "suspicious_ip/vpn": "collection:Suspicious IP VPN",
}

# Brief pause after ``api.work.initiate_work`` so OpenCTI registers the
# work id before the connector streams bundles into it.
INITIATE_WORK_DELAY_SEC = 3

# OpenCTI rejects work.report_expectation payloads above this size.
MAX_ERROR_TRUNCATE_LEN = 3500

# Default ``source_name`` for the Group-IB TI portal external reference
# attached to every emitted SDO (overridable when the mapping provides
# its own portal-link label).
PORTAL_LINK_DEFAULT_LABEL = "Group-IB TI portal"

# Actor-profile collections carry the rich ``stat.*`` block worth a Note.
# The threat actors embedded in report collections (apt/threat, hi/threat)
# only carry name/country, so they get no profile Note.
ACTOR_PROFILE_COLLECTIONS = frozenset({"apt/threat_actor", "hi/threat_actor"})

# Upstream malware/malware emits this literal when no real description exists;
# the adapter substitutes ``shortDescription`` when seen.
MALWARE_DESC_PLACEHOLDER = "Sorry, no description yet."

# Collections that emit a report-level Note (apt/threat, hi/threat).
REPORT_NOTE_COLLECTIONS = frozenset({"apt/threat", "hi/threat"})


# ============================================================================
# Pydantic settings models
# ----------------------------------------------------------------------------
# ``ConnectorSettings`` (bottom of this block) is the single validated source
# of configuration for the whole connector: the standard ``opencti`` and
# ``connector`` sections AND the connector-specific ``ti_api`` section. It is
# what the connector manager reads (``connector_config_schema.json``) and what
# ``main.py`` turns into the pycti helper config via ``to_helper_config()``.
#
# History: before the manager-supported migration this module only modelled
# the framework fields; the whole ``TI_API__*`` surface was read by a legacy
# loader in ``ConfigConnector`` (yaml + ``get_config_variable`` + a scan of
# ``os.environ``) and validated *non-fatally* against a documentation-only
# model. This commit only ADDS the validated ``ti_api`` section to
# ``ConnectorSettings``; the next one makes ``ConfigConnector`` read it (until
# then the legacy loader at the bottom of this module is still the runtime source).
#
# TODO(manager-supported blocker) [BLOCKING -> resolved with a workaround,
# needs a maintainer decision]: this connector's configuration is a tree
#     TI_API__COLLECTIONS__<SLUG>__<KEY>, TI_API__EXTRA_SETTINGS__<KEY>,
#     TI_API__PROXY__<KEY>, TI_API__URL, ...
# but the connectors-sdk loader (``_SettingsLoader``: ``env_nested_delimiter``
# ``"_"`` with ``env_nested_max_split=1``) and the manager's schema generator
# only understand ONE nesting level, ``<SECTION>_<FIELD>``. Consequences:
#   * ``TI_API__URL`` (double underscore) is NOT parsed by the sdk: it lands in
#     ``ti_api`` as an unknown ``_url`` extra and the real ``url`` stays unset.
#   * ``proxy`` / ``extra_settings`` / ``collections`` cannot be nested models
#     or dicts on the env-var side.
# Workaround implemented below: ``ti_api`` is FLAT. Every leaf becomes its own
# field named exactly like the legacy in-memory attribute (``proxy_ip``,
# ``extra_settings_<key>``, ``collections_<slug>_<key>``), i.e. the env vars
# become ``TI_API_PROXY_IP``, ``TI_API_EXTRA_SETTINGS_<KEY>``,
# ``TI_API_COLLECTIONS_<SLUG>_<KEY>``. A ``mode="before"`` validator
# (``_TIApiCoreConfig._normalize_keys``) keeps the old spellings working:
# nested ``config.yml`` blocks are flattened and legacy ``TI_API__*`` env vars
# are mapped (with a deprecation warning). Resulting schema: 234 flat
# ``TI_API_*`` variables in the manager form (see the collection table below).
# Alternatives to decide between: (a) accept the rename + long flat list (done
# here); (b) one JSON-valued ``TI_API_COLLECTIONS`` variable; (c) teach the sdk
# loader/schema generator about deeper nesting.
# ============================================================================


class _SettingsBase(BaseModel):
    model_config = ConfigDict(extra="ignore")


# The three models below are FIELD CATALOGUES: they document the type and
# meaning of every ``ti_api`` leaf. They are not validated directly any more;
# ``_flat_ti_api_fields`` turns them into the flat ``TIApiConfig`` fields.


class ProxySettings(_SettingsBase):
    ip: str | None = Field(default=None, description="Proxy host or IP.")
    port: int | None = Field(default=None, description="Proxy port.")
    protocol: str | None = Field(
        default=None, description="Proxy protocol (http/https)."
    )
    username: str | None = Field(default=None, description="Proxy username.")
    password: str | None = Field(default=None, description="Proxy password.")


class CollectionSettings(_SettingsBase):
    """Per-collection settings. The union of every per-collection key; each
    collection uses the subset listed in ``_COLLECTION_EXTRA_KEYS`` (the same
    subset ``.env.sample`` and the README document)."""

    enable: bool = Field(
        default=False, description="Ingest this collection. Must be true to run."
    )
    default_date: str | None = Field(
        default=None,
        description="First-run lookback anchor (YYYY-MM-DD). Ignored after the "
        "stored sequpdate cursor takes over.",
        examples=["2024-01-01"],
    )
    ttl: int | None = Field(
        default=None,
        description="Validity period (days) for emitted Indicator SDOs.",
        examples=[30, 90, 1460],
    )
    local_custom_tag: str | None = Field(
        default=None,
        description="Extra bare label appended to every entity from this collection.",
    )
    use_hunting_rules: bool | None = Field(
        default=None,
        description="Ask the Group-IB API to apply portal hunting rules "
        "server-side (only honored by collections that support it).",
    )
    description_in_external_references: bool | None = Field(
        default=None,
        description="Move the entity description into an external reference "
        "instead of the SDO description field.",
    )
    full_data: bool | None = Field(
        default=None,
        description="Emit full text instead of a truncated preview in Notes.",
    )
    data_preview_max_len: int | None = Field(
        default=None,
        description="Max characters of preview text in Notes when full_data is off.",
    )
    cnc_as_indicator: bool | None = Field(
        default=None, description="Emit CnC observables as Indicators."
    )
    all_observables_as_indicators: bool | None = Field(
        default=None,
        description="Emit every observable of the event as an Indicator.",
    )
    observables_as_indicators: bool | None = Field(
        default=None, description="Emit report IOC observables as Indicators."
    )
    target_observables: bool | None = Field(
        default=None, description="Emit non-IOC target/victim observables."
    )
    targeted_entities_as_sdo: bool | None = Field(
        default=None,
        description="Promote victimology (sectors/regions/companies) into SDOs.",
    )
    create_incident: bool | None = Field(
        default=None, description="Create an Incident SDO per event."
    )
    brand_as_identity: bool | None = Field(
        default=None, description="Emit the impersonated brand as an Identity."
    )
    author_email_observables: bool | None = Field(
        default=None, description="Emit commit-author emails as observables."
    )
    redact_message_text: bool | None = Field(
        default=None,
        description="Omit the raw chat message body from the Note (keep metadata).",
    )
    store_report_labels_in_note: bool | None = Field(
        default=None, description="Write report labels to a Note instead of the SDO."
    )
    add_threat_actor_label_to_observables: bool | None = Field(
        default=None, description="Attach the actor name as a label on observables."
    )
    include_malware_labels: bool | None = Field(
        default=None,
        description="Tag entities with the originating malware family name.",
    )
    include_threat_actor_labels: bool | None = Field(
        default=None, description="Add labels naming the linked threat actors."
    )
    include_malware_threat_actor_labels: bool | None = Field(
        default=None,
        description="Add labels naming the threat actors linked to the malware.",
    )
    include_source_type_labels: bool | None = Field(
        default=None, description="Add bare labels from the API `source_type` field."
    )
    include_brand_labels: bool | None = Field(
        default=None, description="Add bare labels naming the impersonated brands."
    )
    include_expertise_labels: bool | None = Field(
        default=None,
        description="Add bare expertise labels from the report `expertise` field.",
    )
    include_nation_state_label: bool | None = Field(
        default=None, description="Add the global `nation_state` label."
    )
    include_cybercriminal_label: bool | None = Field(
        default=None, description="Add the global `cybercriminal` label."
    )
    include_context_label: bool | None = Field(
        default=None,
        description="Add labels derived from the payload (tailored, autogen, "
        "raw labels).",
    )
    include_passwords: bool | None = Field(
        default=None,
        description="Include cleartext passwords in the account-group Note "
        "(off by default for GDPR / compliance reasons).",
    )
    include_text_in_note: bool | None = Field(
        default=None, description="Include the parsed text body in the Note."
    )
    include_original_in_note: bool | None = Field(
        default=None, description="Include the raw original payload in the Note."
    )
    include_translation_in_note: bool | None = Field(
        default=None,
        description="Append the message translation (when present) to the Note.",
    )
    unique: bool | None = Field(
        default=None,
        description="Upstream API parameter: deduplicate by credential pair.",
    )
    combolist: bool | None = Field(
        default=None,
        description="Upstream API parameter: include records sourced from "
        "combolists (vs. only stealer logs).",
    )
    probable_corporate_access: bool | None = Field(
        default=None,
        description="Upstream API parameter: prioritise records that look like "
        "corporate access.",
    )


class ExtraSettings(_SettingsBase):
    intrusion_set_instead_of_threat_actor: bool = Field(
        default=False,
        description="Emit Intrusion-Set SDOs instead of Threat-Actor.",
    )
    ignore_non_malware_ddos: bool = Field(
        default=False, description="Drop DDoS events without a malware payload."
    )
    ignore_non_indicator_threats: bool = Field(
        default=False, description="Drop threat events carrying no indicators."
    )
    ignore_non_indicator_threat_reports: bool = Field(
        default=False, description="Drop threat reports carrying no indicators."
    )
    enable_statement_marking: bool = Field(
        default=False, description="Attach a Group-IB statement marking to bundles."
    )
    preserve_manual_labels: bool = Field(
        default=False,
        description="Omit x_opencti_labels so analyst-added labels survive updates.",
    )
    time_output_format: str | None = Field(
        default=None,
        description="strftime format for human-readable timestamps in logs.",
        examples=["%Y-%m-%d %H:%M:%S"],
    )
    # TODO(manager-supported blocker) [minor]: file logging is a dev-only
    # feature that needs a bind-mounted volume (``./logs`` in docker-compose).
    # The connector manager does not mount volumes, so these four variables are
    # exposed in the manager form but cannot be used meaningfully there.
    enable_file_logging: bool = Field(
        default=False, description="Write rotating file logs in addition to stdout."
    )
    log_file_dir: str | None = Field(
        default=None, description="Directory for rotating file logs."
    )
    log_file_max_bytes: int | None = Field(
        default=None, description="Max size (bytes) per log file before rotation."
    )
    log_file_backup_count: int | None = Field(
        default=None, description="Number of rotated log files to keep."
    )


# ---- legacy documentation-only models, removed once ConfigConnector reads
# ---- the validated settings (next commit) ----


class OpenCTISettings(_SettingsBase):
    url: str | None = Field(default=None, description="OpenCTI platform URL.")
    token: str | None = Field(default=None, description="OpenCTI API token.")


class TIApiSettings(_SettingsBase):
    url: str | None = Field(default=None, description="Group-IB TI API URL.")
    username: str | None = Field(
        default=None, description="Group-IB TI portal profile email."
    )
    token: str | None = Field(default=None, description="Group-IB TI API token.")
    proxy: ProxySettings = Field(default_factory=ProxySettings)
    collections: dict[str, CollectionSettings] = Field(default_factory=dict)
    extra_settings: ExtraSettings = Field(default_factory=ExtraSettings)


class GroupIBConnectorSettings(_SettingsBase):
    """Top-level connector configuration schema (Group-IB TI → OpenCTI)."""

    opencti: OpenCTISettings = Field(default_factory=OpenCTISettings)
    ti_api: TIApiSettings = Field(default_factory=TIApiSettings)


# Keys every collection accepts.
_COMMON_COLLECTION_KEYS = ("enable", "default_date", "ttl", "local_custom_tag")

# Extra per-collection keys, per collection (env-style slug, ``/`` -> ``_``).
# This is the exact set ``.env.sample`` / the README document per collection.
# TODO(manager-supported blocker) [needs decision]: 31 collections x (4 common
# + up to 9 own) keys = 215 flat ``TI_API_COLLECTIONS_<SLUG>_<KEY>`` variables
# in the manager schema. A key not listed here is still honoured at runtime
# (it is kept as an unvalidated extra) but the manager cannot set it.
_COLLECTION_EXTRA_KEYS: dict[str, str] = {
    "apt_threat": (
        "use_hunting_rules store_report_labels_in_note "
        "add_threat_actor_label_to_observables "
        "include_threat_actor_labels include_nation_state_label "
        "include_context_label description_in_external_references "
        "targeted_entities_as_sdo include_expertise_labels"
    ),
    "apt_threat_actor": (
        "use_hunting_rules include_nation_state_label "
        "description_in_external_references"
    ),
    "attacks_ddos": "use_hunting_rules cnc_as_indicator create_incident",
    "attacks_deface": "create_incident",
    "attacks_phishing_group": "use_hunting_rules brand_as_identity include_brand_labels",
    "attacks_phishing_kit": "use_hunting_rules brand_as_identity include_brand_labels",
    "compromised_access": (
        "data_preview_max_len full_data "
        "description_in_external_references cnc_as_indicator "
        "target_observables"
    ),
    "compromised_account_group": (
        "include_passwords include_malware_labels "
        "include_malware_threat_actor_labels include_source_type_labels "
        "description_in_external_references unique combolist "
        "probable_corporate_access"
    ),
    "compromised_bank_card_group": "description_in_external_references",
    "compromised_discord": (
        "use_hunting_rules redact_message_text "
        "include_translation_in_note full_data data_preview_max_len"
    ),
    "compromised_masked_card": (
        "description_in_external_references include_malware_labels "
        "include_threat_actor_labels include_source_type_labels"
    ),
    "compromised_messenger": (
        "use_hunting_rules redact_message_text "
        "include_translation_in_note full_data data_preview_max_len"
    ),
    "compromised_spd": "description_in_external_references",
    "darkweb_forums": "use_hunting_rules",
    "hi_open_threats": (
        "use_hunting_rules description_in_external_references "
        "data_preview_max_len full_data include_text_in_note "
        "include_original_in_note observables_as_indicators"
    ),
    "hi_threat": (
        "use_hunting_rules store_report_labels_in_note "
        "add_threat_actor_label_to_observables "
        "include_threat_actor_labels include_cybercriminal_label "
        "include_context_label description_in_external_references "
        "targeted_entities_as_sdo include_expertise_labels"
    ),
    "hi_threat_actor": (
        "use_hunting_rules include_cybercriminal_label "
        "description_in_external_references"
    ),
    "ioc_primary": "",
    "malware_cnc": (
        "include_malware_labels include_threat_actor_labels "
        "all_observables_as_indicators"
    ),
    "malware_config": (
        "use_hunting_rules description_in_external_references include_malware_labels"
    ),
    "malware_malware": "description_in_external_references",
    "malware_signature": "",
    "malware_yara": "",
    "osi_git_repository": (
        "use_hunting_rules description_in_external_references author_email_observables"
    ),
    "osi_public_leak": (
        "use_hunting_rules data_preview_max_len full_data "
        "description_in_external_references"
    ),
    "osi_vulnerability": "use_hunting_rules",
    "suspicious_ip_open_proxy": "use_hunting_rules",
    "suspicious_ip_scanner": "use_hunting_rules",
    "suspicious_ip_socks_proxy": "use_hunting_rules",
    "suspicious_ip_tor_node": "use_hunting_rules",
    "suspicious_ip_vpn": "use_hunting_rules",
}

# env-style slug ("apt_threat") -> Group-IB collection slug ("apt/threat").
_SLASH_SLUG_BY_ENV_SLUG = {
    slug.replace("/", "_"): slug for slug in COLLECTION_DISPLAY_LABEL
}


def _flat_ti_api_fields() -> dict[str, Any]:
    """Build the flat ``ti_api`` field definitions from the field catalogues.

    Field names are the legacy in-memory attribute names minus the ``ti_api_``
    prefix (``proxy_ip``, ``extra_settings_<key>``, ``collections_<slug>_<key>``),
    so ``ConfigConnector`` re-exposes them 1:1 as ``ti_api_<name>`` and every
    existing ``get_collection_settings`` / ``get_extra_settings_by_name`` call
    keeps working untouched. The sdk env parser turns each field ``<name>`` into
    the env var ``TI_API_<NAME>``.
    """
    fields: dict[str, Any] = {}

    for key, info in ProxySettings.model_fields.items():
        annotation = SecretStr | None if key == "password" else info.annotation
        fields[f"proxy_{key}"] = (
            annotation,
            Field(default=None, description=info.description),
        )

    for key, info in ExtraSettings.model_fields.items():
        fields[f"extra_settings_{key}"] = (
            info.annotation,
            Field(
                default=info.default,
                description=info.description,
                examples=info.examples,
            ),
        )

    for env_slug, extra_keys in _COLLECTION_EXTRA_KEYS.items():
        for key in (*_COMMON_COLLECTION_KEYS, *extra_keys.split()):
            info = CollectionSettings.model_fields[key]
            if key == "enable":
                annotation, default = bool, False
            else:
                # Unset (None) is meaningful: the call sites carry their own
                # per-key defaults (``get_setting_bool(..., default=True)``) and
                # the ciaops poller only forwards a filter when it is not None.
                annotation, default = Optional[info.annotation], None
            fields[f"collections_{env_slug}_{key}"] = (
                annotation,
                Field(
                    default=default,
                    description=(
                        f"{info.description} "
                        f"[collection: {_SLASH_SLUG_BY_ENV_SLUG[env_slug]}]"
                    ),
                    examples=info.examples,
                ),
            )
    return fields


def _normalize_ti_api_keys(data: dict[str, Any]) -> dict[str, Any]:
    """Bring every accepted spelling of the ``ti_api`` config to flat field names.

    Accepted inputs, in decreasing order of precedence:
      1. flat names (``proxy_ip``, ``collections_apt_threat_ttl``): what the sdk
         yields for the canonical ``TI_API_PROXY_IP`` / ``TI_API_COLLECTIONS_...``
         env vars, and for flat keys in ``config.yml``;
      2. legacy ``TI_API__<PATH>__<KEY>`` env vars: the sdk cannot split them, so
         they arrive as ``_proxy__ip`` / ``_collections__apt_threat__ttl`` extras;
      3. nested ``config.yml`` blocks (``proxy:``, ``extra_settings:``,
         ``collections: {apt/threat: {...}}``), the documented YAML layout.
    Blank values are dropped so "unset" and "empty" behave alike, which is what
    ``pycti.get_config_variable`` did for the legacy loader.
    """
    flat: dict[str, Any] = {}
    nested: dict[str, Any] = {}
    legacy_names: list[str] = []

    for key, value in data.items():
        if key in ("proxy", "extra_settings", "collections") and isinstance(
            value, dict
        ):
            nested[key] = value
        elif key.startswith("_"):
            # ``TI_API__COLLECTIONS__APT_THREAT__TTL`` -> ``_collections__apt_threat__ttl``
            legacy_names.append(f"TI_API_{key}".upper())
            flat.setdefault(key.lstrip("_").replace("__", "_"), value)
        else:
            flat[key] = value

    for key, value in nested.get("proxy", {}).items():
        flat.setdefault(f"proxy_{key}", value)
    for key, value in nested.get("extra_settings", {}).items():
        flat.setdefault(f"extra_settings_{key}", value)
    for slug, settings in nested.get("collections", {}).items():
        for key, value in (settings or {}).items():
            flat.setdefault(f"collections_{str(slug).replace('/', '_')}_{key}", value)

    if legacy_names:
        warnings.warn(
            "Deprecated double-underscore variable name(s) found "
            f"({', '.join(sorted(legacy_names)[:3])}"
            f"{', ...' if len(legacy_names) > 3 else ''}). "
            "Use the single-underscore form instead, e.g. TI_API_URL, "
            "TI_API_PROXY_IP, TI_API_EXTRA_SETTINGS_<KEY>, "
            "TI_API_COLLECTIONS_<SLUG>_<KEY>.",
            stacklevel=2,
        )

    return {k: v for k, v in flat.items() if not (isinstance(v, str) and v == "")}


class _TIApiCoreConfig(BaseConfigModel):
    """Hand-written part of the ``ti_api`` section: connection settings.

    The 231 flat proxy / extra_settings / per-collection fields are appended by
    ``_flat_ti_api_fields`` when ``TIApiConfig`` is built below.
    """

    url: str = Field(
        default="https://tap.group-ib.com/api/v2/",
        description="Group-IB Threat Intelligence API URL.",
    )
    username: str = Field(description="Group-IB TI portal profile email.")
    token: SecretStr = Field(description="Group-IB TI API token.")

    @model_validator(mode="before")
    @classmethod
    def _normalize_keys(cls, data: Any) -> Any:
        return _normalize_ti_api_keys(data) if isinstance(data, dict) else data


if TYPE_CHECKING:
    TIApiConfig = _TIApiCoreConfig
else:
    # Built dynamically: the field list is data (see ``_COLLECTION_EXTRA_KEYS``),
    # not code. Static checkers only see the hand-written core above.
    TIApiConfig = create_model(
        "TIApiConfig",
        __base__=_TIApiCoreConfig,
        __module__=__name__,
        **_flat_ti_api_fields(),
    )


class _ConnectorFrameworkConfig(BaseExternalImportConnectorConfig):
    """The standard connectors-sdk external-import fields (id/name/scope/
    log_level/duration_period). Declared as a named subclass because the
    connector type EXTERNAL_IMPORT is carried by the base class, and the
    repository's connector linter (VC303) only recognises the type through
    that inheritance.
    """

    # TODO(manager-supported blocker) [needs decision]: a default ``id`` is
    # mandatory for catalog deployment (the sdk declares it required, the
    # manager strips CONNECTOR_ID from the schema). Side effect: the
    # multi-instance layout in ``docker-instances/`` used to force one
    # CONNECTOR_ID per container; with a shared default, an instance that
    # forgets to set it silently reuses this UUID and collides with the others.
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="24a9c578-c911-4a65-9bba-5e7c94b2e742",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Group-IB Connector",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[
            "stix2",
            "report",
            "threat-actor",
            "intrusion-set",
            "malware",
            "attack-pattern",
            "vulnerability",
            "indicator",
            "location",
            "identity",
            "incident",
            "note",
            "relationship",
            "ipv4-addr",
            "ipv6-addr",
            "domain",
            "url",
            "StixFile",
            "email-addr",
            "user-account",
            "payment-card",
            "bank-account",
        ],
    )
    # Was required before; PT4H is the value ``.env.sample`` / the README ship.
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=4),
    )


class ConnectorSettings(BaseConnectorSettings):
    """All connector configuration: ``opencti``, ``connector`` and ``ti_api``.

    Loads from ``OPENCTI_*`` / ``CONNECTOR_*`` / ``TI_API_*`` environment
    variables (or ``config.yml``); raises
    ``connectors_sdk.settings.exceptions.ConfigValidationError`` at
    construction if any required value is missing or malformed. The
    ``ti_api`` section is consumed through ``ConfigConnector`` (below), which
    keeps the historic accessor API for the adapters.
    """

    connector: _ConnectorFrameworkConfig = Field(
        default_factory=_ConnectorFrameworkConfig
    )
    ti_api: TIApiConfig = Field(default_factory=TIApiConfig)


class ConfigConnector:
    _config_validation_warned = False

    def __init__(self):
        self.load = self._load_config()
        self.env_keys = self._load_env_keys()
        self._initialize_configurations()
        self._warn_unknown_collection_keys()
        self.collection_mapping_config = FileHandler().read_json_config(
            self.CONFIG_JSON
        )
        # Validate the effective configuration against the Pydantic schema.
        # Non-fatal by design: the loader above stays the runtime source of
        # truth, so a schema quirk must never block ingestion.
        self.settings = self._build_validated_settings()

    def _warn_unknown_collection_keys(self) -> None:
        """Warn about ``TI_API__COLLECTIONS__<NAME>__*`` keys no collection owns.

        Unmatched keys are silently dropped by the loader, so a collection
        retired in 2.0 or a typo in a slug would otherwise look like a
        collection that is configured but never runs.
        """
        prefix = "ti_api_collections_"
        retired_hits: set[str] = set()
        unknown_keys: list[str] = []
        for attr in vars(self):
            if not attr.startswith(prefix):
                continue
            rest = attr[len(prefix) :]
            if any(rest.startswith(slug + "_") for slug in self.COLLECTION_MAP):
                continue
            retired = next(
                (s for s in self.RETIRED_COLLECTIONS if rest.startswith(s + "_")),
                None,
            )
            if retired:
                retired_hits.add(retired)
            else:
                unknown_keys.append(rest)

        logger = logging.getLogger(__name__)
        for slug in sorted(retired_hits):
            logger.warning(
                "Ignoring configuration for '%s': the collection was dropped in "
                "connector 2.0 and 1.x never actually fetched it. Remove the "
                "TI_API__COLLECTIONS__%s__* keys.",
                self.RETIRED_COLLECTIONS[slug],
                slug.upper(),
            )
        if unknown_keys:
            logger.warning(
                "Ignoring %d collection setting(s) that match no supported "
                "collection: %s. Check the slugs against config.yml.sample / "
                ".env.sample.",
                len(unknown_keys),
                ", ".join(sorted(unknown_keys)),
            )

    @classmethod
    def config_json_schema(cls) -> dict[str, Any]:
        """JSON Schema for the connector configuration (docs tooling)."""
        return GroupIBConnectorSettings.model_json_schema()

    def _assemble_settings_dict(self) -> dict[str, Any]:
        """Fold the flat ``ti_api_collections_<slug>_<key>`` / ``opencti_*`` /
        ``ti_api_extra_settings_*`` attributes into the nested structure the
        Pydantic models expect. Works for both the YAML and env-only paths
        because both resolve to the same flat attribute namespace."""
        env_slugs = sorted(self.COLLECTION_MAP.keys(), key=len, reverse=True)
        opencti: dict[str, Any] = {}
        ti_api: dict[str, Any] = {}
        proxy: dict[str, Any] = {}
        extra: dict[str, Any] = {}
        collections: dict[str, dict[str, Any]] = {}
        for attr, val in vars(self).items():
            if attr.startswith("ti_api_collections_"):
                rest = attr[len("ti_api_collections_") :]
                for slug in env_slugs:
                    if rest.startswith(slug + "_"):
                        collections.setdefault(slug, {})[rest[len(slug) + 1 :]] = val
                        break
            elif attr.startswith("ti_api_extra_settings_"):
                extra[attr[len("ti_api_extra_settings_") :]] = val
            elif attr.startswith("ti_api_proxy_"):
                proxy[attr[len("ti_api_proxy_") :]] = val
            elif attr in ("ti_api_url", "ti_api_username", "ti_api_token"):
                ti_api[attr[len("ti_api_") :]] = val
            elif attr in ("opencti_url", "opencti_token"):
                opencti[attr[len("opencti_") :]] = val
        ti_api["proxy"] = proxy
        ti_api["extra_settings"] = extra
        ti_api["collections"] = collections
        return {"opencti": opencti, "ti_api": ti_api}

    def _build_validated_settings(self) -> "GroupIBConnectorSettings | None":
        try:
            return GroupIBConnectorSettings.model_validate(
                self._assemble_settings_dict()
            )
        except ValidationError as exc:
            if not ConfigConnector._config_validation_warned:
                ConfigConnector._config_validation_warned = True
                logging.getLogger(__name__).warning(
                    "Connector configuration did not validate against the schema; "
                    "continuing with the loaded values. Details: %s",
                    exc,
                )
            return None
        except Exception as exc:  # noqa: BLE001 - validation must never crash startup
            if not ConfigConnector._config_validation_warned:
                ConfigConnector._config_validation_warned = True
                logging.getLogger(__name__).warning(
                    "Unexpected error while validating configuration (ignored): %s",
                    exc,
                )
            return None

    def _load_config(self) -> dict:
        # Probe order must match
        # ``connectors_sdk.settings._settings_loader._get_config_yml_file_path``,
        # or this loader and the sdk's could resolve to different files.
        src_dir = Path(__file__).resolve().parent.parent
        for config_file_path in (src_dir / "config.yml", src_dir.parent / "config.yml"):
            if config_file_path.is_file():
                with open(config_file_path, "r", encoding="utf-8") as file:
                    return yaml.safe_load(file) or {}

        return {}

    def _load_env_keys(self) -> list[str]:
        load_dotenv()
        return list(os.environ.keys())

    def _extract_config_keys(
        self, data: Any, parent_keys: list[Any] | None = None
    ) -> list[list[Any]]:
        if parent_keys is None:
            parent_keys = []

        keys_list = []
        if isinstance(data, dict):
            for key, value in data.items():
                new_keys = parent_keys + [key]
                if isinstance(value, dict):
                    keys_list.extend(self._extract_config_keys(value, new_keys))
                else:
                    keys_list.append(new_keys)
        return keys_list

    def _converting_keys_to_environment_keys(self, key: Any) -> str | None:
        if not key or not isinstance(key, list):
            return None

        key = [str(k).upper().replace("-", "_") for k in key]

        if key[0] in ["OPENCTI", "CONNECTOR"]:
            return "_".join(key)

        if key[0] == "TI_API":
            if len(key) > 1 and key[1] == "COLLECTIONS":
                modified_key = key[2:]
                modified_key = [part.replace("/", "_") for part in modified_key]
                return (
                    f"{key[0]}__{key[1]}__{'__'.join(modified_key)}"
                    if modified_key
                    else f"{key[0]}__{key[1]}"
                )
            return "__".join(key)

        return "_".join(key)

    def _initialize_configurations(self) -> None:
        if self.load:
            for key in self._extract_config_keys(self.load):
                if len(key) > 2 and key[1] == "collections":
                    key[2] = key[2].replace("/", "_")
                env_var = self._converting_keys_to_environment_keys(key)
                attr_name = "__".join(key).lower().replace("__", "_")
                attr_value = get_config_variable(
                    env_var=env_var,
                    yaml_path=key,
                    config=self.load,
                )
                setattr(self, attr_name, attr_value)
        else:
            for env_key in self.env_keys:
                attr_name = env_key.lower().replace("__", "_")
                attr_value = get_config_variable(
                    env_var=env_key,
                    yaml_path=None,
                    config=None,
                )
                setattr(self, attr_name, attr_value)

    @staticmethod
    def _to_bool(value: Any, default: bool = False) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "1", "yes")

    @staticmethod
    def _to_int(value: Any, default: int = 0) -> int:
        if value is None:
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def get_collection_settings(self, collection: str, setting_name: str) -> Any:
        collection_attr_name = f"ti_api_collections_{collection}_{setting_name}"
        return getattr(self, collection_attr_name, None)

    def get_extra_settings_by_name(self, setting_name: str) -> Any:
        extra_setting_attr_name = f"ti_api_extra_settings_{setting_name}"
        return getattr(self, extra_setting_attr_name, None)

    def get_setting(self, collection: str, key: str, default: Any = None) -> Any:
        coll_key = collection.replace("/", "_") if collection else ""
        val = self.get_collection_settings(coll_key, key)
        if val is not None:
            return val
        val = self.get_extra_settings_by_name(key)
        if val is not None:
            return val
        return default

    def get_setting_bool(self, collection: str, key: str, default: bool = True) -> bool:
        return self._to_bool(self.get_setting(collection, key), default)

    def get_extra_settings_bool(self, name: str, default: bool = False) -> bool:
        return self._to_bool(self.get_extra_settings_by_name(name), default)

    def get_file_logging_config(self) -> FileLoggingConfig:
        return FileLoggingConfig(
            enabled=self._to_bool(
                self.get_extra_settings_by_name("enable_file_logging"),
            ),
            directory=(
                self.get_extra_settings_by_name("log_file_dir") or _DEFAULT_LOG_DIR
            ),
            max_bytes=self._to_int(
                self.get_extra_settings_by_name("log_file_max_bytes"),
                _DEFAULT_LOG_MAX_BYTES,
            ),
            backup_count=self._to_int(
                self.get_extra_settings_by_name("log_file_backup_count"),
                _DEFAULT_LOG_BACKUP_COUNT,
            ),
        )

    PRODUCT_TYPE = "SCRIPT"
    PRODUCT_NAME = "OpenCTI"
    PRODUCT_VERSION = "unknown"
    INTEGRATION = "GroupIB_TI_OpenCTI_Connector"
    INTEGRATION_VERSION = "2.0.0"

    AUTHOR = "Group-IB"

    # settings.py lives in src/connector/; docs/ and _data/ stay at the src/
    # root, so resolve one level up for the connector root directory.
    ROOT_DIR = str(Path(__file__).resolve().parent.parent)
    DOCS_DIR = os.path.join(ROOT_DIR, "docs")

    _config_name_json = "mapping.json"

    CONFIG_JSON = os.path.join(DOCS_DIR, "configs", _config_name_json)

    MITRE_CACHE_FILENAME = "mitre_cache.json"
    MITRE_CACHE_FOLDER = os.path.join(DOCS_DIR, "cache")

    # TLP:AMBER+STRICT is an OpenCTI-specific marking, not part of the STIX 2.1
    # TLP vocabulary (stix2 rejects definition_type="TLP" for anything other
    # than white/green/amber/red). We therefore emit it the way OpenCTI itself
    # does: a statement-type MarkingDefinition with the platform's canonical
    # fixed id and x_opencti_* hints so the platform resolves it to the real
    # TLP:AMBER+STRICT marking instead of creating a duplicate.
    try:
        TLP_AMBER_STRICT = MarkingDefinition(
            id="marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
            definition_type="statement",
            definition={"statement": "custom"},
            allow_custom=True,
            custom_properties={
                "x_opencti_definition_type": "TLP",
                "x_opencti_definition": "TLP:AMBER+STRICT",
            },
        )
    except Exception as _exc:  # noqa: BLE001
        logging.getLogger(__name__).warning(
            "TLP_AMBER_STRICT marking unavailable, falling back to TLP_AMBER (%s)",
            _exc,
        )
        TLP_AMBER_STRICT = TLP_AMBER

    STIX_TLP_MAP = {
        "white": TLP_WHITE,
        "green": TLP_GREEN,
        "amber": TLP_AMBER,
        "amber+strict": TLP_AMBER_STRICT,
        "red": TLP_RED,
    }

    DEFAULT_TLP_BY_SDO = {
        "malware": "amber+strict",
        "threat-actor": "amber+strict",
        "intrusion-set": "amber+strict",
        "incident": "amber+strict",
    }
    STIX_MAIN_OBSERVABLE_TYPE_MAP = {
        "domain": "Domain-Name",
        "domain-name": "Domain-Name",
        "file": "StixFile",
        "ipv4": "IPv4-Addr",
        "ipv4-addr": "IPv4-Addr",
        "ipv6": "IPv6-Addr",
        "ipv6-addr": "IPv6-Addr",
        "url": "Url",
        "yara": "StixFile",
        "suricata": "Network-Traffic",
        "user-account": "User-Account",
    }
    STIX_MALWARE_TYPE_MAP = {*MALWARE_TYPE}
    COUNTRIES = _ISO3166_COUNTRIES
    STIX_REPORT_TYPE_MAP = {"threat_report": "Threat-Report"}
    COLLECTION_MAP = {
        "apt_threat": "apt/threat",
        "apt_threat_actor": "apt/threat_actor",
        "attacks_ddos": "attacks/ddos",
        "attacks_deface": "attacks/deface",
        "attacks_phishing_group": "attacks/phishing_group",
        "attacks_phishing_kit": "attacks/phishing_kit",
        "compromised_access": "compromised/access",
        "compromised_account_group": "compromised/account_group",
        "compromised_bank_card_group": "compromised/bank_card_group",
        "compromised_discord": "compromised/discord",
        "compromised_masked_card": "compromised/masked_card",
        "compromised_messenger": "compromised/messenger",
        "compromised_spd": "compromised/spd",
        "darkweb_forums": "darkweb/forums",
        "hi_open_threats": "hi/open_threats",
        "hi_threat": "hi/threat",
        "hi_threat_actor": "hi/threat_actor",
        "ioc_primary": "ioc/primary",
        "malware_cnc": "malware/cnc",
        "malware_config": "malware/config",
        "malware_malware": "malware/malware",
        "malware_signature": "malware/signature",
        "malware_yara": "malware/yara",
        "osi_git_repository": "osi/git_repository",
        "osi_public_leak": "osi/public_leak",
        "osi_vulnerability": "osi/vulnerability",
        "suspicious_ip_open_proxy": "suspicious_ip/open_proxy",
        "suspicious_ip_scanner": "suspicious_ip/scanner",
        "suspicious_ip_socks_proxy": "suspicious_ip/socks_proxy",
        "suspicious_ip_tor_node": "suspicious_ip/tor_node",
        "suspicious_ip_vpn": "suspicious_ip/vpn",
    }

    # Slugs no longer supported, kept only so leftover config keys for them
    # get a targeted warning instead of the generic one.
    RETIRED_COLLECTIONS = {
        "ioc_common": "ioc/common",
        "compromised_imei": "compromised/imei",
        "compromised_mule": "compromised/mule",
    }
