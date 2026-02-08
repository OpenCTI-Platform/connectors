import json
import os
from pathlib import Path
from typing import Any, List, TypedDict

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class CollectionPolicy(TypedDict, total=False):
    action: str
    educate_url: str
    expire_time: int
    max_indicators: int
    rbac_group_names: List[str]
    recommended_actions: str


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file
        self.load = self._load_config()

        self.helper = OpenCTIConnectorHelper(self.load)

        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI configurations

        # Connector extra parameters
        self.tenant_id = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_TENANT_ID",
            ["microsoft_defender_intel_synchronizer", "tenant_id"],
            self.load,
        )
        self.client_id = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_CLIENT_ID",
            ["microsoft_defender_intel_synchronizer", "client_id"],
            self.load,
        )
        self.client_secret = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_CLIENT_SECRET",
            ["microsoft_defender_intel_synchronizer", "client_secret"],
            self.load,
        )
        self.login_url = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_LOGIN_URL",
            ["microsoft_defender_intel_synchronizer", "login_url"],
            self.load,
            default="https://login.microsoftonline.com",
        )
        # Max indicators (int) the connector will attempt to manage in Defender.
        # Must not exceed Defender's hard limit (15,000).
        original_max_indicators = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_MAX_INDICATORS",
            ["microsoft_defender_intel_synchronizer", "max_indicators"],
            self.load,
            isNumber=True,
            default=15000,
        )
        # Enforce hard limits to prevent misconfiguration from causing API errors or performance issues.
        self.max_indicators = max(min(original_max_indicators, 15000), 1)
        if original_max_indicators != self.max_indicators:
            self.helper.log_warning(
                "Configured max_indicators is out of bounds; clamping to allowed range [1, 15000].",
                {
                    "max_indicators": original_max_indicators,
                    "effective_max_indicators": self.max_indicators,
                },
            )
        self.base_url = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_BASE_URL",
            ["microsoft_defender_intel_synchronizer", "base_url"],
            self.load,
            default="https://api.securitycenter.microsoft.com",
        )
        self.resource_path = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_RESOURCE_PATH",
            ["microsoft_defender_intel_synchronizer", "resource_path"],
            self.load,
            default="/api/indicators",
        )
        self.expire_time = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_EXPIRE_TIME",
            ["microsoft_defender_intel_synchronizer", "expire_time"],
            self.load,
            isNumber=True,
            default=30,
        )
        self.action = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_ACTION",
            ["microsoft_defender_intel_synchronizer", "action"],
            self.load,
            default="Audit",
        )
        self.passive_only = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_PASSIVE_ONLY",
            ["microsoft_defender_intel_synchronizer", "passive_only"],
            self.load,
            default=False,
        )
        raw_collections = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_TAXII_COLLECTIONS",
            ["microsoft_defender_intel_synchronizer", "taxii_collections"],
            self.load,
        )
        taxii_collections, taxii_overrides = self._parse_taxii_collections(
            raw_collections
        )
        self.taxii_collections = taxii_collections
        self.taxii_overrides = taxii_overrides
        self.interval = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_INTERVAL",
            ["microsoft_defender_intel_synchronizer", "interval"],
            self.load,
            isNumber=True,
            default=300,
        )
        # Update-only-owned toggle (default true)
        self.update_only_owned = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_UPDATE_ONLY_OWNED",
            ["microsoft_defender_intel_synchronizer", "update_only_owned"],
            self.load,
            default=True,
        )
        self.recommended_actions = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_RECOMMENDED_ACTIONS",
            ["microsoft_defender_intel_synchronizer", "recommended_actions"],
            self.load,
            default="",
        )
        rbac_group_names_raw = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_RBAC_GROUP_NAMES",
            ["microsoft_defender_intel_synchronizer", "rbac_group_names"],
            self.load,
            default="[]",
        )
        if isinstance(rbac_group_names_raw, str):
            try:
                self.rbac_group_names = json.loads(rbac_group_names_raw)
                if not isinstance(self.rbac_group_names, list):
                    raise ValueError
            except (json.JSONDecodeError, ValueError) as exc:
                self.helper.connector_logger.error(
                    "Error: MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_RBAC_GROUP_NAMES is not a valid JSON array."
                    " Connector will terminate."
                )
                raise RuntimeError(
                    "Invalid configuration: MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_RBAC_GROUP_NAMES must be a JSON array."
                ) from exc
        elif isinstance(rbac_group_names_raw, list):
            self.rbac_group_names = rbac_group_names_raw
        else:
            self.rbac_group_names = []
        self.educate_url = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_EDUCATE_URL",
            ["microsoft_defender_intel_synchronizer", "educate_url"],
            self.load,
            default="",
        )

    @staticmethod
    def _parse_taxii_collections(
        raw: Any,
    ) -> tuple[list[str], dict[str, CollectionPolicy]]:
        """
        Accepts:
          - CSV string: "id1,id2"
          - JSON string list: '["id1","id2"]'
          - Python list: ["id1","id2"]
          - JSON/Python map: {"id1": {...}, "id2": null, "id3": {...}}
          - Shorthand null/true/false/"" are treated as "present but use defaults"
        Returns: (ordered_list_of_collection_ids, overrides_map)
        """
        KNOWN = {
            "action",
            "educate_url",
            "expire_time",
            "max_indicators",
            "rbac_group_names",
            "recommended_actions",
        }

        def _normalize_policy(v: Any) -> CollectionPolicy:
            """
            Normalize a per-collection override value into a CollectionPolicy.

            Shorthand values (None/True/False/"") mean "use defaults" -> {}.
            Non-dict values are treated as {}.

            Optional improvements:
              - rbac_group_names may be provided as a single string and will be wrapped into a list
              - policy normalization is centralized in this helper to avoid duplication
            """
            if v is None or v is True or v is False or v == "":
                return {}

            if not isinstance(v, dict):
                return {}

            pol: CollectionPolicy = {}

            for fk in KNOWN:
                if fk in v and v[fk] is not None:
                    pol[fk] = v[fk]

            if "expire_time" in pol:
                pol["expire_time"] = int(pol["expire_time"])

            if "max_indicators" in pol:
                value = int(pol["max_indicators"])
                value = max(min(value, 15000), 1)
                pol["max_indicators"] = value

            if "rbac_group_names" in pol and pol["rbac_group_names"] is not None:
                r = pol["rbac_group_names"]
                if isinstance(r, str):
                    pol["rbac_group_names"] = [r]
                else:
                    try:
                        pol["rbac_group_names"] = [str(x) for x in r]
                    except TypeError:
                        # Not iterable (unexpected), fall back to a single string value
                        pol["rbac_group_names"] = [str(r)]

            return pol

        # 1) Normalize Python objects (dict/list) passed directly from YAML loader
        if isinstance(raw, dict):
            order: list[str] = []
            overrides: dict[str, CollectionPolicy] = {}
            for k, v in raw.items():
                key = str(k)
                order.append(key)
                overrides[key] = _normalize_policy(v)
            return order, overrides

        if isinstance(raw, list):
            # raw is already the list form
            return [str(x) for x in raw], {}

        # 2) Handle string inputs (CSV or JSON)
        s = raw or ""
        if not isinstance(s, str):
            # Unexpected type - be defensive: try stringifying, but prefer CSV fallback
            try:
                s = json.dumps(s)
            except Exception:
                s = str(s)

        s = s.strip()
        if not s:
            return [], {}

        # If it starts with { or [ treat as JSON
        if s[0] in "{[":
            try:
                data = json.loads(s)
            except Exception:
                # Malformed JSON; fall back to CSV parsing to be tolerant
                ids = [x.strip() for x in s.split(",") if x.strip()]
                return ids, {}

            if isinstance(data, dict):
                order: list[str] = []
                overrides: dict[str, CollectionPolicy] = {}
                for k, v in data.items():
                    key = str(k)
                    order.append(key)
                    overrides[key] = _normalize_policy(v)
                return order, overrides

            if isinstance(data, list):
                return [str(x) for x in data], {}

        # CSV fallback
        ids = [x.strip() for x in s.split(",") if x.strip()]
        return ids, {}

    def used_rbac_groups(self) -> list[str]:
        """
        Compute the full set of RBAC group names used, both global and per-collection
        :return: Sorted list of unique RBAC group names
        """
        out = self.rbac_group_names.copy()
        for pol in self.taxii_overrides.values():
            for name in pol.get("rbac_group_names", []) or []:
                if name not in out:
                    out.append(name)
        return sorted(out)
