"""Provide Common classes and functions for the Tenable Security Center Interface using the Rest API >= 5.13."""

# isort: skip_file
# isort is removing the type ignore untyped import comment conflicting with mypy

import datetime
import re

from typing import Any, Callable, Optional

from pydantic import BaseModel, ConfigDict, Field, AwareDatetime


ASSETS_CHUNK_SIZE = 10
FINDINGS_CHUNK_SIZE = 100


FINDING_SEVERITIES_MAP = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

ASSET_FIELDS = [
    "id",
    "uuid",
    "tenableUUID",
    "name",
    "ipAddress",
    "os",
    "firstSeen",
    "lastSeen",
    "macAddress",
    "source",
    "repID",
    "netBios",
    "netBiosWorkgroup",
    "createdTime",
    "modifiedTime",
]

ASSETS_FILTERS = [
    "systemType",
    "ip",
    "repositoryAll",
    "assetCriticalityRating",
    "assetExposureScore",
    "sourceType",
    "hostid",
]


class _BaseModelWithoutExtra(BaseModel):
    """Base model which does not accept other fields than the ones defined."""

    model_config = ConfigDict(
        extra="forbid",
    )


_camel_case_pattern = re.compile(r"([a-z])([A-Z])")


class FlattenRawResponseInSnakeCase:
    """Flatten a raw response from the Tenable Security Center API and convert camel case key to snake case.

    Examples:
        >>> raw_response = {
        ...     "fooBar": "Foo bar",
        ...     "test": {"toTo": 1, "tiTi": 2}
        ...     }
        >>> flatten = FlattenRawResponseInSnakeCase(raw_response)
        >>> flatten.values["foo_bar"]
        "Foo bar"
        >>> flatten.values["test.to_to"]
        1

    """

    def __init__(self, raw_response: dict[str, Any], sep: str = "."):
        """Initialize the FlattenRawResponseInSnakeCase class."""
        self.__raw_response = raw_response.copy()
        self.__sep = sep
        self.values = self.__process()

    @staticmethod
    def __cammel_to_snake_case(v: str) -> str:
        return _camel_case_pattern.sub(r"\1_\2", v).lower()

    @staticmethod
    def __flatten_dict(
        d: dict[str, Any],
        sep: str = ".",
        _parent_key: str = "",
    ) -> dict[str, Any]:
        """Flattens a dictionary of nested dictionnaries and convert camel case key to snake case.

        Args:
            d(dict[str, Any]): The dictionary to flatten.
            sep(str): The separator to use between keys.
            _parent_key(str): The parent key to use (for recursion only, it should not be passed).

        Returns:
            dict[str, Any]: The flatten dictionary.

        Exmaples:
            {a:{b:{c:1}}} => {"a.b.c": 1}

        """
        items: list[tuple[str, Any]] = []
        _parent_key_snake = (
            FlattenRawResponseInSnakeCase.__cammel_to_snake_case(str(_parent_key))
            if _parent_key
            else ""
        )
        for k, v in d.items():
            k_snake = FlattenRawResponseInSnakeCase.__cammel_to_snake_case(str(k))
            new_key = f"{_parent_key_snake}{sep}{k_snake}" if _parent_key else k_snake
            if isinstance(v, dict):  # If the value is a dictionary, recurse
                items.extend(
                    FlattenRawResponseInSnakeCase.__flatten_dict(
                        d=v, _parent_key=new_key, sep=sep
                    ).items()
                )
            else:
                items.append((new_key, v))
        return dict(items)

    def __process(self) -> dict[str, Any]:
        return self.__flatten_dict(self.__raw_response, sep=self.__sep)

    def apply(
        self,
        func: Callable[..., Any],
        key: str,
        optional: bool = False,
        other_excepted_values: Optional[list[str]] = None,
    ) -> Any:
        """Apply a function to a given field."""
        val = self.values.get(key)
        _other_excepted_values = other_excepted_values or []
        if optional and (not (val) or val in _other_excepted_values):
            return None
        return func(val)

    def int_field(self, key: str, optional: bool = False) -> Optional[int]:
        """Apply a int casting to a given field.

        Args:
            key(str): The key to select the field.
            optional(bool): If the field is optional.

        Returns:
            Optional[int]: The value as an integer.

        """
        value = self.apply(int, key, optional=optional)
        return value if value is not None else None

    def bool_int_field(self, key: str, optional: bool = False) -> Optional[bool]:
        """Apply a bool casting to a given field."""
        value = self.apply(lambda x: bool(int(x)), key, optional=optional)
        return value if value is not None else None

    def float_field(self, key: str, optional: bool = False) -> Optional[float]:
        """Apply a float casting to a given field."""
        value = self.apply(float, key, optional=optional)
        return value if value is not None else None

    def timestamp_field(self, key: str, optional: bool) -> Optional[datetime.datetime]:
        """Apply a timestamp casting to a given field."""
        dt: Optional[datetime.datetime] = self.apply(
            lambda x: datetime.datetime.fromtimestamp(int(x)),
            key,
            optional=optional,
            other_excepted_values=["-1"],
        )
        if dt is not None:
            # make utc time aware if no timezone
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt

    def str_list_field(
        self, key: str, optional: bool, sep: str = ","
    ) -> Optional[list[Any]]:
        """Apply a split to a given field."""
        str_list = self.apply(lambda x: x.split(sep), key, optional=optional)
        return list(str_list) if str_list else None


class CVEPydanticModel(_BaseModelWithoutExtra):
    """Pydantic model for a CVE from the Tenable Security Center API."""

    name: str = Field(...)
    description: str = Field(...)
    publication_datetime: AwareDatetime = Field(...)
    last_modified_datetime: AwareDatetime = Field(...)
    cpes: Optional[list[str]] = Field(None)
    cvss_v3_score: Optional[float] = Field(None)
    cvss_v3_vector: Optional[str] = Field(None)
    epss_score: Optional[float] = Field(None)
    epss_percentile: Optional[float] = Field(None)


class FindingPydanticModel(_BaseModelWithoutExtra):
    """Pydantic model for a finding from the Tenable Security Center API.

    Notes :
        Used to validate API results with understandable Validation exception.
    """

    plugin_name: str = Field(...)
    cve: Optional[list[str]] = Field(None)
    cpe: Optional[list[str]] = Field(None)
    plugin_id: str = Field(...)
    has_been_mitigated: bool = Field(...)
    accept_risk: bool = Field(...)
    recast_risk: bool = Field(...)
    ip: str = Field(...)
    uuid: Optional[str] = Field(None)
    port: int = Field(...)
    protocol: str = Field(...)
    first_seen: AwareDatetime = Field(...)
    last_seen: AwareDatetime = Field(...)
    exploit_available: bool = Field(...)
    exploit_ease: Optional[str] = Field(None)
    exploit_frameworks: Optional[list[str]] = Field(None)
    synopsis: Optional[str] = Field(None)
    description: Optional[str] = Field(None)
    solution: Optional[str] = Field(None)
    see_also: Optional[list[str]] = Field(None)
    risk_factor: Optional[str] = Field(None)
    stig_severity: Optional[str] = Field(None)
    severity_name: str = Field(...)
    vpr_score: Optional[float] = Field(None)
    vpr_context: Optional[list[str]] = Field(None)
    base_score: Optional[float] = Field(None)
    temporal_score: Optional[float] = Field(None)
    cvss_vector: Optional[str] = Field(None)
    cvss_v3_base_score: Optional[float] = Field(None)
    cvss_v3_temporal_score: Optional[float] = Field(None)
    cvss_v3_vector: Optional[str] = Field(None)
    vuln_pub_date: Optional[AwareDatetime] = Field(None)
    patch_pub_date: Optional[AwareDatetime] = Field(None)
    plugin_pub_date: Optional[AwareDatetime] = Field(None)
    plugin_mod_date: Optional[AwareDatetime] = Field(None)
    check_type: Optional[str] = Field(None)
    version: Optional[str] = Field(None)
    bid: Optional[list[str]] = Field(None)
    xref: Optional[list[str]] = Field(None)
    seol_date: AwareDatetime = Field(...)
    plugin_text: Optional[str] = Field(None)
    dns_name: Optional[str] = Field(None)
    mac_address: Optional[str] = Field(None)
    netbios_name: Optional[str] = Field(None)
    operating_system: Optional[str] = Field(None)
    recast_risk_rule_comment: Optional[list[str]] = Field(None)
    accept_risk_rule_comment: Optional[list[str]] = Field(None)
    host_uniqueness: list[str] = Field(...)
    host_uuid: Optional[str] = Field(None)
    acr_score: Optional[float] = Field(None)
    asset_exposure_score: float = Field(...)
    vuln_uniqueness: list[str] = Field(...)
    vuln_uuid: Optional[str] = Field(None)
    uniqueness: list[str] = Field(...)


class AssetPydanticModel(_BaseModelWithoutExtra):
    """Pydantic model for an asset from the Tenable Security Center API."""

    id: str = Field(...)
    uuid: str = Field(...)
    tenable_uuid: Optional[str] = Field(None)
    name: str = Field(...)
    operating_systems: Optional[list[str]] = Field(None)
    first_seen: datetime.datetime = Field(...)
    last_seen: datetime.datetime = Field(...)
    mac_address: Optional[str] = Field(None)
    created_time: datetime.datetime = Field(...)
    modified_time: datetime.datetime = Field(...)
    ip_address: str = Field(...)
    repository_id: str = Field(...)
