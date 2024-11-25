"""Provide the Implementation of the Tenable Security Center Interface using the Rest API >= 5.13."""

# isort: skip_file
# isort is removing the type ignore untyped import comment conflicting with mypy

import datetime
import re
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache, partial
from threading import Lock
from typing import TYPE_CHECKING, Any, Callable, Iterable, Optional
from urllib.parse import urlencode

from pycti import (  # type: ignore[import-untyped]
    __version__ as pycti_version,  # pycti does not provide stubs
)

from pydantic import BaseModel, ConfigDict, Field, AwareDatetime, ValidationError
from requests import HTTPError
from semver import VersionInfo
from tenable.errors import (  # type: ignore[import-untyped]
    APIError,  #  tenable does not provide stubs
)
from tenable.sc import (  # type: ignore[import-untyped]
    TenableSC,  # tenable does not provide stubs
)

from tenable_security_center.ports.asset import (
    AssetPort,
    AssetsChunkPort,
    AssetsPort,
    FindingPort,
    CVEPort,
)

from tenable_security_center.ports.errors import (
    AssetRetrievalError,
    CVERetrievalError,
    FindingRetrievalError,
)


if TYPE_CHECKING:
    from requests import Response
    from tenable_security_center.utils import AppLogger


ASSETS_CHUNK_SIZE = 10
FINDINGS_CHUNK_SIZE = 100

FINDING_FILTERS = (
    "acceptedRisk",
    "acceptRiskStatus",
    "assetID",
    "auditFileID",
    "benchmarkName",
    "cceID",
    "cpe",
    "cveID",
    "baseCVSSScore",
    "cvssVector",
    "cvssV3BaseScore",
    "cvssV3Vector",
    "dataFormat",
    "daysMitigated",
    "daysToMitigated",
    "dnsName",
    "exploitAvailable",
    "exploitFrameworks",
    "familyID",
    "firstSeen",
    "iavmID",
    "ip",
    "lastMitigated",
    "lastSeen",
    "mitigatedStatus",
    "msbulletinID",
    "operatingSystem",
    "outputAssets",
    "patchPublished",
    "pluginModified",
    "pluginPublished",
    "pluginID",
    "pluginName",
    "pluginText",
    "pluginType",
    "policyID",
    "port",
    "protocol",
    "recastRisk",
    "recastRiskStatus",
    "repositoryIDs",
    "responsibleUserIDs",
    "vulnRoutedUserIDs",
    "vulnRoutingRuleID",
    "severity",
    "solutionID",
    "stigSeverity",
    "tcpport",
    "udpport",
    "uuid",
    "vulnPublished",
    "seolDate",
    "wasMitigated",
    "xref",
    "vprScore",
    "assetCriticalityRating",
    "hostUUID",
    "vulnUUID",
    "assetExposureScore",
    "aesSeverity",
    "netbiosName",
    "wasInputName",
    "wasInputType",
    "wasURL",
    "wasHttpMethod",
    "wasVuln",
)  # Undocumented at that time in Tenable doc. This has been extractred from API response error message.

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


class _BaseModelWithoutExtra(BaseModel):
    """Base model which does not accept other fields than the ones defined."""

    model_config = ConfigDict(
        extra="forbid",
    )


_camel_case_pattern = re.compile(r"([a-z])([A-Z])")


class _FlattenRawResponseInSnakeCase:
    """Flatten a raw response from the Tenable Security Center API and convert camel case key to snake case.

    Examples:
        >>> raw_response = {
        ...     "fooBar": "Foo bar",
        ...     "test": {"toTo": 1, "tiTi": 2}
        ...     }
        >>> flatten = _FlattenRawResponseInSnakeCase(raw_response)
        >>> flatten.values["foo_bar"]
        "Foo bar"
        >>> flatten.values["test.to_to"]
        1

    """

    def __init__(self, raw_response: dict[str, Any], sep: str = "."):
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

        """
        items: list[tuple[str, Any]] = []
        _parent_key_snake = (
            _FlattenRawResponseInSnakeCase.__cammel_to_snake_case(str(_parent_key))
            if _parent_key
            else ""
        )
        for k, v in d.items():
            k_snake = _FlattenRawResponseInSnakeCase.__cammel_to_snake_case(str(k))
            new_key = f"{_parent_key_snake}{sep}{k_snake}" if _parent_key else k_snake
            if isinstance(v, dict):  # If the value is a dictionary, recurse
                items.extend(
                    _FlattenRawResponseInSnakeCase.__flatten_dict(
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


class _CVEAPI(CVEPort):
    """Represent a CVE from the Tenable Security Center API."""

    def __init__(self, **data: dict[str, Any]):
        try:
            self._pydantic_model = CVEPydanticModel.model_validate(data)
        except ValidationError as e:
            raise CVERetrievalError(
                f"Error while validating the CVE data: {data}"
            ) from e

    @property
    def name(self) -> str:
        return self._pydantic_model.name

    @property
    def description(self) -> str:
        return self._pydantic_model.description

    @property
    def publication_datetime(self) -> datetime.datetime:
        return self._pydantic_model.publication_datetime

    @property
    def last_modified_datetime(self) -> datetime.datetime:
        return self._pydantic_model.last_modified_datetime

    @property
    def cpes(self) -> Optional[list[str]]:
        return self._pydantic_model.cpes

    @property
    def cvss_v3_score(self) -> Optional[float]:
        return self._pydantic_model.cvss_v3_score

    @property
    def cvss_v3_vector(self) -> Optional[str]:
        return self._pydantic_model.cvss_v3_vector

    @property
    def epss_score(self) -> Optional[float]:
        return self._pydantic_model.epss_score

    @property
    def epss_percentile(self) -> Optional[float]:
        return self._pydantic_model.epss_percentile

    @classmethod
    def from_raw_response(cls, raw_response: dict[str, Any]) -> "_CVEAPI":
        """Create a CVE from a raw response."""
        # Note: The values might be None, specific validations will be performed by pydantic.
        name = raw_response.get("primary_vuln_id")
        description = raw_response.get("descriptions", [{}])[0].get("description_text")
        publication_datetime = raw_response.get("descriptions", [{}])[0].get(
            "publication_date"
        )
        last_modified_datetime = raw_response.get("descriptions", [{}])[-1].get(
            "publication_date"
        )
        cpes = [
            str(uri)  # explicit cast for mypy linter
            for uri in raw_response.get("cpe_metrics", [])
            if str(uri).startswith("cpe:") or str(uri).startswith("p-cpe:")
        ]
        cvss_v3_score = raw_response.get("cvss_metrics", [{}])[0].get(
            "cvss3_base_score"
        )
        cvss_v3_vector = raw_response.get("cvss_metrics", [{}])[0].get(
            "cvss3_base_vector"
        )
        epss_score = raw_response.get("epss_metrics", [{}])[0].get("epss")
        epss_percentile = raw_response.get("epss_metrics", [{}])[0].get("percentile")
        return cls(
            name=name,  # type: ignore[arg-type]
            description=description,
            publication_datetime=publication_datetime,
            last_modified_datetime=last_modified_datetime,
            cpes=cpes,  # type: ignore[arg-type]
            cvss_v3_score=cvss_v3_score,
            cvss_v3_vector=cvss_v3_vector,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
        )


class _CVEsAPI:  # pylint: disable=too-few-public-methods

    def __init__(self, tsc_client: TenableSC, logger: "AppLogger", num_threads: int):
        self.logger = logger
        self.client = tsc_client
        self.num_threads = num_threads
        self.lock = Lock()

    def _build_url(self, cve_id: str) -> str:
        return f"cve/{cve_id}"

    @lru_cache(maxsize=65536)  # noqa: B019 # response as dict ~500Bytes => ~32MB
    def __fetch(self, cve_id: str) -> dict[str, Any]:
        """Fetch a CVE from the API."""
        try:
            self.logger.debug(f"Fetching CVE {cve_id} from Tenable Security Center.")
            cve_response: dict[str, Any] = self.client.get(
                f"cve/{cve_id}", stream=True
            ).json()
            return cve_response
        except APIError as e:
            self.logger.error(
                f"Error while fetching data from Tenable Security Center: {e}"
            )
            raise CVERetrievalError(
                "Error while fetching data from Tenable Security Center."
            ) from e

    def _fetch(self, cve_id: str) -> dict[str, Any]:
        """Fetch a CVE from the API (thread safe)."""
        with self.lock:
            self.logger.debug(f"Fetching CVE {cve_id}.")
            return self.__fetch(cve_id)

    def _fetch_data_chunk(self, cve_ids: list[str]) -> Iterable[dict[str, Any]]:
        """Fetch a chunk of data from the API."""
        self.logger.debug(f"CVE Cache stats {self.__fetch.cache_info()}")
        with ThreadPoolExecutor() as executor:
            return list(executor.map(self._fetch, cve_ids))

    def fetch_cves(self, cve_ids: list[str]) -> Iterable[_CVEAPI]:
        """Fetch and process the CVEs."""
        for raw_cve in self._fetch_data_chunk(cve_ids):
            yield _CVEAPI.from_raw_response(raw_cve)


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


class _FindingAPI(FindingPort):
    """Represents a finding from the Tenable Security Center API."""

    def __init__(self, logger: "AppLogger", cves_api: _CVEsAPI, **data: dict[str, Any]):
        self._pydantic_model = FindingPydanticModel.model_validate(
            _FindingAPI.parse_response(data)
        )
        self.logger = logger
        self._cves_api = cves_api
        self.__cves = None

    @property
    def plugin_name(self) -> str:
        return self._pydantic_model.plugin_name

    @property
    def cves(self) -> Optional[list[CVEPort]]:
        if self.__cves is None:
            cve_ids = self._pydantic_model.cve
            if cve_ids:
                self.__cves = list(  # type: ignore[assignment]
                    self._cves_api.fetch_cves(cve_ids)
                )
        else:
            self.logger.debug(
                f"CVEs already fetched for this finding {self.plugin_name}."
            )
        return self.__cves

    @property
    def cpes(self) -> Optional[list[str]]:
        return self._pydantic_model.cpe

    @property
    def plugin_id(self) -> str:
        return self._pydantic_model.plugin_id

    @property
    def has_been_mitigated(self) -> bool:
        return self._pydantic_model.has_been_mitigated

    @property
    def accept_risk(self) -> bool:
        return self._pydantic_model.accept_risk

    @property
    def recast_risk(self) -> bool:
        return self._pydantic_model.recast_risk

    @property
    def ip(self) -> str:
        return self._pydantic_model.ip

    @property
    def uuid(self) -> Optional[str]:
        return self._pydantic_model.uuid

    @property
    def port(self) -> int:
        return self._pydantic_model.port

    @property
    def protocol(self) -> str:
        return self._pydantic_model.protocol

    @property
    def first_seen(self) -> datetime.datetime:
        return self._pydantic_model.first_seen

    @property
    def last_seen(self) -> datetime.datetime:
        return self._pydantic_model.last_seen

    @property
    def exploit_available(self) -> bool:
        return self._pydantic_model.exploit_available

    @property
    def exploit_ease(self) -> Optional[str]:
        return self._pydantic_model.exploit_ease

    @property
    def exploit_frameworks(self) -> Optional[list[str]]:
        return self._pydantic_model.exploit_frameworks

    @property
    def synopsis(self) -> Optional[str]:
        return self._pydantic_model.synopsis

    @property
    def description(self) -> Optional[str]:
        return self._pydantic_model.description

    @property
    def solution(self) -> Optional[str]:
        return self._pydantic_model.solution

    @property
    def see_also(self) -> Optional[list[str]]:
        return self._pydantic_model.see_also

    @property
    def risk_factor(self) -> Optional[str]:
        return self._pydantic_model.risk_factor

    @property
    def stig_severity(self) -> Optional[str]:
        return self._pydantic_model.stig_severity

    @property
    def tenable_severity(self) -> str:
        return self._pydantic_model.severity_name

    @property
    def vpr_score(self) -> Optional[float]:
        return self._pydantic_model.vpr_score

    @property
    def vpr_context(self) -> Optional[list[str]]:
        return self._pydantic_model.vpr_context

    @property
    def base_score(self) -> Optional[float]:
        return self._pydantic_model.base_score

    @property
    def temporal_score(self) -> Optional[float]:
        return self._pydantic_model.temporal_score

    @property
    def cvss_vector(self) -> Optional[str]:
        return self._pydantic_model.cvss_vector

    @property
    def cvss_v3_base_score(self) -> Optional[float]:
        return self._pydantic_model.cvss_v3_base_score

    @property
    def cvss_v3_temporal_score(self) -> Optional[float]:
        return self._pydantic_model.cvss_v3_temporal_score

    @property
    def cvss_v3_vector(self) -> Optional[str]:
        return self._pydantic_model.cvss_v3_vector

    @property
    def vuln_pub_date(self) -> Optional[datetime.datetime]:
        return self._pydantic_model.vuln_pub_date

    @property
    def patch_pub_date(self) -> Optional[datetime.datetime]:
        return self._pydantic_model.patch_pub_date

    @property
    def plugin_pub_date(self) -> Optional[datetime.datetime]:
        return self._pydantic_model.plugin_pub_date

    @property
    def plugin_mod_date(self) -> Optional[datetime.datetime]:
        return self._pydantic_model.plugin_mod_date

    @property
    def check_type(self) -> Optional[str]:
        return self._pydantic_model.check_type

    @property
    def version(self) -> Optional[str]:
        return self._pydantic_model.version

    @property
    def bid(self) -> Optional[list[str]]:
        return self._pydantic_model.bid

    @property
    def xref(self) -> Optional[list[str]]:
        return self._pydantic_model.xref

    @property
    def seol_date(self) -> datetime.datetime:
        return self._pydantic_model.seol_date

    @property
    def plugin_text(self) -> Optional[str]:
        return self._pydantic_model.plugin_text

    @property
    def dns_name(self) -> Optional[str]:
        return self._pydantic_model.dns_name

    @property
    def mac_address(self) -> Optional[str]:
        return self._pydantic_model.mac_address

    @property
    def netbios_name(self) -> Optional[str]:
        return self._pydantic_model.netbios_name

    @property
    def operating_system(self) -> Optional[str]:
        return self._pydantic_model.operating_system

    @property
    def recast_risk_rule_comment(self) -> Optional[list[str]]:
        return self._pydantic_model.recast_risk_rule_comment  # Note : Not implemented

    @property
    def accept_risk_rule_comment(self) -> Optional[list[str]]:
        return self._pydantic_model.accept_risk_rule_comment  # Note : Not implemented

    @property
    def host_uniqueness(self) -> list[str]:
        return self._pydantic_model.host_uniqueness

    @property
    def host_uuid(self) -> Optional[str]:
        return self._pydantic_model.host_uuid

    @property
    def acr_score(self) -> Optional[float]:
        return self._pydantic_model.acr_score

    @property
    def asset_exposure_score(self) -> float:
        return self._pydantic_model.asset_exposure_score

    @property
    def vuln_uniqueness(self) -> list[str]:
        return self._pydantic_model.vuln_uniqueness

    @property
    def vuln_uuid(self) -> Optional[str]:
        return self._pydantic_model.vuln_uuid

    @property
    def uniqueness(self) -> list[str]:
        return self._pydantic_model.uniqueness

    @staticmethod
    def parse_response(raw_response: dict[str, Any]) -> dict[str, Any]:
        """Parse finding needed arguments from a raw response."""
        flatten_response_snake_case_key = _FlattenRawResponseInSnakeCase(
            raw_response, sep="_"
        )

        direct_fields = [
            "plugin_name",
            "plugin_id",
            "ip",
            "protocol",
            "seol_date",
            "asset_exposure_score",
            "severity_name",
        ]
        optional_direct_fields = [
            "uuid",
            "exploit_ease",
            "synopsis",
            "description",
            "solution",
            "risk_factor",
            "stig_severity",
            "cvss_vector",
            "dns_name",
            "mac_address",
            "netbios_name",
            "operating_system",
            "plugin_text",
            "host_uuid",
            "acr_score",
            "vuln_uuid",
        ]
        optional_list_fields = [  # various separators in the API response...
            ("cve", ","),
            ("cpe", "<br/>"),
            ("exploit_frameworks", ","),
            ("see_also", "\n"),
            ("xref", ","),
        ]
        optional_float_fields = [
            "vpr_score",
            "base_score",
            "temporal_score",
            "cvss_v3_base_score",
            "cvss_v3_temporal_score",
        ]
        datetime_fields = ["first_seen", "last_seen"]
        optional_datetime_fields = [
            "vuln_pub_date",
            "patch_pub_date",
            "plugin_pub_date",
            "plugin_mod_date",
        ]
        bool_fields = ["has_been_mitigated", "accept_risk", "recast_risk"]
        int_fields = ["port"]
        list_fields = [
            ("host_uniqueness", ","),
            ("vuln_uniqueness", ","),
            ("uniqueness", ","),
        ]

        data = {
            field: flatten_response_snake_case_key.apply(str, field)
            for field in direct_fields
        }

        data.update(
            {
                field: flatten_response_snake_case_key.apply(str, field, optional=True)
                for field in optional_direct_fields
            }
        )
        data.update(
            {
                field: flatten_response_snake_case_key.str_list_field(
                    field, sep=sep, optional=False
                )
                for field, sep in list_fields
            }
        )
        data.update(
            {
                field: flatten_response_snake_case_key.str_list_field(
                    field, optional=True, sep=sep
                )
                for field, sep in optional_list_fields
            }
        )
        data.update(
            {
                field: flatten_response_snake_case_key.float_field(field, optional=True)
                for field in optional_float_fields
            }
        )
        data.update(
            {
                field: flatten_response_snake_case_key.timestamp_field(
                    field, optional=False
                )
                for field in datetime_fields
            }
        )
        data.update(
            {
                field: flatten_response_snake_case_key.timestamp_field(
                    field, optional=True
                )
                for field in optional_datetime_fields
            }
        )
        data.update(
            {
                field: flatten_response_snake_case_key.bool_int_field(field)
                for field in bool_fields
            }
        )
        data.update(
            {
                field: flatten_response_snake_case_key.int_field(field, optional=False)
                for field in int_fields
            }
        )

        data.update(  # another special case from the API response...
            {
                "exploit_available": flatten_response_snake_case_key.apply(
                    lambda x: str(x).lower() == "yes", "exploit_available"
                )
            }
        )
        return data


class _FindingsAPI:
    def __init__(
        self,
        tsc_client: TenableSC,
        logger: "AppLogger",
        since_datetime: datetime.datetime,
        min_severity: str,
        num_threads: int,
        cves_api: _CVEsAPI,
    ):
        self.logger = logger
        self.client = tsc_client
        self.since_datetime = since_datetime
        self.min_severity = min_severity
        self.num_threads = num_threads
        self._cves_api = cves_api

    def _fetch(
        self, offset: int, limit: int, filters: list[tuple[str, str, str]]
    ) -> dict[str, Any]:
        """Fetch a data from the API."""
        try:
            finding_response: dict[str, Any] = self.client.analysis.vulns(
                json_result=True, offset=offset, limit=limit, filters=filters
            )
            return finding_response
        except APIError as e:
            self.logger.error(
                f"Error while fetching data from Tenable Security Center: {e}"
            )
            raise FindingRetrievalError(
                "Error while fetching data from Tenable Security Center."
            ) from e

    def _fetch_data_chunk(
        self, offset: int, limit: int, filters: list[tuple[str, str, str]]
    ) -> list[dict[str, Any]]:
        """Fetch a chunk of data from the API."""
        resp = self._fetch(offset, limit, filters)
        return resp.get("results", [])  # type: ignore[no-any-return]

    def _fetch_data_chunks(
        self, filters: list[tuple[str, str, str]]
    ) -> Iterable[dict[str, Any]]:
        """Fetch all data chunks from the API."""
        total_records = int(
            self._fetch(offset=0, limit=1, filters=filters).get("totalRecords", 0)
        )
        self.logger.debug(
            f"Fetching {total_records} findings from Tenable Security Center."
        )

        if total_records == 0:
            return  # early out

        offsets = range(0, total_records, FINDINGS_CHUNK_SIZE)

        _fixed_fetch_chunk = partial(
            self._fetch_data_chunk, limit=FINDINGS_CHUNK_SIZE, filters=filters
        )

        with ThreadPoolExecutor(self.num_threads) as pool:
            # Map offsets to fetch_and_process_chunk function and gather results
            for result in pool.map(_fixed_fetch_chunk, offsets):
                yield from result

    def _from_asset_filters(
        self, name: str, ip: str, repository_id: str
    ) -> list[tuple[str, str, str]]:
        """Return the filter supposed to retrieve findings from a unique asset.

        Note:
            This is retro-engineered from Vulnerabilities API samples response all showing finding.hostUniqueness based on this properties.

        """
        return [
            ("dnsName", "=", name),
            ("ip", "=", ip),
            ("repositoryIDs", "=", repository_id),
        ]

    def _fetch_raw_findings(
        self,
        name: Optional[str] = None,
        ip: Optional[str] = None,
        repository_id: Optional[str] = None,
    ) -> Iterable[dict[str, Any]]:
        """Fetch all findings from the API.

        Args:
            name (str | None): The asset name used to filter.
            ip (str | None): The asset IP used to filter.
            repository_id (str | None): The asset repository ID used to filter.

        Returns:
            Iterable[dict[str, Any], None, None]: The raw findings.

        """
        filters: list[tuple[str, str, str]] = [
            (
                "lastSeen",
                "=",  # ts_start-ts_end
                f"{int(self.since_datetime.timestamp())}-{int(datetime.datetime.now().timestamp())}",
            ),
            (
                "severity",
                ">=",
                str(FINDING_SEVERITIES_MAP[self.min_severity]),
            ),
        ]
        if name and ip and repository_id:
            filters.extend(self._from_asset_filters(name, ip, repository_id))
        yield from self._fetch_data_chunks(filters)

    def fetch_findings(
        self,
        name: Optional[str] = None,
        ip: Optional[str] = None,
        repository_id: Optional[str] = None,
    ) -> Iterable[_FindingAPI]:
        """Fetch and process the findings."""
        raw_findings = self._fetch_raw_findings(
            name=name, ip=ip, repository_id=repository_id
        )
        for raw_finding in raw_findings:
            yield _FindingAPI(
                logger=self.logger, cves_api=self._cves_api, **raw_finding
            )


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


class _AssetAPI(AssetPort):
    """Represents an asset from the Tenable Security Center API."""

    def __init__(
        self,
        tsc_client: TenableSC,
        logger: "AppLogger",
        since_datetime: datetime.datetime,
        findings_api: _FindingsAPI,
        **data: dict[str, Any],
    ):
        self._pydantic_model = AssetPydanticModel.model_validate(
            _AssetAPI.parse_response(data)
        )
        self._logger = logger
        self._client = tsc_client
        self.since_datetime = since_datetime
        self._findings_api = findings_api

    @property
    def id(self) -> str:
        return self._pydantic_model.id

    @property
    def uuid(self) -> str:
        return self._pydantic_model.uuid

    @property
    def tenable_uuid(self) -> Optional[str]:
        return self._pydantic_model.tenable_uuid

    @property
    def name(self) -> str:
        return self._pydantic_model.name

    @property
    def operating_systems(self) -> Optional[list[str]]:
        return self._pydantic_model.operating_systems

    @property
    def first_seen(self) -> datetime.datetime:
        return self._pydantic_model.first_seen

    @property
    def last_seen(self) -> datetime.datetime:
        return self._pydantic_model.last_seen

    @property
    def mac_address(self) -> Optional[str]:
        return self._pydantic_model.mac_address

    @property
    def created_time(self) -> datetime.datetime:
        return self._pydantic_model.created_time

    @property
    def modified_time(self) -> datetime.datetime:
        return self._pydantic_model.modified_time

    @property
    def ip_address(self) -> str:
        return self._pydantic_model.ip_address

    @property
    def repository_id(self) -> str:
        return self._pydantic_model.repository_id

    @property
    def findings(self) -> Iterable[_FindingAPI]:
        yield from self._findings_api.fetch_findings(
            name=self.name, ip=self.ip_address, repository_id=self.repository_id
        )

    @staticmethod
    def parse_response(raw_response: dict[str, Any]) -> dict[str, Any]:
        """Parse asset needed arguments from a raw response."""
        direct_fields = ["id", "uuid", "name", "ip_address", "repository_id"]
        optional_direct_fields = ["tenable_uuid", "mac_address"]
        optional_list_fields = [("operating_systems", ",")]

        datetime_fields = ["first_seen", "last_seen", "created_time", "modified_time"]
        flatten_response_snake_case_key = _FlattenRawResponseInSnakeCase(
            raw_response, sep="_"
        )

        data = {
            field: flatten_response_snake_case_key.apply(str, field)
            for field in direct_fields
        }

        data.update(
            {
                field: flatten_response_snake_case_key.apply(str, field, optional=True)
                for field in optional_direct_fields
            }
        )
        data.update(
            {
                field: flatten_response_snake_case_key.str_list_field(
                    field, sep=sep, optional=True
                )
                for field, sep in optional_list_fields
            }
        )
        data.update(
            {
                field: flatten_response_snake_case_key.timestamp_field(
                    field, optional=False
                )
                for field in datetime_fields
            }
        )
        return data


class _AssetsChunkAPI(AssetsChunkPort):
    """Responsible for fetching a chunk and parse each asset."""

    def __init__(
        self,
        tsc_client: TenableSC,
        offset: int,
        limit: int,
        fields: list[str],
        since_datetime: datetime.datetime,
        findings_api: _FindingsAPI,
        logger: "AppLogger",
        filters: Optional[list[tuple[str, str, str]]],
    ):
        self.client = tsc_client
        self.logger = logger
        self.offset = offset
        self.limit = limit
        self.filters = filters if filters else []
        self.fields = fields
        self.since_datetime = since_datetime
        self._findings_api = findings_api

    @staticmethod
    def _format_url(url: str, params: dict[str, Any]) -> str:
        return f"{url}?{urlencode(params)}" if params else url

    def _build_url(self) -> str:
        """Build the URL to fetch data from the API.

        Note:
            `paginated` param is needed to get total_records in response

        """
        params = {
            "startOffset": self.offset,
            "limit": self.limit,
            "endOffset": self.offset + self.limit,
            "paginated": "true",
        }
        if self.fields:
            params["fields"] = ",".join(self.fields)
        return _AssetsChunkAPI._format_url("hosts/search", params)

    def _fetch(self) -> dict[str, Any]:
        """Fetch response."""
        body = {
            "filters": {
                "and": [
                    {
                        "property": item[0],
                        "operator": {"=": "eq", ">": "gt", "<": "lt"}[item[1]],
                        "value": item[2],
                    }
                    for item in self.filters
                ]
            }
        }

        try:
            resp: "Response" = self.client.post(self._build_url(), json=body)
            resp.raise_for_status()
            json_resp = resp.json()
            return json_resp["response"]  # type: ignore[no-any-return]
        except HTTPError as e:
            msg = f"Error while fetching data from Tenable Security Center: {e}"
            self.logger.error(msg)
            raise AssetRetrievalError(msg) from e

    def _fetch_data_chunk(self) -> list[dict[str, Any]]:
        """Fetch a chunk of data from the API."""
        resp = self._fetch()
        return resp["results"]  # type: ignore[no-any-return]

    @property
    def assets(self) -> Iterable[_AssetAPI]:
        raw_assets = self._fetch_data_chunk()
        for raw_asset in raw_assets:
            asset = _AssetAPI(
                tsc_client=self.client,
                logger=self.logger,
                since_datetime=self.since_datetime,
                findings_api=self._findings_api,
                **raw_asset,
            )
            # Manual filtering because API filter does not work
            if asset.last_seen.timestamp() >= self.since_datetime.timestamp():
                yield asset


class AssetsAPI(AssetsPort):
    """Implement the assets API."""

    def __init__(
        self,
        url: str,
        access_key: str,
        secret_key: str,
        retries: int,
        backoff: int,
        timeout: int,
        since_datetime: datetime.datetime,
        logger: "AppLogger",
        num_threads: int,
        findings_min_severity: str,
    ):
        """Initialize the asset API."""
        self.logger = logger
        self.since_datetime = since_datetime
        self.num_threads = num_threads

        self.client = TenableSC(
            url=url,
            access_key=access_key,
            secret_key=secret_key,
            retries=retries,
            backoff=backoff,
            timeout=timeout,
            # Tenable integration best practice.
            # See https://developer.tenable.com/docs/tenableio-integrations [consulted on September 27th, 2024]
            vendor="Filigran",
            product="OpenCTI",
            build=pycti_version,
        )
        _version_info = VersionInfo.parse(self.client.version)
        if not (_version_info.match(">=5.13.0") and _version_info.match("<6.5.0")):
            self.logger.warning(
                f"This version ({self.client.version}) of Tenable Security Center API has not been fully tested."
                "Consider using >=5.13.0,<6.5.0 or another adapter."
            )

        self._cves_api: _CVEsAPI = _CVEsAPI(self.client, self.logger, self.num_threads)
        self._findings_api: _FindingsAPI = _FindingsAPI(
            tsc_client=self.client,
            logger=self.logger,
            since_datetime=self.since_datetime,
            min_severity=findings_min_severity,
            num_threads=self.num_threads,
            cves_api=self._cves_api,
        )

    def _fetch_data_chunks(self) -> Iterable[_AssetsChunkAPI]:
        """Fetch all data chunks from the API."""
        filters = [
            (
                "lastSeen",
                "=",
                f"{int(self.since_datetime.timestamp())}-{int(datetime.datetime.now().timestamp())}",
            )  # ts_start-ts_end
        ]  # this lastSeen Filter does not do anything. We will reject assets with lastSeen < Since_date manually.

        # Only get "id" field to get total_records
        total_records = int(
            _AssetsChunkAPI(  # pylint: disable=protected-access
                tsc_client=self.client,
                logger=self.logger,
                offset=0,
                limit=1,
                fields=["id"],
                filters=filters,
                since_datetime=self.since_datetime,
                findings_api=self._findings_api,
            )
            ._fetch()
            .get("totalRecords", 0)
        )

        self.logger.debug(
            f"Fetching {total_records} assets from Tenable Security Center."
        )

        offsets = range(0, total_records, ASSETS_CHUNK_SIZE)

        def _fixed_fetch_chunk(offset: int) -> _AssetsChunkAPI:
            return _AssetsChunkAPI(
                tsc_client=self.client,
                logger=self.logger,
                offset=offset,
                limit=ASSETS_CHUNK_SIZE,
                fields=ASSET_FIELDS,
                filters=filters,
                since_datetime=self.since_datetime,
                findings_api=self._findings_api,
            )

        with ThreadPoolExecutor(self.num_threads) as pool:
            # Map offsets to fetch_and_process_chunk function and gather results
            yield from pool.map(_fixed_fetch_chunk, offsets)

    @property
    def chunks(self) -> Iterable[_AssetsChunkAPI]:
        """Fetch and yield the assets chunks."""
        yield from self._fetch_data_chunks()


# if __name__ == "__main__":
#     from tenable.sc import TenableSC

#     f = _FindingAPI.from_raw_response(
#         {
#     "pluginID": "10107",
#     "severity": {
#       "id": "0",
#       "name": "Info",
#       "description": "Informative"
#     },
#     "hasBeenMitigated": "1",
#     "acceptRisk": "0",
#     "recastRisk": "0",
#     "ip": "10.238.64.1",
#     "uuid": "",
#     "port": "443",
#     "protocol": "TCP",
#     "pluginName": "HTTP Server Type and Version",
#     "firstSeen": "1570291573",
#     "lastSeen": "1729354189",
#     "exploitAvailable": "No",
#     "exploitEase": "",
#     "exploitFrameworks": "",
#     "synopsis": "A web server is running on the remote host.",
#     "description": "This plugin attempts to determine the type and the version of the   remote web server.",
#     "solution": "",
#     "seeAlso": "",
#     "riskFactor": "None",
#     "stigSeverity": "",
#     "vprScore": "",
#     "vprContext": "[]",
#     "baseScore": "",
#     "temporalScore": "",
#     "cvssVector": "",
#     "cvssV3BaseScore": "",
#     "cvssV3TemporalScore": "",
#     "cvssV3Vector": "",
#     "cpe": "",
#     "vulnPubDate": "-1",
#     "patchPubDate": "-1",
#     "pluginPubDate": "946987200",
#     "pluginModDate": "1604059200",
#     "checkType": "remote",
#     "version": "1.141",
#     "cve": "",
#     "bid": "",
#     "xref": "IAVT #0001-T-0931",
#     "seolDate": "-1",
#     "pluginText": "<plugin_output>The remote web server type is :\n\nopenresty</plugin_output>",
#     "dnsName": "_gateway.incus",
#     "macAddress": "00:16:3e:a1:12:f7",
#     "netbiosName": "",
#     "operatingSystem": "Linux Kernel 2.6",
#     "ips": "10.238.64.1",
#     "recastRiskRuleComment": "",
#     "acceptRiskRuleComment": "",
#     "hostUniqueness": "repositoryID,ip,dnsName",
#     "hostUUID": "",
#     "acrScore": "6.0",
#     "keyDrivers": "{\"internet exposure\":\"internal\",\"device capability\":\"dns_server\",\"device type\":\"general_purpose\"}",
#     "assetExposureScore": "547",
#     "vulnUniqueness": "repositoryID,ip,port,protocol,pluginID",
#     "vulnUUID": "",
#     "uniqueness": "repositoryID,ip,dnsName",
#     "family": {
#       "id": "11",
#       "name": "Web Servers",
#       "type": "active"
#     },
#     "repository": {
#       "id": "1",
#       "name": "Live",
#       "description": "",
#       "dataFormat": "IPv4"
#     },
#     "pluginInfo": "10107 (443/6) HTTP Server Type and Version"
#   }
#     )
