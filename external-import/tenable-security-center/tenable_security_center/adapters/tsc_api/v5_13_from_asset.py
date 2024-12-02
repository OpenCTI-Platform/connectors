"""Provide the Implementation of the Tenable Security Center Interface using the Rest API >= 5.13."""

# isort: skip_file
# isort is removing the type ignore untyped import comment conflicting with mypy

import datetime
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache, partial
from threading import Lock
from typing import TYPE_CHECKING, Any, Iterable, Optional
from urllib.parse import urlencode

from pycti import (  # type: ignore[import-untyped]
    __version__ as pycti_version,  # pycti does not provide stubs
)

from pydantic import ValidationError
from requests import HTTPError
from semver import VersionInfo
from tenable.errors import (  # type: ignore[import-untyped]
    APIError,  # tenable does not provide stubs
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

from tenable_security_center.adapters.tsc_api.v5_13_common import (
    CVEPydanticModel,
    FindingPydanticModel,
    AssetPydanticModel,
    FlattenRawResponseInSnakeCase,
    ASSETS_CHUNK_SIZE,
    ASSET_FIELDS,
    FINDINGS_CHUNK_SIZE,
    FINDING_SEVERITIES_MAP,
)


if TYPE_CHECKING:
    from requests import Response
    from tenable_security_center.utils import AppLogger


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
            # we need to work around the client.get as it expects a error key in the response
            # see _resp_error_check in tenable.sc source code.
            raw_response: "Response" = self.client._session.get(
                f"{self.client._url}/rest/{self._build_url(cve_id)}"
            )
            raw_response.raise_for_status()
            cve_response: dict[str, Any] = raw_response.json()
            return cve_response
        except HTTPError as e:
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
        # we must disable pylint which thinks we are calling the self.__fetch method
        cache_stats = (
            self.__fetch.cache_info()  # pylint: disable=no-value-for-parameter
        )
        self.logger.debug(f"CVE Cache stats {cache_stats}")

        with ThreadPoolExecutor(self.num_threads) as executor:
            return list(executor.map(self._fetch, cve_ids))

    def fetch_cves(self, cve_ids: list[str]) -> Iterable[_CVEAPI]:
        """Fetch and process the CVEs."""
        for raw_cve in self._fetch_data_chunk(cve_ids):
            yield _CVEAPI.from_raw_response(raw_cve)


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
        flatten_response_snake_case_key = FlattenRawResponseInSnakeCase(
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
        flatten_response_snake_case_key = FlattenRawResponseInSnakeCase(
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


class _ScanResultsAPI:
    def __init__(
        self,
        tsc_client: TenableSC,
        logger: "AppLogger",
        since_datetime: datetime.datetime,
    ):
        self.logger = logger
        self.client = tsc_client
        self.since_datetime = since_datetime

    def get_completed_scan_ids(self) -> list[str]:
        """Get the IDs of the completed scans since the last run."""
        params = {
            "filters": "usable,completed,optimizeCompletedScans",
            "fields": "id",
            "timeComparedField": "createdTime",
            "startTime": int(self.since_datetime.timestamp()),
        }
        url = f"scanResult?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
        try:
            resp_scan_results = self.client.get(url)
            resp_scan_results.raise_for_status()
            json_resp_scan_results = resp_scan_results.json()
            return [scan["id"] for scan in json_resp_scan_results["response"]["usable"]]
        except HTTPError as e:
            self.logger.error(
                f"Error while fetching data from Tenable Security Center: {e}"
            )
            raise AssetRetrievalError(
                "Error while fetching data from Tenable Security Center."
            ) from e

    def get_scanned_assets_info(self, scan_id: str) -> tuple[str, str]:
        """Get the scanned IPs and the repository ID from a scan result."""
        fields = ["id", "name", "repository", "progress"]
        url = f"scanResult/{scan_id}?fields={','.join(fields)}"
        try:
            resp_scan_result = self.client.get(url)
            resp_scan_result.raise_for_status()
            json_data = resp_scan_result.json()["response"]
            if not json_data["progress"]:  # could be an empty list, empty dict or null
                return "", ""
            return json_data["progress"]["scannedIPs"], json_data["repository"]["id"]

        except (HTTPError, IndexError) as e:
            self.logger.error(
                f"Error while fetching data from Tenable Security Center: {e}"
            )
            raise AssetRetrievalError(
                "Error while fetching data from Tenable Security Center."
            ) from e


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
            # Manual filtering because no API filter
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
        self._since_datetime = since_datetime
        self.logger = logger
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
            since_datetime=self._since_datetime,
            min_severity=findings_min_severity,
            num_threads=self.num_threads,
            cves_api=self._cves_api,
        )
        self._scan_results_api: _ScanResultsAPI = _ScanResultsAPI(
            tsc_client=self.client,
            logger=self.logger,
            since_datetime=self.since_datetime,
        )

    @property
    def since_datetime(self) -> datetime.datetime:
        """Return the since datetime."""
        return self._since_datetime

    @since_datetime.setter
    def since_datetime(self, value: datetime.datetime) -> None:
        """Set the since datetime."""
        self._since_datetime = value
        self._findings_api.since_datetime = value
        self._scan_results_api.since_datetime = value

    def _fetch_data_chunks(self) -> Iterable[_AssetsChunkAPI]:
        """Fetch all data chunks from the API."""
        # As we can't filter assets by last seen date, we use scan results endpoints to filter
        # on assets that have been scanned since the provided datetime, then we fetch the assets using
        # these information.
        self.logger.debug("Fetching scan results from Tenable Security Center.")
        scan_ids = self._scan_results_api.get_completed_scan_ids()
        if scan_ids:
            assets_info = [
                self._scan_results_api.get_scanned_assets_info(scan_id)
                for scan_id in scan_ids
            ]
            filters = [
                ("ip", "=", ",".join({ip for ip, _ in assets_info if ip})),
                (
                    "repositoryAll",
                    "=",
                    ",".join(
                        {
                            repository_id
                            for _, repository_id in assets_info
                            if repository_id
                        }
                    ),
                ),
            ]
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
        else:
            self.logger.warning(
                "No scan results found in Tenable Security Center since the provided datetime."
            )
            total_records = 0

        self.logger.info(
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
