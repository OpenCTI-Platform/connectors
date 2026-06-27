from typing import Any, Callable, Generator, List

import vulncheck_sdk
from pycti import OpenCTIConnectorHelper
from vclib.config_variables import ConfigConnector
from vclib.models import data_source
from vulncheck_sdk.models.advisory_botnet import AdvisoryBotnet
from vulncheck_sdk.models.advisory_ip_intel_record import AdvisoryIpIntelRecord
from vulncheck_sdk.models.advisory_ransomware_exploit import AdvisoryRansomwareExploit
from vulncheck_sdk.models.advisory_threat_actor_with_external_objects import (
    AdvisoryThreatActorWithExternalObjects,
)
from vulncheck_sdk.models.advisory_vuln_check_kev import AdvisoryVulnCheckKEV
from vulncheck_sdk.models.api_epss_data import ApiEPSSData
from vulncheck_sdk.models.api_exploit_v3_result import ApiExploitV3Result
from vulncheck_sdk.models.api_initial_access import ApiInitialAccess
from vulncheck_sdk.models.api_nvd20_cve import ApiNVD20CVE
from vulncheck_sdk.models.api_nvd20_cve_extended import ApiNVD20CVEExtended


class ConnectorClient:
    def __init__(self, helper: OpenCTIConnectorHelper, config: ConfigConnector):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        vc_config = vulncheck_sdk.Configuration(host=str(self.config.api_base_url))
        vc_config.api_key["Bearer"] = str(self.config.api_key)

        self.vc_config = vc_config

    def iter_data(
        self, index_func: Callable[..., Any], source_name: str, **kwargs
    ) -> Generator[List[Any], None, None]:
        self.helper.connector_logger.info(
            f"[API] Getting {source_name} data from VulnCheck API"
        )

        with vulncheck_sdk.ApiClient(self.vc_config) as api_client:
            session = vulncheck_sdk.IndicesApi(api_client)

            api_response = index_func(
                session, start_cursor="true", limit=2000, **kwargs
            )
            self.helper.connector_logger.info(
                f"[API] Total items: {api_response.meta.total_documents}"
            )
            if api_response.data:
                yield api_response.data

            while api_response.meta.next_cursor is not None:
                api_response = index_func(
                    session, cursor=api_response.meta.next_cursor, limit=2000, **kwargs
                )
                if api_response.data:
                    yield api_response.data

    def iter_ipintel(self) -> Generator[List[AdvisoryIpIntelRecord], None, None]:
        yield from self.iter_data(
            lambda session, **kwargs: session.index_ipintel3d_get(id="c2", **kwargs),
            source_name=data_source.IPINTEL,
        )

    def iter_vckev(self) -> Generator[List[AdvisoryVulnCheckKEV], None, None]:
        yield from self.iter_data(
            lambda session, **kwargs: session.index_vulncheck_kev_get(**kwargs),
            source_name=data_source.VULNCHECK_KEV,
        )

    def iter_epss(self) -> Generator[List[ApiEPSSData], None, None]:
        yield from self.iter_data(
            lambda session, **kwargs: session.index_epss_get(**kwargs),
            source_name=data_source.EPSS,
        )

    def iter_botnets(self) -> Generator[List[AdvisoryBotnet], None, None]:
        yield from self.iter_data(
            lambda session, **kwargs: session.index_botnets_get(**kwargs),
            source_name=data_source.BOTNETS,
        )

    def iter_ransomware(self) -> Generator[List[AdvisoryRansomwareExploit], None, None]:
        yield from self.iter_data(
            lambda session, **kwargs: session.index_ransomware_get(**kwargs),
            source_name=data_source.RANSOMWARE,
        )

    def iter_threat_actors(
        self,
    ) -> Generator[List[AdvisoryThreatActorWithExternalObjects], None, None]:
        yield from self.iter_data(
            lambda session, **kwargs: session.index_threat_actors_get(**kwargs),
            source_name=data_source.THREAT_ACTORS,
        )

    def iter_exploits(self) -> Generator[List[ApiExploitV3Result], None, None]:
        yield from self.iter_data(
            lambda session, **kwargs: session.index_exploits_get(**kwargs),
            source_name=data_source.EXPLOITS,
        )

    def iter_initial_access(self) -> Generator[List[ApiInitialAccess], None, None]:
        yield from self.iter_data(
            lambda session, **kwargs: session.index_initial_access_get(**kwargs),
            source_name=data_source.INITIAL_ACCESS,
        )

    def iter_vcnvd2(self, **kwargs) -> Generator[List[ApiNVD20CVEExtended], None, None]:
        yield from self.iter_data(
            lambda session, **kw: session.index_vulncheck_nvd2_get(**kw),
            source_name=data_source.VULNCHECK_NVD2,
            **kwargs,
        )

    def iter_nistnvd2(self, **kwargs) -> Generator[List[ApiNVD20CVE], None, None]:
        yield from self.iter_data(
            lambda session, **kw: session.index_nist_nvd2_get(**kw),
            source_name=data_source.NIST_NVD2,
            **kwargs,
        )

    def get_rules(self, rule_type: str) -> str:
        self.helper.connector_logger.info(f"[API] Getting {rule_type} rules")

        with vulncheck_sdk.ApiClient(self.vc_config) as api_client:
            session = vulncheck_sdk.EndpointsApi(api_client)

            api_response = session.rules_initial_access_type_get(rule_type)

            self.helper.connector_logger.info(
                f"[API] Rules for {rule_type} successfully collected!"
            )

            return api_response
