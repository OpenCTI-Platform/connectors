from typing import Any, Callable, List

import requests
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

    def get_data(
        self, index_func: Callable[..., Any], source_name: str, **kwargs
    ) -> List[Any]:
        self.helper.connector_logger.info(
            f"[API] Getting {source_name} data from VulnCheck API"
        )

        result = []
        with vulncheck_sdk.ApiClient(self.vc_config) as api_client:
            session = vulncheck_sdk.IndicesApi(api_client)

            limit = 2000
            api_response = index_func(
                session, start_cursor="true", limit=limit, **kwargs
            )
            total = api_response.meta.total_documents
            if api_response.data is not None:
                result = api_response.data

            self.helper.connector_logger.info(f"[API] Total items: {total}")

            while api_response.meta.next_cursor is not None:
                api_response = index_func(
                    session, cursor=api_response.meta.next_cursor, limit=limit, **kwargs
                )
                if api_response.data is not None:
                    result.extend(api_response.data)
                self.helper.connector_logger.debug(
                    f"[API] Items Processed: {len(result)}/{total}"
                )

            self.helper.connector_logger.info(
                f"[API] Successfully retrieved {len(result)} items from {source_name}"
            )

        return result

    def get_ipintel(self) -> list[AdvisoryIpIntelRecord]:
        return self.get_data(
            lambda session, **kwargs: session.index_ipintel3d_get(id="c2", **kwargs),
            source_name=data_source.IPINTEL,
        )

    def get_vckev(self) -> list[AdvisoryVulnCheckKEV]:
        return self.get_data(
            lambda session, **kwargs: session.index_vulncheck_kev_get(**kwargs),
            source_name=data_source.VULNCHECK_KEV,
        )

    def get_epss(self) -> list[ApiEPSSData]:
        return self.get_data(
            lambda session, **kwargs: session.index_epss_get(**kwargs),
            source_name=data_source.EPSS,
        )

    def get_botnets(self) -> list[AdvisoryBotnet]:
        return self.get_data(
            lambda session, **kwargs: session.index_botnets_get(**kwargs),
            source_name=data_source.BOTNETS,
        )

    def get_ransomware(self) -> list[AdvisoryRansomwareExploit]:
        return self.get_data(
            lambda session, **kwargs: session.index_ransomware_get(**kwargs),
            source_name=data_source.RANSOMWARE,
        )

    def get_threat_actors(self) -> list[AdvisoryThreatActorWithExternalObjects]:
        return self.get_data(
            lambda session, **kwargs: session.index_threat_actors_get(**kwargs),
            source_name=data_source.THREAT_ACTORS,
        )

    def get_exploits(self) -> list[ApiExploitV3Result]:
        return self.get_data(
            lambda session, **kwargs: session.index_exploits_get(**kwargs),
            source_name=data_source.EXPLOITS,
        )

    def get_initial_access(self) -> list[ApiInitialAccess]:
        return self.get_data(
            lambda session, **kwargs: session.index_initial_access_get(**kwargs),
            source_name=data_source.INITIAL_ACCESS,
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

    def get_vcnvd2_backup_filepath(self) -> str:
        self.helper.connector_logger.info(
            "[API] Downloading backup for VulnCheck-NVD2..."
        )
        file_path = self._get_backup(data_source.VULNCHECK_NVD2)
        self.helper.connector_logger.info("[API] Backup downloaded for VulnCheck-NVD2")
        return file_path

    def get_nistnvd2_backup_filepath(self) -> str:
        self.helper.connector_logger.info("[API] Downloading backup for NIST-NVD2...")
        file_path = self._get_backup(data_source.NIST_NVD2)
        self.helper.connector_logger.info("[API] Backup downloaded for NIST-NVD2")
        return file_path

    def _get_backup(self, index: str) -> str:
        file_path = f"{index}.zip"
        with vulncheck_sdk.ApiClient(self.vc_config) as api_client:
            endpoints_client = vulncheck_sdk.EndpointsApi(api_client)

            api_response = endpoints_client.backup_index_get(index)
            if api_response.data is not None and api_response.data[0].url:
                backup_url = requests.get(api_response.data[0].url)

                with open(file_path, "wb") as file:
                    file.write(backup_url.content)
        return file_path
