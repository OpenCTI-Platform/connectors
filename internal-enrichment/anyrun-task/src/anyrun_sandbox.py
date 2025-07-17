import time

from anyrun.connectors import SandboxConnector
from anyrun.connectors.sandbox.base_connector import BaseSandboxConnector
from anyrun.connectors.sandbox.operation_systems import AndroidConnector, LinuxConnector, WindowsConnector

from pycti import OpenCTIConnectorHelper

from config import Config


class AnyRunSandbox:
    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        self._config: Config | None = None
        self._helper = helper
        self._analysis_type: str | None = None

    def load_analysis_object(self, opencti_entity: dict) -> None:
        """
        Setups ANY.RUN client using OpenCTI entity data

        :param opencti_entity: OpenCTI entity
        """
        if opencti_entity['entity_type']  == 'Artifact':
            self._config = Config.update_config(
                self._get_file_content(opencti_entity['importFiles'][-1]),
                'File'
            )
            self._analysis_type = 'File'
        elif opencti_entity['entity_type']  == 'Url':
            self._config = Config.update_config(
                opencti_entity['value'],
                'Url'
            )
            self._analysis_type = 'Url'
        else:
            raise ValueError('Wrong scope! Supported only Artifact and Url observables')

    def process_analysis(self) -> dict:
        """
        Starts new ANY.RUN Sandbox analysis using env_os option value

        """
        if self._config.env_os == 'windows':
            return self._process_windows_analysis()
        elif self._config.env_os == 'linux':
            return self._process_linux_analysis()
        elif self._config.env_os == 'android':
            return self._process_android_analysis()
        else:
            raise ValueError('ANY.RUN env_os option value is invalid! Please specify one of the following environments: windows, linux, android')

    def get_iocs(self, task_uuid) -> list[dict] | None:
        """
        Loads ANY.RUN task indicators

        :param task_uuid: ANY.RUN task uuid
        :return: List of indicators if exists
        """
        with SandboxConnector.windows(
            self._config.anyrun_token,
            integration=self._config.VERSION,
            enable_requests=True
        ) as connector:
            iocs = connector.get_analysis_report(task_uuid, report_format='ioc')

        return iocs if iocs else None

    def get_report(self, task_uuid: str) -> bytes | dict:
        """
        Loads ANY.RUN task html report

        :param task_uuid: ANY.RUN task uuid
        :return: HTML report bytes
        """
        with BaseSandboxConnector(
            self._config.anyrun_token,
            integration=self._config.VERSION,
            enable_requests=True
        ) as connector:
            return connector.get_analysis_report(task_uuid, 'html')

    def get_verdict(self, task_uuid: str) -> str:
        """
        Loads ANY.RUN task verdict

        :param task_uuid: ANY.RUN task uuid
        :return: Verdict
        """
        with BaseSandboxConnector(
            self._config.anyrun_token,
            integration=self._config.VERSION,
            enable_requests=True
        ) as connector:
            return connector.get_analysis_verdict(task_uuid)


    def _get_file_content(self, file: dict) -> tuple[bytes, str]:
        """
        Loads OpenCTI entity file

        :param file: OpenCTI file params
        :return: File data
        """
        artifact_url = f'{self._helper.opencti_url}/storage/get/{file.get("id")}'
        try:
            return self._helper.api.fetch_opencti_file(artifact_url, binary=True), file.get('name')
        except Exception as err:
            raise ValueError('Error fetching artifact from OpenCTI') from err

    def _process_windows_analysis(self) -> dict:
        """
        Initializes ANY.RUN Sandbox analysis using Windows environment

        :return: ANY.RUN Sandbox analysis summary
        """
        with SandboxConnector.windows(
            self._config.anyrun_token,
            integration=self._config.VERSION,
            enable_requests=True
        ) as connector:
            summary = self._get_submission(connector)
            return summary

    def _process_linux_analysis(self) -> dict:
        """
        Initializes ANY.RUN Linux analysis using Windows environment

        :return: ANY.RUN Linux analysis summary
        """
        with SandboxConnector.linux(
            self._config.anyrun_token,
            integration=self._config.VERSION,
            enable_requests=True
        ) as connector:
            summary = self._get_submission(connector)
            return summary

    def _process_android_analysis(self) -> dict:
        """
        Initializes ANY.RUN Android analysis using Windows environment

        :return: ANY.RUN Android analysis summary
        """
        with SandboxConnector.android(
            self._config.anyrun_token,
            integration=self._config.VERSION,
            enable_requests=True
        ) as connector:
            summary = self._get_submission(connector)
            return summary

    def _get_submission(
            self,
            connector: WindowsConnector | LinuxConnector | AndroidConnector
    ) -> dict:
        """
        Process analysis

        :param connector: ANY.RUN Sandbox connector instance
        :return: ANY.RUN analysis summary
        """
        connector.check_authorization()

        if self._analysis_type == 'File':
            task_uuid = connector.run_file_analysis(**self._config.to_dict)
        else:
            task_uuid = connector.run_url_analysis(**self._config.to_dict)

        time.sleep(10)

        self._helper.log_info('Analysis is started successfully.')
        for status in connector.get_task_status(task_uuid):
            self._helper.log_info(str(status))

        self._helper.log_info('Analysis is completed. Processing the report results.')
        return connector.get_analysis_report(task_uuid, report_format='summary')
