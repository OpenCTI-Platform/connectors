from pycti import OpenCTIConnectorHelper, get_config_variable

from anyrun_sandbox import AnyRunSandbox
from config import config

ANYRUN_INDICATOR_TO_MAIN_OBSERVABLE = {
    'domain': 'Domain-Name',
    'url': 'Url',
    'ip': 'IPv4-Addr',
    'sha256': 'File'
}

ANYRUN_INDICATOR_TO_STIX = {
    'domain': 'domain-name',
    'url': 'url',
    'ip': 'ipv4-addr',
    'sha256': 'sha256'
}


class OpenCTI:
    def __init__(self, helper: OpenCTIConnectorHelper, anyrun: AnyRunSandbox):
        self._helper = helper
        self._anyrun = anyrun

        self._opencti_entity: dict | None = None

        self._organization = self._helper.api.identity.create(
            type='Organization', name='ANY.RUN',
            description='Empowers SOC teams with a Sandbox for real-time malware analysis, Threat Intelligence Lookup, '
                        'and high-quality feeds to enhance detection and threat coverage',
            contact_information='anyrun-integrations@any.run'
        )


    def _process_message(self, data):
        self._load_opencti_entity(data)

        self._anyrun.load_analysis_object(self._opencti_entity)
        self._helper.log_info('Preparing for the analysis.')

        analysis_summary = self._anyrun.process_analysis()['data']

        self._helper.log_info('Analysis successful')
        task_uuid = analysis_summary.get('analysis').get('uuid')

        external_reference_id = self._add_external_reference(task_uuid)
        self._add_labels(analysis_summary['analysis']['tags'])
        self._add_score(analysis_summary['analysis']['scores']['verdict']['score'])
        self._attach_report(task_uuid)

        if (self._anyrun.get_verdict(task_uuid) != 'No threats detected'
            and get_config_variable('ANYRUN_ENABLE_IOC', ['anyrun', 'enable_ioc'], config, default=True)
        ):
            self._add_malicious_iocs(task_uuid, external_reference_id)


    def _load_opencti_entity(self, data) -> None:
        """
        Loads OpenCTI entity object using message data

        :param data: Message data
        """
        self._helper.log_debug(str(data))

        opencti_entity = self._helper.api.stix_cyber_observable.read(id=data['entity_id'], withFiles=True)

        if opencti_entity is None:
            raise ValueError(
                'Observable not found (or the connector does not has access to this observable, '
                'check the group of the connector user)'
            )

        self._helper.log_debug(str(opencti_entity))
        self._opencti_entity = opencti_entity


    def _add_external_reference(self, task_uuid: str) -> str:
        """
        Creates external reference and attaches it to the OpenCTI entity

        :param task_uuid: ANY.RUN task uuid
        :return: External reference ID
        """
        url = f'https://app.any.run/tasks/{task_uuid}'
        external_reference_id = self._helper.api.external_reference.create(
            source_name=f'ANY.RUN analysis {url}',
            url=url
        ).get('id')

        self._helper.api.stix_cyber_observable.add_external_reference(
            id=self._opencti_entity['id'],
            external_reference_id=external_reference_id
        )

        return external_reference_id

    def _add_labels(self, tags: dict) -> None:
        """
        Adds labels to the OpenCTI entity

        :param tags: ANY.RUN task tags
        """
        for tag in tags:
            label = self._helper.api.label.create(value=tag['tag'])
            self._helper.api.stix_cyber_observable.add_label(id=self._opencti_entity['id'], label_id=label['id'])

    def _add_score(self, anyrun_score: int) -> None:
        """
        Adds score to the OpenCTI entity

        :param anyrun_score: ANY.RUN task score
        """
        if not (opencti_score := self._opencti_entity.get('x_opencti_score', 0)):
            self._update_score(anyrun_score)
            return

        if anyrun_score > opencti_score:
            self._update_score(anyrun_score)

    def _update_score(self, anyrun_score: int) -> None:
        """
        Updates OpenCTI entity score

        :param anyrun_score: ANY.RUN task score
        """
        self._helper.api.stix_cyber_observable.update_field(
            id=self._opencti_entity['id'],
            input={
                'key': 'x_opencti_score',
                'value': str(anyrun_score)
            }
        )


    def _add_malicious_iocs(self, task_uuid: str, external_reference_id: str) -> None:
        """
        Process ANY.RUN task indicators. If indicator's threat level is 'No threads detected' crates related observable
            else creates a new stix indicator

        :param task_uuid: ANY.RUN task uuid
        :param external_reference_id: External reference ID
        """
        if iocs := self._anyrun.get_iocs(task_uuid):

            for ioc in iocs:
                if ioc['reputation'] == 0:
                    new_observable = self._helper.api.stix_cyber_observable.create(
                        createIndicator=False,
                        createdBy=self._organization['id'],
                        update=True,
                        observableData=self._generate_observable_data(ioc),
                        externalReferences=[external_reference_id]
                    )
                    if new_observable['id'] != self._opencti_entity['id']:
                        self._helper.api.stix_core_relationship.create(
                            toId=new_observable['id'],
                            fromId=self._opencti_entity['id'],
                            confidence=90,
                            createdBy=self._organization['id'],
                            relationship_type='related-to',
                            description=ioc['category'],
                        )

                elif ioc['reputation'] in (1, 2):
                    indicator = self._helper.api.indicator.create(
                        name=ioc['ioc'],
                        description=ioc['category'],
                        x_opencti_main_observable_type=ANYRUN_INDICATOR_TO_MAIN_OBSERVABLE.get(ioc['type']),
                        x_opencti_score={0: 0, 1: 50, 2: 100}.get(ioc.get('reputation')),
                        update=True,
                        x_mitre_platforms=[get_config_variable('ANYRUN_OS_TYPE', ['anyrun_env', 'os_type'], config)],
                        createdBy=self._organization['id'],
                        pattern_type = 'stix',
                        pattern = "[{}:value = '{}']".format(
                            ANYRUN_INDICATOR_TO_STIX.get(ioc['type']),
                            ioc['ioc']
                        ),
                        externalReferences=[external_reference_id]
                    )


                    self._helper.api.stix_core_relationship.create(
                        toId=self._opencti_entity['id'],
                        fromId=indicator['id'],
                        confidence=90,
                        createdBy=self._organization['id'],
                        relationship_type='based-on',
                        description=ioc['category'],
                        externalReferences=[external_reference_id]
                    )


    def _attach_report(self, task_uuid: str) -> None:
        """
        Attaches ANY.RUN task html report to the OpenCTI entity

        :param task_uuid: ANY.RUN task uuid
        """
        self._helper.api.stix_cyber_observable.add_file(
            id=self._opencti_entity['id'],
            file_name='anyrun_cloud_sandbox_report.html',
            data=self._anyrun.get_report(task_uuid),
            mime_type='text/html'
        )

    @staticmethod
    def _generate_observable_data(indicator: dict) -> dict:
        """
        Generates OpenCTI observable payload using ANY.RUN indicator data

        :param indicator: ANY.RUN indicator
        :return: OpenCTI observable data
        """
        observable_type = ANYRUN_INDICATOR_TO_MAIN_OBSERVABLE.get(indicator['type'])
        data = {
            'type': observable_type,
            'x_opencti_description': 'Detected by ANY.RUN Sandbox'
        }

        if observable_type in ('Domain-Name', 'Url', 'IPv4-Addr'):
            data['value'] = indicator.get('ioc')
        elif observable_type == 'File':
            data['hashes'] = {'SHA-256': indicator.get('ioc')}
        return data


    # Start the main loop
    def mainloop(self):
        self._helper.listen(self._process_message)


if __name__ == '__main__':
    opencti_helper = OpenCTIConnectorHelper(config)
    anyrun_connector = AnyRunSandbox(opencti_helper)
    opencti = OpenCTI(opencti_helper, anyrun_connector)

    opencti.mainloop()
