from pycti import OpenCTIConnectorHelper
from anyrun.connectors import LookupConnector

from config import Config

ANYRUN_INDICATOR_TO_MAIN_OBSERVABLE = {
    'relatedDNS': 'Domain-Name',
    'relatedURLs': 'Url',
    'destinationIP': 'IPv4-Addr'
}

ANYRUN_INDICATOR_TO_STIX = {
    'relatedDNS': 'domain-name',
    'relatedURLs': 'url',
    'destinationIP': 'ipv4-addr'
}

SDK_ENTITY_TO_LOOKUP_OBJECT = {
    'domain_name': 'domainName',
    'destination_ip': 'destinationIp',
    'url': 'url',
    'sha256': 'sha256',
    'sha1': 'sha1',
    'md5': 'md5',
}


class AnyRunTILookup:
    def __init__(self, config: Config):
        self._helper = OpenCTIConnectorHelper({})
        self._config = config

        self._organization = self._helper.api.identity.create(
            type='Organization',
            name='ANY.RUN',
            description='Empowers SOC teams with a Sandbox for real-time malware analysis, Threat Intelligence Lookup, '
                        'and high-quality feeds to enhance detection and threat coverage',
            contact_information='anyrun-integrations@any.run',
        )

    def _process_message(self, data):
        self._load_opencti_entity(data)

        lookup_search_results = self._get_intelligence()

        if self._is_empty(lookup_search_results):
            self._helper.api.work.to_received(self._helper.work_id, 'Object was not found in ANY.RUN TI Lookup.')
            return

        anyrun_score = lookup_search_results.get('summary').get('threatLevel')
        if not anyrun_score:
            anyrun_score = 0

        self._create_country_relationship(lookup_search_results.get('destinationIPgeo'))
        self._add_source_tasks(lookup_search_results.get('sourceTasks'))
        external_reference_id = self._add_external_reference()

        self._add_malicious_indicators(lookup_search_results.get('relatedDNS'), 'relatedDNS', external_reference_id)
        self._add_malicious_indicators(lookup_search_results.get('relatedURLs'), 'relatedURLs', external_reference_id)
        self._add_malicious_indicators(lookup_search_results.get('destinationIP'), 'destinationIP',
                                       external_reference_id)

        self._add_score(anyrun_score)
        self._add_tags(lookup_search_results.get('summary').get('tags'))
        self._add_indicator(anyrun_score)

    def _create_country_relationship(self, destination_ips: list[dict | None]) -> None:
        for ipgeo in destination_ips:
            if self._opencti_entity['entity_type'] == 'IPv4-Addr':
                opencti_locations = self._helper.api.location.list(search=ipgeo)
                self._helper.api.stix_core_relationship.create(
                    toId=opencti_locations[0]['id'],
                    fromId=self._opencti_entity['id'],
                    createdBy=self._organization['id'],
                    relationship_type='located-at',
                )

    def _add_source_tasks(self, source_tasks: list[dict | None]) -> None:
        """
        Adds source tasks to the OpenCTI entity

        :param source_tasks: ANY.RUN analysis source tasks
        :return:
        """
        for task in source_tasks:
            if task.get('threatLevel') == 2:
                external_reference_task = self._helper.api.external_reference.create(
                    source_name='ANY.RUN analysis {}'.format(task['uuid']),
                    url=task['related'],
                )
                self._helper.api.stix_cyber_observable.add_external_reference(
                    id=self._opencti_entity['id'],
                    external_reference_id=external_reference_task['id'],
                )

    def _add_tags(self, tags: list[str | None]) -> None:
        """
        Adds ANY.RUN tags to the OpenCTI entity

        :param tags: ANY.RUN analysis tags
        """
        for tag in tags:
            label = self._helper.api.label.create(value=tag)
            self._helper.api.stix_cyber_observable.add_label(
                id=self._opencti_entity['id'],
                label_id=label['id']
            )

    def _add_malicious_indicators(self, indicators: list[dict], indicator_type: str,
                                  external_reference_id: str) -> None:
        """
        Process ANY.RUN task indicators. If indicator's threat level is 'No threads detected' crates related observable
            else creates a new stix indicator

        :param indicators: List of ANY.RUN indicators
        :param indicator_type: ANY.RUN indicator type
        :param external_reference_id: External reference ID
        """
        if indicators:
            for ioc in indicators:
                if ioc['threatLevel'] == 0:
                    new_observable = self._helper.api.stix_cyber_observable.create(
                        createIndicator=False,
                        createdBy=self._organization['id'],
                        update=True,
                        observableData=self._generate_observable_data(ioc, indicator_type),
                        externalReferences=[external_reference_id]
                    )
                    if new_observable['id'] != self._opencti_entity['id']:
                        self._helper.api.stix_core_relationship.create(
                            toId=new_observable['id'],
                            fromId=self._opencti_entity['id'],
                            confidence=90,
                            createdBy=self._organization['id'],
                            relationship_type='related-to',
                            description='Detected by ANY.RUN TI Lookup',
                        )
                elif ioc['threatLevel'] in (1, 2):
                    indicator = self._helper.api.indicator.create(
                        name=self._extract_indicator_value(ioc, indicator_type),
                        description='Detected by ANY.RUN TI Lookup',
                        x_opencti_main_observable_type=ANYRUN_INDICATOR_TO_MAIN_OBSERVABLE.get(indicator_type),
                        x_opencti_score={0: 0, 1: 50, 2: 100}.get(ioc.get('threatLevel')),
                        update=True,
                        createdBy=self._organization['id'],
                        pattern_type='stix',
                        pattern="[{}:value = '{}']".format(
                            ANYRUN_INDICATOR_TO_STIX.get(indicator_type),
                            self._extract_indicator_value(ioc, indicator_type)
                        ),
                        externalReferences=[external_reference_id]
                    )

                    self._helper.api.stix_core_relationship.create(
                        toId=self._opencti_entity['id'],
                        fromId=indicator['id'],
                        confidence=90,
                        createdBy=self._organization['id'],
                        relationship_type='based-on',
                        description='Detected by ANY.RUN TI Lookup',
                        externalReferences=[external_reference_id]
                    )

    def _add_score(self, anyrun_score: int) -> None:
        """
        Adds score to the OpenCTI entity

        :param anyrun_score: ANY.RUN task score
        """
        opencti_score = self._opencti_entity.get('x_opencti_score', 0)
        anyrun_score = {0: 0, 1: 50, 2: 100}.get(anyrun_score, 0)

        if not opencti_score:
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

    def _add_indicator(self, anyrun_score: int) -> None:
        """
        Creates indicator for the main observable if it has suspicious or malicious threat level

        :param anyrun_score: ANY.RUN score
        """
        if anyrun_score in (0, 3, 4):
            return
        elif anyrun_score == 1:
            score = 30
        elif anyrun_score == 2:
            score = 100

        self._helper.api.stix_cyber_observable.create(
            observableData={
                'type': self._opencti_entity.get('entity_type').lower(),
                'value': self._opencti_entity.get('value'),
                'x_opencti_description': 'Detected by ANY.RUN TI Lookup'
            },
            createIndicator=True,
            createdBy=self._organization['id'],
            update=True,
            x_opencti_score=score
        )

    def _load_opencti_entity(self, data) -> None:
        """
        Loads OpenCTI entity object using message data

        :param data: Message data
        """
        self._helper.log_debug(str(data))

        self._opencti_entity = self._helper.api.stix_cyber_observable.read(id=data['entity_id'], withFiles=True)

        if self._opencti_entity is None:
            raise ValueError(
                'Observable not found (or the connector does not has access to this observable, check the group of the connector user)'
            )

        self._helper.log_info(str(self._opencti_entity))
        self._opencti_entity = self._opencti_entity

    def _get_intelligence(self) -> dict | None:
        """
        Executes a request to ANY.RUN TI Lookup

        :return: TI Lookup summary
        """
        with LookupConnector(
                self._config.anyrun_token,
                integration=self._config.VERSION,
                enable_requests=True
        ) as connector:
            connector.check_authorization()

            return connector.get_intelligence(**self._prepare_lookup_params(), lookup_depth=self._config.lookup_depth)

    def _prepare_lookup_params(self) -> dict:
        """
        Converts OpenCTI entity data to the SDK query parameters

        :return: Query parameters
        """
        if self._opencti_entity['entity_type'] == 'Domain-Name':
            return {'domain_name': self._opencti_entity['value']}
        elif self._opencti_entity['entity_type'] == 'Hostname':
            return {'domain_name': self._opencti_entity['value']}
        elif self._opencti_entity['entity_type'] == 'IPv4-Addr':
            return {'destination_ip': self._opencti_entity['value']}
        elif self._opencti_entity['entity_type'] == 'Url':
            return {'url': self._opencti_entity['value']}
        elif self._opencti_entity['entity_type'] in ('StixFile', 'Artifact'):
            if hashes := self._opencti_entity.get('hashes'):
                for file_hash in hashes:
                    if (algorithm := file_hash.get('algorithm')) in ('SHA-256', 'SHA-1', 'MD5'):
                        return {algorithm.lower().replace('-', ''): file_hash.get('hash')}
            raise ValueError(
                'StixFile or Artifact entity must have at least one of the following hashes: SHA-256, SHA-1, MD5'
            )
        else:
            raise ValueError(
                'Wrong scope! Supported only Artifact, StixFile, Directory, Domain-Name, Hostname, IPv4-Addr, Mutex, Process, Url'
                'Windows-Registry-Key, Windows-Registry-Value-Type observables'
            )

    def _add_external_reference(self) -> str:
        """
        Creates external reference and attaches it to the OpenCTI entity

        :return: External reference ID
        """
        entity_type, entity_value = list(self._prepare_lookup_params().items())[0]

        url = (
                'https://intelligence.any.run/analysis/lookup#{%22query%22:%22'
                + SDK_ENTITY_TO_LOOKUP_OBJECT.get(entity_type)
                + ':%5C%22'
                + entity_value
                + '%5C%22%22,%22dateRange%22:'
                + str(self._config.lookup_depth)
                + '}'
        )

        # Create and add note to the main observable
        note = self._helper.api.note.create(
            authors=[self._organization['id']],
            content=f'ANY.RUN TI Lookup link:\n {url}'
        )

        self._helper.api.note.add_stix_object_or_stix_relationship(
            id=note['id'],
            stixObjectOrStixRelationshipId=self._opencti_entity['id'])

        # Create external reference for the child entities
        external_reference_id = self._helper.api.external_reference.create(
            source_name=f'ANY.RUN TI Lookup link {url}',
            url=url
        ).get('id')

        return external_reference_id

    def _generate_observable_data(self, indicator: dict, indicator_type: str) -> dict:
        """
        Generates OpenCTI observable payload using ANY.RUN indicator data

        :param indicator: ANY.RUN indicator
        :return: OpenCTI observable data
        """
        return {
            'type': ANYRUN_INDICATOR_TO_MAIN_OBSERVABLE.get(indicator_type),
            'x_opencti_description': 'Detected by ANY.RUN TI Lookup',
            'value': self._extract_indicator_value(indicator, indicator_type)
        }

    @staticmethod
    def _extract_indicator_value(indicator: dict, indicator_type: str) -> str:
        """
        Extracts indicator value according to the indicator type

        :param indicator: ANY.RUN indicator
        :param indicator_type: ANY.RUN indicator type
        :return: ANY.RUN indicator value
        """
        if indicator_type == 'relatedDNS':
            return indicator.get('domainName')
        elif indicator_type == 'relatedURLs':
            return indicator.get('url')
        else:
            return indicator.get('destinationIP')

    @staticmethod
    def _is_empty(lookup_search_results: dict) -> bool:
        """
        Checks if ANY.RUN TI Lookup summary is empty

        :param lookup_search_results: TI Lookup summary
        :return: True if TI Lookup summary is not empty else False
        """
        empty = True
        for key, value in lookup_search_results.items():
            if key != 'summary' and value:
                empty = False
        return empty

    # Start the main loop
    def mainloop(self):
        self._helper.listen(self._process_message)


if __name__ == '__main__':
    anyrun_connector = AnyRunTILookup(Config())
    anyrun_connector.mainloop()
