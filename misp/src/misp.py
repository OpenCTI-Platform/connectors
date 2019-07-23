# coding: utf-8

import os
import yaml
import time
import logging

from datetime import datetime
from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper
from pymisp import ExpandedPyMISP
from stix2 import Bundle, Identity, ThreatActor, IntrusionSet, Malware, Tool, Report, Indicator, Relationship, \
    ExternalReference, TLP_WHITE, TLP_GREEN, \
    TLP_AMBER, TLP_RED


class Misp:
    def __init__(self):
        # Get configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        self.config = dict()
        if os.path.isfile(config_file_path):
            config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            self.config_rabbitmq = config['rabbitmq']
            self.config['name'] = config['misp']['name']
            self.config['confidence_level'] = config['misp']['confidence_level']
            self.config['url'] = config['misp']['url']
            self.config['key'] = config['misp']['key']
            self.config['tag'] = config['misp']['tag'] if 'tag' in config['misp'] else None
            self.config['untag_event'] = config['misp']['untag_event'] if 'untag_event' in config['misp'] else None
            self.config['imported_tag'] = config['misp']['imported_tag']
            self.config['filter_on_imported_tag'] = config['misp']['filter_on_imported_tag']
            self.config['interval'] = config['misp']['interval']
            self.config['log_level'] = config['misp']['log_level']
        else:
            self.config_rabbitmq = dict()
            self.config_rabbitmq['hostname'] = os.getenv('RABBITMQ_HOSTNAME', 'localhost')
            self.config_rabbitmq['port'] = os.getenv('RABBITMQ_PORT', 5672)
            self.config_rabbitmq['username'] = os.getenv('RABBITMQ_USERNAME', 'guest')
            self.config_rabbitmq['password'] = os.getenv('RABBITMQ_PASSWORD', 'guest')
            self.config['name'] = os.getenv('MISP_NAME', 'MISP')
            self.config['confidence_level'] = int(os.getenv('MISP_CONFIDENCE_LEVEL', 3))
            self.config['url'] = os.getenv('MISP_URL', 'http://localhost')
            self.config['key'] = os.getenv('MISP_KEY', 'ChangeMe')
            self.config['tag'] = os.getenv('MISP_TAG', None)
            self.config['untag_event'] = os.getenv('MISP_UNTAG_EVENT', None) == "true"
            self.config['imported_tag'] = os.getenv('MISP_IMPORTED_TAG', 'OpenCTI: Imported')
            self.config['filter_on_imported_tag'] = os.getenv('MISP_FILTER_ON_IMPORTED_TAG', "true") == "true"
            self.config['interval'] = os.getenv('MISP_INTERVAL', 5)
            self.config['log_level'] = os.getenv('MISP_LOG_LEVEL', 'info')

        # Initialize OpenCTI Connector
        connector_identifier = ''.join(e for e in self.config['name'] if e.isalnum())
        self.opencti_connector_helper = OpenCTIConnectorHelper(
            connector_identifier.lower(),
            self.config,
            self.config_rabbitmq,
            self.config['log_level']
        )

        # Initialize MISP
        self.misp = ExpandedPyMISP(self.config['url'], self.config['key'], False, 'json')

    def get_log_level(self):
        return self.config['log_level']

    def get_interval(self):
        return int(self.config['interval']) * 60

    def run(self):
        generic_actor = ThreatActor(
            name='Unknown threats',
            labels=['threat-actor'],
            description='All unknown threats are representing by this pseudo threat actor.'
        )
        added_threats = []
        and_parameters = None
        not_parameters= None
        if self.config['tag'] is not None:
            and_parameters = [self.config['tag']]
        if self.config['filter_on_imported_tag']:
            not_parameters = [self.config['imported_tag']]

        complex_query = self.misp.build_complex_query(and_parameters=and_parameters, not_parameters=not_parameters)
        result = self.misp.search('events', tags=complex_query)
        for event in result:
            # Default values
            author = Identity(name=event['Event']['Orgc']['name'], identity_class='organization')
            report_threats = self.prepare_threats(event['Event']['Galaxy'])
            report_markings = self.resolve_markings(event['Event']['Tag'])
            reference_misp = ExternalReference(
                source_name=self.config['name'],
                url=self.config['url'] + '/events/view/' + event['Event']['uuid'])

            # Get all attributes
            indicators = []
            for attribute in event['Event']['Attribute']:
                indicator = self.process_attribute(author, report_threats, attribute, generic_actor)
                if indicator is not None:
                    indicators.append(indicator)

            # get all attributes of object
            for object in event['Event']['Object']:
                for attribute in object['Attribute']:
                    indicator = self.process_attribute(author, report_threats, attribute, generic_actor)
                    if indicator is not None:
                        indicators.append(indicator)

            bundle_objects = [author]
            report_refs = []
            for report_marking in report_markings:
                bundle_objects.append(report_marking)

            for report_threat in report_threats:
                report_refs.append(report_threat)
                bundle_objects.append(report_threat)
                added_threats.append(report_threat['name'])

            for indicator in indicators:
                report_refs.append(indicator['indicator'])
                bundle_objects.append(indicator['indicator'])
                for attribute_threat in indicator['attribute_threats']:
                    if attribute_threat['name'] not in added_threats:
                        report_refs.append(attribute_threat)
                        bundle_objects.append(attribute_threat)
                        added_threats.append(attribute_threat['name'])
                for relationship in indicator['relationships']:
                    report_refs.append(relationship)
                    bundle_objects.append(relationship)

            if len(report_refs) > 0:
                report = Report(
                    name=event['Event']['info'],
                    description=event['Event']['info'],
                    published=parse(event['Event']['date']),
                    created_by_ref=author,
                    object_marking_refs=report_markings,
                    labels=['threat-report'],
                    object_refs=report_refs,
                    external_references=[reference_misp],
                    custom_properties={
                        'x_opencti_report_class': 'Threat Report'
                    }
                )
                bundle_objects.append(report)
                bundle = Bundle(objects=bundle_objects).serialize()
                self.opencti_connector_helper.send_stix2_bundle(bundle)

            if 'untag_event' not in self.config or self.config['untag_event']:
                self.misp.untag(event['Event']['uuid'], self.config['tag'])
            self.misp.tag(event['Event']['uuid'], self.config['imported_tag'])

    def process_attribute(self, author, report_threats, attribute, generic_actor):
        resolved_attributes = self.resolve_type(attribute['type'], attribute['value'])
        if resolved_attributes is None:
            return None

        for resolved_attribute in resolved_attributes:
            # Default values
            attribute_threats = self.prepare_threats(attribute['Galaxy'])
            if 'Tag' in attribute:
                attribute_markings = self.resolve_markings(attribute['Tag'])
            else:
                attribute_markings = [TLP_WHITE]

            if len(report_threats) == 0 and len(attribute_threats) == 0:
                attribute_threats.append(generic_actor)

            indicator = Indicator(
                name='Indicator',
                description=attribute['comment'],
                pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                labels=['malicious-activity'],
                created_by_ref=author,
                object_marking_refs=attribute_markings,
                custom_properties={
                    'x_opencti_observable_type': resolved_attribute['type'],
                    'x_opencti_observable_value': resolved_attribute['value'],
                }
            )

            relationships = []
            for report_threat_ref in report_threats:
                relationships.append(
                    Relationship(
                        relationship_type='indicates',
                        created_by_ref=author,
                        source_ref=indicator.id,
                        target_ref=report_threat_ref.id,
                        description=attribute['comment'],
                        object_marking_refs=attribute_markings,
                        custom_properties={
                            'x_opencti_first_seen': datetime.utcfromtimestamp(int(attribute['timestamp'])).strftime(
                                '%Y-%m-%dT%H:%M:%SZ'),
                            'x_opencti_last_seen': datetime.utcfromtimestamp(int(attribute['timestamp'])).strftime(
                                '%Y-%m-%dT%H:%M:%SZ'),
                            'x_opencti_weight': self.config['confidence_level']
                        }
                    )
                )
            for attribute_threat_ref in attribute_threats:
                relationships.append(
                    Relationship(
                        relationship_type='indicates',
                        created_by_ref=author,
                        source_ref=indicator.id,
                        target_ref=attribute_threat_ref.id,
                        description=attribute['comment'],
                        object_marking_refs=attribute_markings,
                        custom_properties={
                            'x_opencti_first_seen': datetime.utcfromtimestamp(int(attribute['timestamp'])).strftime(
                                '%Y-%m-%dT%H:%M:%SZ'),
                            'x_opencti_last_seen': datetime.utcfromtimestamp(int(attribute['timestamp'])).strftime(
                                '%Y-%m-%dT%H:%M:%SZ'),
                            'x_opencti_weight': self.config['confidence_level']
                        }
                    )
                )
            return {'indicator': indicator, 'relationships': relationships, 'attribute_threats': attribute_threats}

    def prepare_threats(self, galaxies):
        threats = []
        for galaxy in galaxies:
            # MITRE galaxies
            if galaxy['namespace'] == 'mitre-attack':
                if galaxy['name'] == 'Intrusion Set':
                    for galaxy_entity in galaxy['GalaxyCluster']:
                        if ' - G' in galaxy_entity['value']:
                            name = galaxy_entity['value'].split(' - G')[0]
                        else:
                            name = galaxy_entity['value']
                        if 'meta' in galaxy_entity and 'synonyms' in galaxy_entity['meta']:
                            aliases = galaxy_entity['meta']['synonyms']
                        else:
                            aliases = [name]
                        threats.append(IntrusionSet(
                            name=name,
                            labels=['intrusion-set'],
                            description=galaxy_entity['description'],
                            custom_properties={
                                'x_opencti_aliases': aliases
                            }
                        ))
                if galaxy['name'] == 'Malware':
                    for galaxy_entity in galaxy['GalaxyCluster']:
                        if ' - S' in galaxy_entity['value']:
                            name = galaxy_entity['value'].split(' - S')[0]
                        else:
                            name = galaxy_entity['value']
                        if 'meta' in galaxy_entity and 'synonyms' in galaxy_entity['meta']:
                            aliases = galaxy_entity['meta']['synonyms']
                        else:
                            aliases = [name]
                        threats.append(Malware(
                            name=name,
                            labels=['malware'],
                            description=galaxy_entity['description'],
                            custom_properties={
                                'x_opencti_aliases': aliases
                            }
                        ))
                if galaxy['name'] == 'Tool':
                    for galaxy_entity in galaxy['GalaxyCluster']:
                        if ' - S' in galaxy_entity['value']:
                            name = galaxy_entity['value'].split(' - S')[0]
                        else:
                            name = galaxy_entity['value']
                        if 'meta' in galaxy_entity and 'synonyms' in galaxy_entity['meta']:
                            aliases = galaxy_entity['meta']['synonyms']
                        else:
                            aliases = [name]
                        threats.append(Tool(
                            name=name,
                            labels=['tool'],
                            description=galaxy_entity['description'],
                            custom_properties={
                                'x_opencti_aliases': aliases
                            }
                        ))
            if galaxy['namespace'] == 'misp':
                if galaxy['name'] == 'Threat Actor':
                    for galaxy_entity in galaxy['GalaxyCluster']:
                        if 'APT ' in galaxy_entity['value']:
                            name = galaxy_entity['value'].replace('APT ', 'APT')
                        else:
                            name = galaxy_entity['value']
                        if 'meta' in galaxy_entity and 'synonyms' in galaxy_entity['meta']:
                            aliases = galaxy_entity['meta']['synonyms']
                        else:
                            aliases = [name]
                        threats.append(IntrusionSet(
                            name=name,
                            labels=['intrusion-set'],
                            description=galaxy_entity['description'],
                            custom_properties={
                                'x_opencti_aliases': aliases
                            }
                        ))
                if galaxy['name'] == 'Tool':
                    for galaxy_entity in galaxy['GalaxyCluster']:
                        name = galaxy_entity['value']
                        if 'meta' in galaxy_entity and 'synonyms' in galaxy_entity['meta']:
                            aliases = galaxy_entity['meta']['synonyms']
                        else:
                            aliases = [name]
                        threats.append(Malware(
                            name=name,
                            labels=['malware'],
                            description=galaxy_entity['description'],
                            custom_properties={
                                'x_opencti_aliases': aliases
                            }
                        ))
                if galaxy['name'] == 'Ransomware':
                    for galaxy_entity in galaxy['GalaxyCluster']:
                        name = galaxy_entity['value']
                        if 'meta' in galaxy_entity and 'synonyms' in galaxy_entity['meta']:
                            aliases = galaxy_entity['meta']['synonyms']
                        else:
                            aliases = [name]
                        threats.append(Malware(
                            name=name,
                            labels=['malware'],
                            description=galaxy_entity['description'],
                            custom_properties={
                                'x_opencti_aliases': aliases
                            }
                        ))
                if galaxy['name'] == 'Malpedia':
                    for galaxy_entity in galaxy['GalaxyCluster']:
                        name = galaxy_entity['value']
                        if 'meta' in galaxy_entity and 'synonyms' in galaxy_entity['meta']:
                            aliases = galaxy_entity['meta']['synonyms']
                        else:
                            aliases = [name]
                        threats.append(Malware(
                            name=name,
                            labels=['malware'],
                            description=galaxy_entity['description'],
                            custom_properties={
                                'x_opencti_aliases': aliases
                            }
                        ))
        return threats

    def resolve_type(self, type, value):
        types = {
            'md5': ['File-MD5'],
            'sha1': ['File-SHA1'],
            'sha256': ['File-SHA256'],
            'filename': ['File-Name'],
            'pdb': ['PDB-Path'],
            'filename|md5': ['File-Name', 'File-MD5'],
            'filename|sha1': ['File-Name', 'File-SHA1'],
            'filename|sha256': ['File-Name', 'File-SHA256'],
            'ip-src': ['IPv4-Addr'],
            'ip-dst': ['IPv4-Addr'],
            'hostname': ['Domain'],
            'domain': ['Domain'],
            'domain|ip': ['Domain', 'IPv4-Addr'],
            'url': ['URL'],
            'windows-service-name': ['Windows-Service-Name'],
            'windows-service-displayname': ['Windows-Service-Display-Name'],
            'windows-scheduled-task': ['Windows-Scheduled-Task']
        }
        if type in types:
            resolved_types = types[type]
            if len(resolved_types) == 2:
                values = value.split('|')
                if resolved_types[0] == 'IPv4-Addr':
                    type_0 = self.detect_ip_version(values[0])
                else:
                    type_0 = resolved_types[0]
                if resolved_types[1] == 'IPv4-Addr':
                    type_1 = self.detect_ip_version(values[1])
                else:
                    type_1 = resolved_types[1]
                return [{'type': type_0, 'value': values[0]}, {'type': type_1, 'value': values[1]}]
            else:
                if resolved_types[0] == 'IPv4-Addr':
                    type_0 = self.detect_ip_version(value)
                else:
                    type_0 = resolved_types[0]
                return [{'type': type_0, 'value': value}]

    def detect_ip_version(self, value):
        if len(value) > 16:
            return 'IPv6-Addr'
        else:
            return 'IPv4-Addr'

    def resolve_markings(self, tags):
        markings = []
        for tag in tags:
            if tag['name'] == 'tlp:white':
                markings.append(TLP_WHITE)
            if tag['name'] == 'tlp:green':
                markings.append(TLP_GREEN)
            if tag['name'] == 'tlp:amber':
                markings.append(TLP_AMBER)
            if tag['name'] == 'tlp:red':
                markings.append(TLP_RED)
        if len(markings) == 0:
            markings.append(TLP_WHITE)
        return markings


if __name__ == '__main__':
    misp = Misp()

    # Configure logger
    numeric_level = getattr(logging, misp.get_log_level().upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: ' + misp.get_log_level())
    logging.basicConfig(level=numeric_level)

    logging.info('Starting the MISP connector...')
    while True:
        try:
            logging.info('Fetching new MISP events...')
            misp.run()
            time.sleep(misp.get_interval())
        except Exception as e:
            logging.error(e)
            time.sleep(30)
