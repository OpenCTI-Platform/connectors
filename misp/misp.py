# coding: utf-8

import urllib3
import os
from datetime import datetime
from dateutil.parser import parse
from pycti import OpenCTI
from pymisp import PyMISP

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Misp:
    def __init__(self, config):
        # Initialize config
        self.config = config

        # Initialize MISP
        self.misp = PyMISP(self.config['misp']['url'], self.config['misp']['key'], False, 'json')

        # Initialize OpenCTI client
        self.opencti = OpenCTI(
            self.config['opencti']['api_url'],
            self.config['opencti']['api_key'],
            os.path.dirname(os.path.abspath(__file__)) + '/misp.log',
            True
        )

    def get_config(self):
        return self.config['misp']

    def run(self):
        result = self.misp.search('events', tags=['OpenCTI: Import'])

        for event in result['response']:
            # Default values
            author_id = self.opencti.create_identity_if_not_exists('Organization', event['Event']['Orgc']['name'], '')[
                'id']
            event_threats = self.prepare_threats(event['Event']['Galaxy'])
            event_markings = self.resolve_markings(event['Event']['Tag'])

            # Create the external reference of the event
            external_reference_id = self.opencti.create_external_reference_if_not_exists(
                self.config['misp']['name'],
                self.config['misp']['url'] + '/events/view/' + event['Event']['uuid'],
                event['Event']['uuid'])['id']

            # Create the report of the event
            report_id = self.opencti.create_report_if_not_exists_from_external_reference(
                external_reference_id,
                event['Event']['info'],
                event['Event']['info'],
                parse(event['Event']['date']).strftime('%Y-%m-%dT%H:%M:%SZ'),
                'external'
            )['id']
            self.opencti.update_stix_domain_entity_created_by_ref(report_id, author_id)

            # Add markings to report
            for marking in event_markings:
                self.opencti.add_marking_definition_if_not_exists(report_id, marking)

            # Add entities to report
            for threat in event_threats:
                self.opencti.add_object_ref_to_report_if_not_exists(report_id, threat['id'])

            # Get all attributes
            for attribute in event['Event']['Attribute']:
                self.process_attribute(report_id, author_id, event_threats, event_markings, attribute)
            # get all attributes of object
            for object in event['Event']['Object']:
                for attribute in object['Attribute']:
                    self.process_attribute(report_id, author_id, event_threats, event_markings, attribute)

            self.misp.tag(event['Event']['uuid'], 'OpenCTI: Imported')
            self.misp.untag(event['Event']['uuid'], 'OpenCTI: Import')

    def process_attribute(self, report_id, author_id, event_threats, event_markings, attribute):
        type = self.resolve_type(attribute['type'])
        if type is not None:
            # Default values
            attribute_threats = self.prepare_threats(attribute['Galaxy'])
            if 'Tag' in attribute:
                attribute_markings = self.resolve_markings(attribute['Tag'])
            else:
                attribute_markings = []

            # Check necessary threats
            if len(event_threats) == 0 and len(attribute_threats) == 0:
                attribute_threats.append({'type': 'Threat-Actor', 'id': self.opencti.create_threat_actor_if_not_exists(
                    'Unknown threats',
                    'All unknown threats are representing by this pseudo threat actors.'
                )['id']})

            # Create observable
            observable_id = self.opencti.create_stix_observable_if_not_exists(
                type,
                attribute['value'],
                attribute['comment']
            )['id']
            self.opencti.update_stix_observable_created_by_ref(observable_id, author_id)

            # Add observable to report
            self.opencti.add_object_ref_to_report_if_not_exists(report_id, observable_id)

            # Add threats to reports
            for threat in attribute_threats:
                self.opencti.add_object_ref_to_report_if_not_exists(report_id, threat['id'])

            # Add threats to observables
            for threat in event_threats:
                relation_id = self.opencti.create_relation_if_not_exists(
                    observable_id,
                    'Observable',
                    threat['id'],
                    threat['type'],
                    'indicates',
                    attribute['comment'],
                    datetime.utcfromtimestamp(int(attribute['timestamp'])).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    datetime.utcfromtimestamp(int(attribute['timestamp'])).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    2
                )['id']
                self.opencti.add_object_ref_to_report_if_not_exists(report_id, relation_id)
            for threat in attribute_threats:
                relation_id = self.opencti.create_relation_if_not_exists(
                    observable_id,
                    'Observable',
                    threat['id'],
                    threat['type'],
                    'indicates',
                    attribute['comment'],
                    datetime.utcfromtimestamp(int(attribute['timestamp'])).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    datetime.utcfromtimestamp(int(attribute['timestamp'])).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    2
                )['id']
                self.opencti.add_object_ref_to_report_if_not_exists(report_id, relation_id)

            # Add markings to observable
            if len(attribute_markings) > 0:
                for marking in attribute_markings:
                    self.opencti.add_marking_definition_if_not_exists(observable_id, marking)
                    self.opencti.add_marking_definition_if_not_exists(observable_id, marking)
            else:
                for marking in event_markings:
                    self.opencti.add_marking_definition_if_not_exists(observable_id, marking)

    def prepare_threats(self, galaxies):
        threats = []
        for galaxy in galaxies:
            if galaxy['name'] == 'Intrusion Set':
                for galaxy_entity in galaxy['GalaxyCluster']:
                    threats.append({'type': 'Intrusion-Set', 'id':
                        self.opencti.create_intrusion_set_if_not_exists(galaxy_entity['value'],
                                                                        galaxy_entity['description'])['id']})
        return threats

    def resolve_type(self, type):
        types = {
            'ip-src': 'IPv4-Addr',
            'ip-dst': 'IPv4-Addr',
            'domain': 'Domain',
            'hostname': 'Domain',
            'url': 'URL',
            'md5': 'File-MD5',
            'sha1': 'File-SHA1',
            'sha256': 'File-SHA256'
        }
        if type in types:
            return types[type]
        else:
            return None

    def resolve_markings(self, tags):
        markings = []
        for tag in tags:
            if tag['name'] == 'tlp:white':
                markings.append(self.opencti.get_marking_definition_by_definition('TLP', 'TLP:WHITE')['id'])
            if tag['name'] == 'tlp:green':
                markings.append(self.opencti.get_marking_definition_by_definition('TLP', 'TLP:GREEN')['id'])
            if tag['name'] == 'tlp:amber':
                markings.append(self.opencti.get_marking_definition_by_definition('TLP', 'TLP:AMBER')['id'])
            if tag['name'] == 'tlp:red':
                markings.append(self.opencti.get_marking_definition_by_definition('TLP', 'TLP:RED')['id'])
        return markings
