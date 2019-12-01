import os
import yaml
import time

from datetime import datetime
from dateutil.parser import parse
from pymisp import ExpandedPyMISP
from stix2 import Bundle, Identity, ThreatActor, IntrusionSet, Malware, Tool, Report, Indicator, Relationship, \
    ExternalReference, TLP_WHITE, TLP_GREEN, \
    TLP_AMBER, TLP_RED

from pycti import OpenCTIConnectorHelper


class Misp:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader) if os.path.isfile(config_file_path) else {}
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.misp_url = os.getenv('MISP_URL') or config.get('misp', {}).get('url')
        self.misp_key = os.getenv('MISP_KEY') or config.get('misp', {}).get('key')
        self.misp_tag = os.getenv('MISP_TAG') or config.get('misp', {}).get('tag')
        self.misp_untag_event = os.getenv('MISP_UNTAG_EVENT') or config.get('misp', {}).get('untag_event')
        self.misp_imported_tag = os.getenv('MISP_IMPORTED_TAG') or config.get('misp', {}).get('imported_tag')
        self.misp_filter_on_imported_tag = os.getenv('MISP_FILTER_ON_IMPORTED_TAG') or config.get('misp', {}).get('filter_on_imported_tag')
        self.misp_interval = os.getenv('MISP_INTERVAL') or config.get('misp', {}).get('interval')

        # Initialize MISP
        self.misp = ExpandedPyMISP(url=self.misp_url, key=self.misp_key, ssl=False, debug=False)


    def get_interval(self):
        return int(self.misp_interval) * 60

    def run(self):
        self.helper.log_info('Fetching MISP events...')
        while True:
            try:
                and_parameters = None
                not_parameters = None
                if self.misp_tag is not None:
                    and_parameters = [self.misp_tag]
                if self.misp_filter_on_imported_tag:
                    not_parameters = [self.misp_imported_tag]
                complex_query = self.misp.build_complex_query(and_parameters=and_parameters, not_parameters=not_parameters)
                events = self.misp.search('events', tags=complex_query)
                self.process_events(events)
                time.sleep(self.get_interval())
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info('Connector stop')
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(self.get_interval())

    def process_events(self, events):
        for event in events:
            generic_actor = ThreatActor(
                name='Unknown threats',
                labels=['threat-actor'],
                description='All unknown threats are represented by this pseudo threat actor. This entity helps to organize knowledge and indicators that could not be attributed to any other threats.'
            )
            added_threats = []
            added_markings = []
            # Default values
            author = Identity(name=event['Event']['Orgc']['name'], identity_class='organization')
            report_threats = self.prepare_threats(event['Event']['Galaxy'])
            if 'Tag' in event['Event']:
                report_markings = self.resolve_markings(event['Event']['Tag'])
            else:
                report_markings = []
            reference_misp = ExternalReference(
                source_name=self.helper.connect_name,
                url=self.misp_url + '/events/view/' + event['Event']['uuid'])

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
                if report_marking['id'] not in added_markings:
                    bundle_objects.append(report_marking)
                    added_markings.append(report_marking['id'])

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
                for marking in indicator['markings']:
                    if marking['id'] not in added_markings:
                        bundle_objects.append(marking)
                        added_markings.append(marking['id'])
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
                self.helper.send_stix2_bundle(bundle)

            if self.misp_untag_event:
                self.misp.untag(event['Event']['uuid'], self.misp_tag)
            self.misp.tag(event['Event']['uuid'], self.misp_imported_tag)

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
                            'x_opencti_weight': self.helper.connect_confidence_level
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
                            'x_opencti_weight': self.helper.connect_confidence_level
                        }
                    )
                )
            return {'indicator': indicator, 'relationships': relationships, 'attribute_threats': attribute_threats, 'markings': attribute_markings}

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
    mispConnector = Misp()
    mispConnector.run()
