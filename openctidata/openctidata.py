# coding: utf-8

import os
import json
import urllib.request
from pycti import OpenCTI


class Openctidata:
    def __init__(self, config, scheduler):
        # Initialize config
        self.config = config
        self.scheduler = scheduler

        # Initialize OpenCTI client
        self.opencti = OpenCTI(
            self.config['opencti']['api_url'],
            self.config['opencti']['api_key'],
            os.path.dirname(os.path.abspath(__file__)) + '/openctidata.log',
            True
        )

    def set_config(self, config):
        self.config = config

    def get_config(self):
        return self.config['openctidata']

    def run(self):
        if 'sector' in self.config['openctidata']['entities']:
            sectors_data = urllib.request.urlopen(self.config['openctidata']['sectors_file_url']).read()
            sectors = json.loads(sectors_data)
            for sector in sectors:
                sector_id = self.opencti.create_identity_if_not_exists('Sector', sector['name'], sector['description'], None, sector['stix_id'])['id']
                self.opencti.update_stix_domain_entity_field(sector_id, 'name', sector['name'])
                self.opencti.update_stix_domain_entity_field(sector_id, 'description', sector['description'])
                self.opencti.update_stix_domain_entity_field(sector_id, 'stix_id', sector['stix_id'])

                for subsector in sector['subsectors']:
                    subsector_id = self.opencti.create_identity_if_not_exists('Sector', subsector['name'], subsector['description'], None, subsector['stix_id'])['id']
                    self.opencti.update_stix_domain_entity_field(subsector_id, 'name', subsector['name'])
                    self.opencti.update_stix_domain_entity_field(subsector_id, 'description', subsector['description'])
                    self.opencti.update_stix_domain_entity_field(subsector_id, 'stix_id', subsector['stix_id'])

                    # Temporary for fixing multiple relations of previous version
                    old_relations = self.opencti.get_stix_relations(sector_id, subsector_id)
                    for old_relation in old_relations:
                        self.opencti.delete_relation(old_relation['id'])

                    self.opencti.create_relation_if_not_exists(
                        sector_id,
                        'sector',
                        subsector_id,
                        'sector',
                        'gathering',
                        'Subsector from OpenCTI connector',
                        '1900-01-01T00:00:00.000Z',
                        '1900-01-01T00:00:00.000Z',
                        5
                    )
