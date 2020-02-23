import yaml
import os
import requests
import json
import random

from pycti import OpenCTIConnectorHelper, get_config_variable


class VirusTotalConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.token = get_config_variable("VIRUSTOTAL_TOKEN", ["virustotal", "token"], config)
        self.max_tlp = get_config_variable(
            "VIRUSTOTAL_MAX_TLP", ["virustotal", "max_tlp"], config
        )
        self.api_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.token, "accept": "application/json", "content-type": "application/json"}

    def _process_file(self, observable):
        marking_definitions = observable['markingDefinitionsIds']
        created_by_ref_id = observable['createdByRef']['id'] if 'id' in observable['createdByRef'] else None
        response = requests.request("GET", self.api_url + '/files/' +  observable["observable_value"], headers=self.headers)
        json_data = json.loads(response.text)
        if 'error' in json_data:
            raise ValueError(json_data['error']['message'])
        if 'data' in json_data:
            data = json_data['data']
            attributes = data['attributes']
            created_observables = []
            # Create observables
            # MD5
            md5 = self.helper.api.stix_observable.create(
                type='File-MD5',
                observable_value=attributes['md5'],
                markingDefinitions=marking_definitions,
                createdByRef=created_by_ref_id
            )
            created_observables.append(md5['id'])
            # SHA1
            sha1 = self.helper.api.stix_observable.create(
                type='File-SHA1',
                observable_value=attributes['sha1'],
                markingDefinitions=marking_definitions,
                createdByRef=created_by_ref_id
            )
            created_observables.append(sha1['id'])
            # SHA256
            sha256 = self.helper.api.stix_observable.create(
                type='File-SHA256',
                observable_value=attributes['sha256'],
                markingDefinitions=marking_definitions,
                createdByRef=created_by_ref_id
            )
            created_observables.append(sha256['id'])
            # Names
            for name in attributes['names']:
                file_name = self.helper.api.stix_observable.create(
                    type='File-Name',
                    observable_value=name,
                    markingDefinitions=marking_definitions,
                    createdByRef=created_by_ref_id
                )
                created_observables.append(file_name['id'])
                self.helper.api.stix_observable_relation.create(
                    fromId=md5['id'],
                    fromType='File-MD5',
                    toId=file_name['id'],
                    toType='File-Name',
                    relationship_type='corresponds',
                    ignore_dates=True
                )
                self.helper.api.stix_observable_relation.create(
                    fromId=sha1['id'],
                    fromType='File-SHA1',
                    toId=file_name['id'],
                    toType='File-Name',
                    relationship_type='corresponds',
                    ignore_dates=True
                )
                self.helper.api.stix_observable_relation.create(
                    fromId=sha256['id'],
                    fromType='File-SHA256',
                    toId=file_name['id'],
                    toType='File-Name',
                    relationship_type='corresponds',
                    ignore_dates=True
                )

            # Create observables relation
            self.helper.api.stix_observable_relation.create(
                fromId=md5['id'],
                fromType='File-MD5',
                toId=sha1['id'],
                toType='File-SHA1',
                relationship_type='corresponds',
                ignore_dates=True
            )
            self.helper.api.stix_observable_relation.create(
                fromId=md5['id'],
                fromType='File-MD5',
                toId=sha256['id'],
                toType='File-SHA256',
                relationship_type='corresponds',
                ignore_dates=True
            )
            self.helper.api.stix_observable_relation.create(
                fromId=sha1['id'],
                fromType='File-SHA1',
                toId=sha256['id'],
                toType='File-SHA256',
                relationship_type='corresponds',
                ignore_dates=True
            )

            # Create external reference
            external_reference = self.helper.api.external_reference.create(
                source_name='VirusTotal',
                url='https://www.virustotal.com/gui/file/' + attributes['sha256'],
                description=attributes['magic']
            )

            # Create tags
            for tag in attributes['tags']:
                tag_vt = self.helper.api.tag.create(
                    tag_type='VirusTotal',
                    value=tag,
                    color="%06x" % random.randint(0, 0xFFFFFF)
                )
                for created_observable in created_observables:
                    self.helper.api.stix_entity.add_tag(
                        id=created_observable,
                        tag_id=tag_vt['id']
                    )

            for created_observable in created_observables:
                self.helper.api.stix_entity.add_external_reference(
                    id=created_observable,
                    external_reference_id=external_reference['id']
                )

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_observable.read(id=entity_id)
        # Extract TLP
        tlp = "TLP:WHITE"
        for marking_definition in observable["markingDefinitions"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError("Do not send any data, TLP of the observable is greater than MAX TLP")

        observable_type = observable["entity_type"]
        if 'file' in observable_type:
            self._process_file(observable)


    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    virusTotalInstance = VirusTotalConnector()
    virusTotalInstance.start()
