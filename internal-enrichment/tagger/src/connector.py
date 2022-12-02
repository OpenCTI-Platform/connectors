import stix2
import json

from pycti import OpenCTIConnectorHelper
from pycti import get_config_variable


class TaggerConnector:

    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})
        self.definitions = json.loads(get_config_variable("TAGGER_DEFINITIONS", []))     

    def start(self):
        self.helper.listen(self._process_message)

    def _process_message(self, data):
        entity_id = data.get("entity_id")

        for definition in self.definitions:

            entity_type = definition["scope"].lower()
            api = getattr(self.helper.api, entity_type)
            entity = api.read(id=entity_id)

            if not entity:
                continue

            for rule in definition["rules"]:
                for attribute in rule["attributes"]:

                    # FIXME: improve search capability
                    if rule["search"] not in entity[attribute]:                   
                        continue

                    self.helper.api.stix_domain_object.add_label(
                        id=entity_id,
                        label_name=rule["label"]
                    )
                    break


if __name__ == "__main__":
    connector = TaggerConnector()
    connector.start()
