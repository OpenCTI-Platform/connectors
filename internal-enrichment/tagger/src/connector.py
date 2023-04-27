import json
import re

from pycti import OpenCTIConnectorHelper, get_config_variable


def load_re_flags(rule):
    """Load the regular expression flags from a rule definition."""

    config = rule.get("flags") or []

    flags = 0
    for flag in config:
        flag = getattr(re, flag)
        flags |= flag

    return flags


class TaggerConnector:
    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})
        self.definitions = json.loads(get_config_variable("TAGGER_DEFINITIONS", []))

    def start(self):
        self.helper.listen(self._process_message)

    def _process_message(self, data):
        entity_id = data.get("entity_id")

        for definition in self.definitions:
            for scope in definition["scopes"]:
                entity_type = scope.lower()
                api = getattr(self.helper.api, entity_type)
                entity = api.read(id=entity_id)

                if not entity:
                    continue

                for rule in definition["rules"]:
                    flags = load_re_flags(rule)

                    for attribute in rule["attributes"]:
                        if not re.search(
                            rule["search"], entity[attribute], flags=flags
                        ):
                            continue

                        self.helper.api.stix_domain_object.add_label(
                            id=entity_id, label_name=rule["label"]
                        )
                        break


if __name__ == "__main__":
    connector = TaggerConnector()
    connector.start()
