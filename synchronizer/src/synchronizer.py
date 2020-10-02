################################
# OpenCTI Synchronizer         #
################################

import os
import yaml
import json

from pycti import OpenCTIConnectorHelper, get_config_variable, StixCyberObservableTypes

STIX_META_RELATIONSHIPS = ["object_refs", "created_by_ref", "object_marking_refs"]


class SynchronizerConnector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.remote_opencti_url = get_config_variable(
            "REMOTE_OPENCTI_URL", ["remote_opencti", "url"], config
        )
        self.remote_opencti_token = get_config_variable(
            "REMOTE_OPENCTI_TOKEN", ["remote_opencti", "token"], config
        )
        self.remote_opencti_events = get_config_variable(
            "REMOTE_OPENCTI_EVENTS", ["remote_opencti", "events"], config
        ).split(",")

    def _add_object_marking_refs(self, entity_type, id, object_marking_refs):
        for object_marking_ref in object_marking_refs:
            if entity_type == "relationship":
                self.helper.api.stix_core_relationship.add_marking_definition(
                    id=id, marking_definition_id=object_marking_ref
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.helper.api.stix_cyber_observable.add_marking_definition(
                    id=id, marking_definition_id=object_marking_ref
                )
            else:
                self.helper.api.stix_domain_object.add_marking_definition(
                    id=id, marking_definition_id=object_marking_ref
                )

    def _remove_object_marking_refs(self, entity_type, id, object_marking_refs):
        for object_marking_ref in object_marking_refs:
            if entity_type == "relationship":
                self.helper.api.stix_core_relationship.remove_marking_definition(
                    id=id, marking_definition_id=object_marking_ref
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.helper.api.stix_cyber_observable.remove_marking_definition(
                    id=id, marking_definition_id=object_marking_ref
                )
            else:
                self.helper.api.stix_domain_object.remove_marking_definition(
                    id=id, marking_definition_id=object_marking_ref
                )

    def _add_object_refs(self, entity_type, id, object_refs):
        for object_ref in object_refs:
            if entity_type == "report":
                self.helper.api.report.add_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "note":
                self.helper.api.note.add_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "observed-data":
                self.helper.api.observed_data.add_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "opinion":
                self.helper.api.opinion.add_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )

    def _remove_object_refs(self, entity_type, id, object_refs):
        for object_ref in object_refs:
            if entity_type == "report":
                self.helper.api.report.remove_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "note":
                self.helper.api.note.remove_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "observed-data":
                self.helper.api.observed_data.remove_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "opinion":
                self.helper.api.opinion.remove_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )

    def _add_labels(self, entity_type, id, labels):
        for label in labels:
            if entity_type == "relationship":
                self.helper.api.stix_core_relationship.add_label(
                    id=id, label_name=label
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.helper.api.stix_cyber_observable.add_label(id=id, label_name=label)
            else:
                self.helper.api.stix_domain_object.add_label(id=id, label_name=label)

    def _remove_labels(self, entity_type, id, labels):
        for label in labels:
            if entity_type == "relationship":
                self.helper.api.stix_core_relationship.remove_label(
                    id=id, label_name=label
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.helper.api.stix_cyber_observable.remove_label(
                    id=id, label_name=label
                )
            else:
                self.helper.api.stix_domain_object.remove_label(id=id, label_name=label)

    def _update_attribute(self, entity_type, id, operation, key, value):
        if entity_type == "relationship":
            self.helper.api.stix_core_relationship.update_field(
                id=id, key=key, value=value, operation=operation
            )
        elif StixCyberObservableTypes.has_value(entity_type):
            self.helper.api.stix_cyber_observable.update_field(
                id=id, key=key, value=value, operation=operation
            )
        else:
            self.helper.api.stix_domain_object.update_field(
                id=id, key=key, value=value, operation=operation
            )

    def _replace_created_by_ref(self, entity_type, id, created_by_ref):
        if entity_type == "relationship":
            self.helper.api.stix_core_relationship.update_created_by(
                id=id, identity_id=created_by_ref
            )
        elif StixCyberObservableTypes.has_value(entity_type):
            self.helper.api.stix_cyber_observable.update_created_by(
                id=id, identity_id=created_by_ref
            )
        else:
            self.helper.api.stix_domain_object.update_created_by(
                id=id, identity_id=created_by_ref
            )

    def _process_message(self, msg):
        data = json.loads(msg.data)
        try:
            # Handle creation
            if "create" in self.remote_opencti_events and msg.event == "create":
                bundle = json.dumps({"objects": [data["data"]]})
                print(bundle)
                self.helper.send_stix2_bundle(bundle)
            elif "update" in self.remote_opencti_events and msg.event == "update":
                if "x_data_update" in data["data"]:
                    if "add" in data["data"]["x_data_update"]:
                        for key in data["data"]["x_data_update"]["add"].keys():
                            if key == "object_marking_refs":
                                self._add_object_marking_refs(
                                    data["data"]["type"],
                                    data["data"]["id"],
                                    data["data"]["x_data_update"]["add"][
                                        "object_marking_refs"
                                    ],
                                )
                            elif key == "object_refs":
                                self._add_object_refs(
                                    data["data"]["type"],
                                    data["data"]["id"],
                                    data["data"]["x_data_update"]["add"]["object_refs"],
                                )
                            elif key == "labels":
                                self._add_labels(
                                    data["data"]["type"],
                                    data["data"]["id"],
                                    data["data"]["x_data_update"]["add"]["labels"],
                                )

                            else:
                                self._update_attribute(
                                    data["data"]["type"],
                                    data["data"]["id"],
                                    "add",
                                    key,
                                    data["data"]["x_data_update"]["add"][key],
                                )
                    elif "remove" in data["data"]["x_data_update"]:
                        for key in data["data"]["x_data_update"]["remove"].keys():
                            if key == "object_marking_refs":
                                self._remove_object_marking_refs(
                                    data["data"]["type"],
                                    data["data"]["id"],
                                    data["data"]["x_data_update"]["remove"][
                                        "object_marking_refs"
                                    ],
                                )
                            elif key == "object_refs":
                                self._add_object_refs(
                                    data["data"]["type"],
                                    data["data"]["id"],
                                    data["data"]["x_data_update"]["remove"][
                                        "object_refs"
                                    ],
                                )
                            elif key == "labels":
                                self._remove_labels(
                                    data["data"]["type"],
                                    data["data"]["id"],
                                    data["data"]["x_data_update"]["remove"]["labels"],
                                )
                            else:
                                self._update_attribute(
                                    data["data"]["type"],
                                    data["data"]["id"],
                                    "remove",
                                    key,
                                    data["data"]["x_data_update"]["remove"][key],
                                )
                    elif "replace" in data["data"]["x_data_update"]:
                        for key in data["data"]["x_data_update"]["replace"].keys():
                            if key == "created_by_ref":
                                self._add_object_marking_refs(
                                    data["data"]["type"],
                                    data["data"]["id"],
                                    data["data"]["x_data_update"]["replace"][
                                        "created_by_ref"
                                    ],
                                )
                            else:
                                self._update_attribute(
                                    data["data"]["type"],
                                    data["data"]["id"],
                                    "replace",
                                    key,
                                    data["data"]["x_data_update"]["replace"][key],
                                )
                    else:
                        self.helper.log_error("Unsupported operation")
            elif "delete" in self.remote_opencti_events and msg.event == "delete":
                if data["data"]["type"] == "relationship":
                    self.helper.api.stix_core_relationship.delete(id=data["data"]["id"])
                elif StixCyberObservableTypes.has_value(data["data"]["type"]):
                    self.helper.api.stix_cyber_observable.delete(id=data["data"]["id"])
                else:
                    self.helper.api.stix_domain_object.delete(id=data["data"]["id"])
        except:
            pass

    def start(self):
        self.helper.listen_stream(
            self._process_message, self.remote_opencti_url, self.remote_opencti_token
        )


if __name__ == "__main__":
    SynchronizerInstance = SynchronizerConnector()
    SynchronizerInstance.start()
