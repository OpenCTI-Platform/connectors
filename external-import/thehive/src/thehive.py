import os
import sys
import time
import traceback
from datetime import datetime

import stix2
import yaml
from dateutil.parser import parse
from pycti import (
    CaseIncident,
    CustomObjectCaseIncident,
    CustomObjectTask,
    CustomObservableHostname,
    CustomObservableText,
    CustomObservableUserAgent,
    Incident,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    StixSightingRelationship,
    Task,
    get_config_variable,
)
from stix2 import (
    URL,
    AutonomousSystem,
    DomainName,
    EmailMessage,
    File,
    IPv4Address,
    WindowsRegistryKey,
)
from thehive4py.api import TheHiveApi
from thehive4py.query import Child, Gt, Or

OBSERVABLES_MAPPING = {
    "autonomous-system": "Autonomous-System.number",
    "domain": "Domain-Name.value",
    "file": None,
    "file_md5": "File.hashes.MD5",
    "file_sha1": "File.hashes.SHA-1",
    "file_sha256": "File.hashes.SHA-256",
    "filename": "File.name",
    "fqdn": "Hostname.value",
    "hostname": "Hostname.value",
    "hash": None,
    "ip": "IPv4-Addr.value",
    "mail": "Email-Message.body",
    "mail-subject": "Email-Message.subject",
    "other": "Text.value",
    "regexp": "Text.value",
    "registry": "Windows-Registry-Key.key",
    "uri_path": "Text.value",
    "url": "Url.value",
    "user-agent": "User-Agent.value",
}


class TheHive:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.thehive_url = get_config_variable(
            "THEHIVE_URL", ["thehive", "url"], config
        )
        self.thehive_api_key = get_config_variable(
            "THEHIVE_API_KEY", ["thehive", "api_key"], config
        )
        self.thehive_check_ssl = get_config_variable(
            "THEHIVE_CHECK_SSL", ["thehive", "check_ssl"], config, False, True
        )
        self.thehive_organization_name = get_config_variable(
            "THEHIVE_ORGANIZATION_NAME", ["thehive", "organization_name"], config
        )
        self.thehive_import_from_date = get_config_variable(
            "THEHIVE_IMPORT_FROM_DATE",
            ["thehive", "import_from_date"],
            config,
            False,
            datetime.utcfromtimestamp(int(time.time())).strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.thehive_import_only_tlp = get_config_variable(
            "THEHIVE_IMPORT_ONLY_TLP",
            ["thehive", "import_only_tlp"],
            config,
            False,
            "0,1,2,3,4",
        ).split(",")
        self.thehive_import_alerts = get_config_variable(
            "THEHIVE_IMPORT_ALERTS", ["thehive", "import_alerts"], config, False, True
        )
        self.thehive_severity_mapping = get_config_variable(
            "THEHIVE_SEVERITY_MAPPING",
            ["thehive", "severity_mapping"],
            config,
            False,
            "1:01 - low,2:02 - medium,3:03 - high,4:04 - critical",
        ).split(",")
        self.thehive_status_mapping = get_config_variable(
            "THEHIVE_STATUS_MAPPING", ["thehive", "status_mapping"], config, False, ""
        ).split(",")
        self.thehive_interval = get_config_variable(
            "THEHIVE_INTERVAL", ["thehive", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name=self.thehive_organization_name,
            description=self.thehive_organization_name,
        )
        self.severity_mapping = {}
        for mapping in self.thehive_severity_mapping:
            self.severity_mapping[int(mapping.split(":")[0])] = mapping.split(":")[1]
        self.thehive_api = TheHiveApi(
            self.thehive_url, self.thehive_api_key, cert=self.thehive_check_ssl
        )

    def convert_observable(self, observable, markings):
        stix_observable = None
        if observable["dataType"] == "hash":
            if len(observable["data"]) == 32:
                data_type = "file_md5"
            elif len(observable["data"]) == 40:
                data_type = "file_sha1"
            elif len(observable["data"]) == 64:
                data_type = "file_sha256"
            else:
                data_type = "unknown"
        else:
            data_type = observable["dataType"]
        observable_key = (
            OBSERVABLES_MAPPING[data_type] if data_type in OBSERVABLES_MAPPING else None
        )
        if observable_key is not None:
            if data_type == "autonomous-system":
                stix_observable = AutonomousSystem(
                    number=observable["data"],
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else None,
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "domain":
                stix_observable = DomainName(
                    value=observable["data"],
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else None,
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "file_md5":
                stix_observable = File(
                    hashes={"MD5": observable["data"]},
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else None,
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "file_sha1":
                stix_observable = File(
                    hashes={"SHA-1": observable["data"]},
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else None,
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "file_sha256":
                stix_observable = File(
                    hashes={"SHA-256": observable["data"]},
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else "Imported from TheHive",
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "filename":
                stix_observable = File(
                    name=observable["data"],
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else "Imported from TheHive",
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "fqdn":
                stix_observable = CustomObservableHostname(
                    value=observable["data"],
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else "Imported from TheHive",
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "hostname":
                stix_observable = CustomObservableHostname(
                    value=observable["data"],
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else "Imported from TheHive",
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "ip":
                stix_observable = IPv4Address(
                    value=observable["data"],
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else "Imported from TheHive",
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "mail":
                stix_observable = EmailMessage(
                    body=observable["data"],
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else "Imported from TheHive",
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "mail_subject":
                stix_observable = EmailMessage(
                    subject=observable["data"],
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else "Imported from TheHive",
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "other":
                stix_observable = CustomObservableText(
                    value=observable["data"],
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else "Imported from TheHive",
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "regexp":
                stix_observable = CustomObservableText(
                    value=observable["data"],
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else "Imported from TheHive",
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "registry":
                stix_observable = WindowsRegistryKey(
                    key=observable["data"],
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else "Imported from TheHive",
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "uri_path":
                stix_observable = URL(
                    value=observable["data"],
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else "Imported from TheHive",
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "url":
                stix_observable = URL(
                    value=observable["data"],
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else "Imported from TheHive",
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
            elif data_type == "user-agent":
                stix_observable = CustomObservableUserAgent(
                    value=observable["data"],
                    object_marking_refs=markings,
                    custom_properties={
                        "description": observable["message"]
                        if "message" in observable
                        else "Imported from TheHive",
                        "labels": observable["tags"] if "tags" in observable else [],
                        "x_opencti_score": 80 if observable["ioc"] else 50,
                        "created_by_ref": self.identity["standard_id"],
                        "x_opencti_create_indicator": observable["ioc"],
                    },
                )
        return stix_observable

    def generate_case_bundle(self, case):
        self.helper.log_info("Importing case '" + case["title"] + "'")
        case_objects = []
        bundle_objects = []
        markings = []
        if case["tlp"] == 0:
            markings.append(stix2.TLP_WHITE)
            bundle_objects.append(stix2.TLP_WHITE)
        elif case["tlp"] == 1:
            markings.append(stix2.TLP_GREEN)
            bundle_objects.append(stix2.TLP_GREEN)
        elif case["tlp"] == 2:
            markings.append(stix2.TLP_AMBER)
            bundle_objects.append(stix2.TLP_AMBER)
        elif case["tlp"] == 3:
            markings.append(stix2.TLP_RED)
            bundle_objects.append(stix2.TLP_RED)
        elif case["tlp"] == 4:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            )
            markings.append(marking)
            bundle_objects.append(marking)
        else:
            markings.append(stix2.TLP_WHITE)
            bundle_objects.append(stix2.TLP_WHITE)
        if case["pap"] == 0:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("PAP", "PAP:WHITE"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="PAP",
                x_opencti_definition="PAP:WHITE",
                x_opencti_color="#ffffff",
            )
            markings.append(marking)
            bundle_objects.append(marking)
        elif case["pap"] == 1:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("PAP", "PAP:GREEN"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="PAP",
                x_opencti_definition="PAP:GREEN",
                x_opencti_color="#2e7d32",
            )
            markings.append(marking)
            bundle_objects.append(marking)
        elif case["pap"] == 2:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("PAP", "PAP:AMBER"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="PAP",
                x_opencti_definition="PAP:AMBER",
                x_opencti_color="#d84315",
            )
            markings.append(marking)
            bundle_objects.append(marking)
        elif case["pap"] == 3:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("PAP", "PAP:RED"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="PAP",
                x_opencti_definition="PAP:RED",
                x_opencti_color="#c62828",
            )
            markings.append(marking)
            bundle_objects.append(marking)
        else:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("PAP", "PAP:WHITE"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="PAP",
                x_opencti_definition="PAP:WHITE",
                x_opencti_color="#ffffff",
            )
            markings.append(marking)
            bundle_objects.append(marking)

        # Get observables
        observables = self.thehive_api.get_case_observables(case_id=case["id"]).json()
        for observable in observables:
            stix_observable = self.convert_observable(observable, markings)
            if stix_observable is not None:
                case_objects.append(stix_observable.id)
                bundle_objects.append(stix_observable)
                if observable["sighted"]:
                    fake_indicator_id = (
                        "indicator--c1034564-a9fb-429b-a1c1-c80116cc8e1e"
                    )
                    stix_sighting = stix2.Sighting(
                        id=StixSightingRelationship.generate_id(
                            stix_observable.id,
                            self.identity["standard_id"],
                            datetime.utcfromtimestamp(
                                int(observable["startDate"] / 1000)
                            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            datetime.utcfromtimestamp(
                                int(observable["startDate"] / 1000 + 3600)
                            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        ),
                        confidence=int(self.helper.connect_confidence_level),
                        first_seen=datetime.utcfromtimestamp(
                            int(observable["startDate"] / 1000)
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        last_seen=datetime.utcfromtimestamp(
                            int(observable["startDate"] / 1000 + 3600)
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        where_sighted_refs=[self.identity["standard_id"]],
                        sighting_of_ref=fake_indicator_id,
                        custom_properties={
                            "x_opencti_sighting_of_ref": stix_observable.id
                        },
                    )
                    case_objects.append(self.identity["standard_id"])
                    case_objects.append(stix_sighting.id)
                    bundle_objects.append(stix_sighting)

        # Create case
        created = datetime.utcfromtimestamp(int(case["createdAt"] / 1000)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        opencti_status = None
        if len(self.thehive_status_mapping) > 0:
            for status_mapping in self.thehive_status_mapping:
                status_mapping_split = status_mapping.split(":")
                if case["extendedStatus"] == status_mapping_split[0]:
                    opencti_status = status_mapping_split[1]
        stix_case = CustomObjectCaseIncident(
            id=CaseIncident.generate_id(case["title"], created),
            name=case["title"],
            description=case["description"],
            created=created,
            object_marking_refs=markings,
            labels=case["tags"] if "tags" in case else [],
            created_by_ref=self.identity["standard_id"],
            severity=self.severity_mapping[case["severity"]]
            if case["severity"] in self.severity_mapping
            else None,
            confidence=int(self.helper.connect_confidence_level),
            object_refs=case_objects,
            x_opencti_workflow_id=opencti_status,
        )
        bundle_objects.append(stix_case)

        # Get tasks
        tasks = self.thehive_api.get_case_tasks(case_id=case["id"]).json()
        for task in tasks:
            created = datetime.utcfromtimestamp(int(task["createdAt"] / 1000)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            stix_task = CustomObjectTask(
                id=Task.generate_id(task["title"], created),
                name=task["title"],
                description=task["description"],
                created=created,
                due_date=datetime.utcfromtimestamp(
                    int(task["dueDate"] / 1000)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                if "dueDate" in task
                else None,
                confidence=int(self.helper.connect_confidence_level),
                object_refs=[stix_case.id],
            )
            bundle_objects.append(stix_task)

        bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
        return bundle

    def generate_alert_bundle(self, alert):
        self.helper.log_info("Importing alert '" + alert["title"] + "'")
        bundle_objects = []
        markings = []
        if alert["tlp"] == 0:
            markings.append(stix2.TLP_WHITE)
            bundle_objects.append(stix2.TLP_WHITE)
        elif alert["tlp"] == 1:
            markings.append(stix2.TLP_GREEN)
            bundle_objects.append(stix2.TLP_GREEN)
        elif alert["tlp"] == 2:
            markings.append(stix2.TLP_AMBER)
            bundle_objects.append(stix2.TLP_AMBER)
        elif alert["tlp"] == 3:
            markings.append(stix2.TLP_RED)
            bundle_objects.append(stix2.TLP_RED)
        elif alert["tlp"] == 4:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            )
            markings.append(marking)
            bundle_objects.append(marking)
        else:
            markings.append(stix2.TLP_WHITE)
            bundle_objects.append(stix2.TLP_WHITE)
        if alert["pap"] == 0:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("PAP", "PAP:WHITE"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="PAP",
                x_opencti_definition="PAP:WHITE",
            )
            markings.append(marking)
            bundle_objects.append(marking)
        elif alert["pap"] == 1:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("PAP", "PAP:GREEN"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="PAP",
                x_opencti_definition="PAP:GREEN",
            )
            markings.append(marking)
            bundle_objects.append(marking)
        elif alert["pap"] == 2:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("PAP", "PAP:AMBER"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="PAP",
                x_opencti_definition="PAP:AMBER",
            )
            markings.append(marking)
            bundle_objects.append(marking)
        elif alert["pap"] == 3:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("PAP", "PAP:RED"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="PAP",
                x_opencti_definition="PAP:RED",
            )
            markings.append(marking)
            bundle_objects.append(marking)
        else:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("PAP", "PAP:WHITE"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="PAP",
                x_opencti_definition="PAP:WHITE",
            )
            markings.append(marking)
            bundle_objects.append(marking)

        created = datetime.utcfromtimestamp(int(alert["createdAt"] / 1000)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        stix_incident = stix2.Incident(
            id=Incident.generate_id(alert["title"], created),
            name=alert["title"],
            description=alert["description"],
            object_marking_refs=markings,
            labels=alert["tags"] if "tags" in alert else [],
            created_by_ref=self.identity["standard_id"],
            confidence=int(self.helper.connect_confidence_level),
            allow_custom=True,
            custom_properties={
                "source": alert["source"],
                "severity": self.severity_mapping[alert["severity"]]
                if alert["severity"] in self.severity_mapping
                else None,
                "incident_type": "alert",
            },
        )
        bundle_objects.append(stix_incident)
        for observable in alert["artifacts"]:
            stix_observable = self.convert_observable(observable, markings)
            if stix_observable is not None:
                stix_observable_relation = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", stix_observable.id, stix_incident.id
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity["standard_id"],
                    source_ref=stix_observable.id,
                    target_ref=stix_incident.id,
                    confidence=int(self.helper.connect_confidence_level),
                    object_marking_refs=markings,
                    allow_custom=True,
                )
                bundle_objects.append(stix_observable)
                bundle_objects.append(stix_observable_relation)
        bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
        return bundle

    def get_interval(self):
        return int(self.thehive_interval) * 60

    def run(self):
        self.helper.log_info("Starting TheHive Connector...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_case_date" in current_state:
                    last_case_date = current_state["last_case_date"]
                    self.helper.log_info(
                        "Connector last_case_date: "
                        + datetime.utcfromtimestamp(last_case_date).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_case_date = parse(self.thehive_import_from_date).timestamp()
                    self.helper.log_info("Connector has no last_case_date")
                if current_state is not None and "last_alert_date" in current_state:
                    last_alert_date = current_state["last_alert_date"]
                    self.helper.log_info(
                        "Connector last_case_date: "
                        + datetime.utcfromtimestamp(last_case_date).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_alert_date = parse(self.thehive_import_from_date).timestamp()
                    self.helper.log_info("Connector has no last_alert_date")

                self.helper.log_info(
                    "Get cases since last run ("
                    + datetime.utcfromtimestamp(last_case_date).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    + ")"
                )
                query_cases = Or(
                    Gt("updatedAt", int(last_case_date * 1000)),
                    Gt("createdAt", int(last_case_date * 1000)),
                    Child("case_task", Gt("createdAt", int(last_case_date * 1000))),
                    Child("case_artifact", Gt("createdAt", int(last_case_date * 1000))),
                )
                cases = self.thehive_api.find_cases(
                    query=query_cases, sort="+updatedAt", range="0-10000"
                ).json()
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "TheHive run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                try:
                    for case in cases:
                        if str(case["tlp"]) in self.thehive_import_only_tlp:
                            stix_bundle = self.generate_case_bundle(case)
                            self.helper.send_stix2_bundle(
                                stix_bundle,
                                update=self.update_existing_data,
                                work_id=work_id,
                            )
                            last_case_date = (
                                (int(case["updatedAt"] / 1000) + 1)
                                if "updatedAt" in case and case["updatedAt"] is not None
                                else (int(case["createdAt"] / 1000) + 1)
                            )
                        else:
                            self.helper.log_info(
                                "Ignoring case '" + case["title"] + "' due TLP too high"
                            )
                except Exception:
                    error_msg = traceback.format_exc()
                    self.helper.log_error(error_msg)
                if self.thehive_import_alerts:
                    query_alerts = Or(
                        Gt("updatedAt", int(last_alert_date * 1000)),
                        Gt("createdAt", int(last_alert_date * 1000)),
                    )
                    alerts = self.thehive_api.find_alerts(
                        query=query_alerts, sort="+updatedAt", range="0-10000"
                    ).json()
                    try:
                        for alert in alerts:
                            if str(alert["tlp"]) in self.thehive_import_only_tlp:
                                stix_bundle = self.generate_alert_bundle(alert)
                                self.helper.send_stix2_bundle(
                                    stix_bundle,
                                    update=self.update_existing_data,
                                    work_id=work_id,
                                )
                                last_alert_date = (
                                    (int(alert["updatedAt"] / 1000) + 1)
                                    if "updatedAt" in alert
                                    and alert["updatedAt"] is not None
                                    else (int(alert["createdAt"] / 1000)) + 1
                                )
                            else:
                                self.helper.log_info(
                                    "Ignoring alert '"
                                    + alert["title"]
                                    + "' due TLP too high"
                                )
                    except Exception:
                        error_msg = traceback.format_exc()
                        self.helper.log_error(error_msg)

                # Store the current timestamp as a last run
                message = (
                    "Connector successfully run, storing last_case_date="
                    + str(last_case_date)
                    + ", last_alert_date="
                    + str(last_alert_date)
                )
                self.helper.log_info(message)
                self.helper.api.work.to_processed(work_id, message)
                current_state = self.helper.get_state()
                if current_state is None:
                    current_state = {
                        "last_case_date": last_case_date,
                        "last_alert_date": last_alert_date,
                    }
                else:
                    current_state["last_case_date"] = last_case_date
                    current_state["last_alert_date"] = last_alert_date
                self.helper.set_state(current_state)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                sys.exit(0)

            time.sleep(self.get_interval())


if __name__ == "__main__":
    try:
        theHiveConnector = TheHive()
        theHiveConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
