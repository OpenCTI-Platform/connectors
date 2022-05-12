import os
import time
from datetime import datetime

import yaml
from dateutil.parser import parse
from pycti import (
    Incident,
    OpenCTIConnectorHelper,
    OpenCTIStix2Utils,
    SimpleObservable,
    get_config_variable,
)
from stix2 import (
    TLP_AMBER,
    TLP_GREEN,
    TLP_RED,
    TLP_WHITE,
    Bundle,
    Incident,
    Relationship,
    Sighting,
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
    "mail_subject": "Email-Message.subject",
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
        self.thehive_api = TheHiveApi(
            self.thehive_url, self.thehive_api_key, cert=self.thehive_check_ssl
        )

    def generate_case_bundle(self, case):
        markings = []
        if case["tlp"] == 0:
            markings.append(TLP_WHITE)
        if case["tlp"] == 1:
            markings.append(TLP_GREEN)
        if case["tlp"] == 2:
            markings.append(TLP_AMBER)
        if case["tlp"] == 3:
            markings.append(TLP_RED)
        if len(markings) == 0:
            markings.append(TLP_WHITE)
        bundle_objects = []
        incident = Incident(
            id=Incident.generate_id(case["title"]),
            name=case["title"],
            description=case["description"],
            object_marking_refs=markings,
            labels=case["tags"] if "tags" in case else [],
            created_by_ref=self.identity["standard_id"],
        )
        bundle_objects.append(incident)
        # Get observables
        observables = self.thehive_api.get_case_observables(case_id=case["id"]).json()
        for observable in observables:
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
            observable_key = OBSERVABLES_MAPPING[data_type]
            if observable_key is not None:
                stix_observable = SimpleObservable(
                    id=OpenCTIStix2Utils.generate_random_stix_id(
                        "x-opencti-simple-observable"
                    ),
                    key=observable_key,
                    value=observable["data"],
                    description=observable["message"],
                    x_opencti_score=80 if observable["ioc"] else 50,
                    object_marking_refs=markings,
                    labels=observable["tags"] if "tags" in observable else [],
                    created_by_ref=self.identity["standard_id"],
                    x_opencti_create_indicator=observable["ioc"],
                )
                stix_observable_relation = Relationship(
                    relationship_type="related-to",
                    created_by_ref=self.identity["standard_id"],
                    source_ref=stix_observable.id,
                    target_ref=incident.id,
                    object_marking_refs=markings,
                    allow_custom=True,
                )
                bundle_objects.append(stix_observable)
                bundle_objects.append(stix_observable_relation)
                if observable["sighted"]:
                    fake_indicator_id = (
                        "indicator--c1034564-a9fb-429b-a1c1-c80116cc8e1e"
                    )
                    stix_sighting = Sighting(
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
                    bundle_objects.append(stix_sighting)
        bundle = Bundle(objects=bundle_objects, allow_custom=True).serialize()
        return bundle

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

                self.helper.log_info(
                    "Get cases since last run ("
                    + datetime.utcfromtimestamp(last_case_date).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    + ")"
                )
                query = Or(
                    Gt("updatedAt", int(last_case_date * 1000)),
                    Child("case_task", Gt("createdAt", int(last_case_date * 1000))),
                    Child("case_artifact", Gt("createdAt", int(last_case_date * 1000))),
                )
                cases = self.thehive_api.find_cases(
                    query=query, sort="updatedAt", range="0-100"
                ).json()
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "TheHive run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                try:
                    for case in cases:
                        stix_bundle = self.generate_case_bundle(case)
                        self.helper.send_stix2_bundle(
                            stix_bundle,
                            update=self.update_existing_data,
                            work_id=work_id,
                        )
                except Exception as e:
                    self.helper.log_error(str(e))
                # Store the current timestamp as a last run
                message = "Connector successfully run, storing last_run as " + str(
                    timestamp
                )
                self.helper.log_info(message)
                self.helper.api.work.to_processed(work_id, message)
                current_state = self.helper.get_state()
                if current_state is None:
                    current_state = {"last_case_date": timestamp}
                else:
                    current_state["last_case_date"] = timestamp
                self.helper.set_state(current_state)
                time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        theHiveConnector = TheHive()
        theHiveConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
