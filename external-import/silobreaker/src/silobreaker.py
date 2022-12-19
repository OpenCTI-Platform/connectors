import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime

import pytz
import stix2
import yaml
from dateutil.parser import parse
from pycti import (
    Identity,
    Incident,
    IntrusionSet,
    Location,
    Malware,
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
    Vulnerability,
    get_config_variable,
)


class Silobreaker:
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
        self.silobreaker_api_url = get_config_variable(
            "SILOBREAKER_API_URL", ["silobreaker", "api_url"], config
        )
        self.silobreaker_api_key = get_config_variable(
            "SILOBREAKER_API_KEY", ["silobreaker", "api_key"], config
        )
        self.silobreaker_api_shared = get_config_variable(
            "SILOBREAKER_API_SHARED", ["silobreaker", "api_shared"], config
        )
        self.silobreaker_import_start_date = get_config_variable(
            "SILOBREAKER_IMPORT_START_DATE",
            ["silobreaker", "import_start_date"],
            config,
        )
        self.silobreaker_interval = get_config_variable(
            "SILOBREAKER_INTERVAL", ["silobreaker", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        # self.added_after = int(parse(self.mandiant_import_start_date).timestamp())

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Silobreaker",
            description="Silobreaker helps security, business and intelligence professionals make sense of the overwhelming amount of data on the web.",
        )
        # Init variables
        self.auth_token = None
        self.cache = {}

    def get_interval(self):
        return int(self.silobreaker_interval) * 60

    def _query(self, method, url, body=None):
        if method == "POST":
            verb = "POST"
            urlSignature = verb + " " + url
            message = urlSignature.encode() + body
            hmac_sha1 = hmac.new(
                self.silobreaker_api_shared.encode(), message, digestmod=hashlib.sha1
            )
            digest = base64.b64encode(hmac_sha1.digest())
            final_url = (
                url
                + "?apiKey="
                + self.silobreaker_api_key
                + "&digest="
                + urllib.parse.quote(digest.decode())
            )
            req = urllib.request.Request(
                final_url, data=body, headers={"Content-Type": "application/json"}
            )
        else:
            verb = "GET"
            message = verb + " " + url
            hmac_sha1 = hmac.new(
                self.silobreaker_api_shared.encode(),
                message.encode(),
                digestmod=hashlib.sha1,
            )
            digest = base64.b64encode(hmac_sha1.digest())
            final_url = (
                url
                + "&apiKey="
                + self.silobreaker_api_key
                + "&digest="
                + urllib.parse.quote(digest.decode())
            )
            req = urllib.request.Request(final_url)
        with urllib.request.urlopen(req) as response:
            responseJson = response.read()
        return json.loads(responseJson.decode("utf-8"))

    def _import_documents(self, work_id, delta_days):
        url = (
            self.silobreaker_api_url
            + "/search/documents?q=list:threat%20publications%20AND%20entitytype:malware%20OR%20entitytype:threatactor%20fromdate:-"
            + str(delta_days)
            + "&extras=inmemevidence&pagesize=5000&includeEntities=True"
        )
        data = self._query("GET", url)
        if "Items" in data:
            for item in data["Items"]:
                if (
                    item["Type"] == "Report"
                    or item["Type"] == "News"
                    or item["Type"] == "User Article"
                ):
                    objects = []
                    threats = []
                    users = []
                    used = []
                    victims = []
                    entities = item["Extras"]["RelatedEntities"]["Items"]
                    for entity in entities:
                        if entity["Type"] == "ThreatActor":
                            actor_stix = stix2.IntrusionSet(
                                id=IntrusionSet.generate_id(entity["Description"]),
                                name=entity["Description"],
                                description=entity["Description"],
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_AMBER.get("id")],
                            )
                            objects.append(actor_stix)
                            threats.append(actor_stix)
                            users.append(actor_stix)
                        if entity["Type"] == "Malware":
                            malware_stix = stix2.Malware(
                                id=Malware.generate_id(entity["Description"]),
                                name=entity["Description"],
                                description=entity["Description"],
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_AMBER.get("id")],
                                is_family=True,
                            )
                            objects.append(malware_stix)
                            threats.append(malware_stix)
                            used.append(malware_stix)
                        if entity["Type"] == "Incident":
                            incident_stix = stix2.Incident(
                                id=Incident.generate_id(entity["Description"]),
                                name=entity["Description"],
                                description=entity["Description"],
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_AMBER.get("id")],
                            )
                            objects.append(incident_stix)
                            threats.append(incident_stix)
                            users.append(incident_stix)
                        if entity["Type"] == "Country":
                            country_stix = stix2.Location(
                                id=Location.generate_id(
                                    entity["Description"], "Country"
                                ),
                                name=entity["Description"],
                                description=entity["Description"],
                                country=entity["Description"],
                                created_by_ref=self.identity["standard_id"],
                                allow_custom=True,
                                custom_properties={
                                    "x_opencti_location_type": "Country"
                                },
                            )
                            objects.append(country_stix)
                            victims.append(country_stix)
                        if entity["Type"] == "City":
                            city_stix = stix2.Location(
                                id=Location.generate_id(entity["Description"], "City"),
                                name=entity["Description"],
                                description=entity["Description"],
                                country=entity["Description"],
                                created_by_ref=self.identity["standard_id"],
                                allow_custom=True,
                                custom_properties={"x_opencti_location_type": "City"},
                            )
                            objects.append(city_stix)
                            victims.append(city_stix)
                        if entity["Type"] == "Company":
                            organization_stix = stix2.Identity(
                                id=Identity.generate_id(
                                    entity["Description"], "organization"
                                ),
                                name=entity["Description"],
                                description=entity["Description"],
                                created_by_ref=self.identity["standard_id"],
                            )
                            objects.append(organization_stix)
                            victims.append(organization_stix)
                        if entity["Type"] == "Vulnerability":
                            vulnerability_stix = stix2.Vulnerability(
                                id=Vulnerability.generate_id(entity["Description"]),
                                name=entity["Description"],
                                description=entity["Description"],
                                created_by_ref=self.identity["standard_id"],
                            )
                            objects.append(vulnerability_stix)
                            victims.append(vulnerability_stix)
                    if len(threats) > 0 and len(victims) > 0:
                        for threat in threats:
                            for victim in victims:
                                relationship_stix = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "targets",
                                        threat.get("id"),
                                        victim.get("id"),
                                        item["PublicationDate"],
                                    ),
                                    relationship_type="targets",
                                    source_ref=threat.get("id"),
                                    target_ref=victim.get("id"),
                                    object_marking_refs=[stix2.TLP_AMBER.get("id")],
                                    created_by_ref=self.identity["standard_id"],
                                    start_time=item["PublicationDate"],
                                )
                                objects.append(relationship_stix)
                    if len(users) > 0 and len(used) > 0:
                        for user in users:
                            for use in used:
                                relationship_stix = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "uses",
                                        user.get("id"),
                                        use.get("id"),
                                        item["PublicationDate"],
                                    ),
                                    relationship_type="uses",
                                    source_ref=user.get("id"),
                                    target_ref=use.get("id"),
                                    object_marking_refs=[stix2.TLP_AMBER.get("id")],
                                    created_by_ref=self.identity["standard_id"],
                                    start_time=item["PublicationDate"],
                                )
                                objects.append(relationship_stix)
                    if len(objects) > 0:
                        report_stix = stix2.Report(
                            id=Report.generate_id(
                                item["Description"], item["PublicationDate"]
                            ),
                            name=item["Description"],
                            published=item["PublicationDate"],
                            created=item["PublicationDate"],
                            modified=item["PublicationDate"],
                            created_by_ref=self.identity["standard_id"],
                            object_marking_refs=[stix2.TLP_AMBER.get("id")],
                            object_refs=[object["id"] for object in objects],
                        )
                        objects.append(report_stix)
                        bundle = stix2.Bundle(
                            objects=objects,
                            allow_custom=True,
                        )
                        self.helper.send_stix2_bundle(
                            bundle.serialize(),
                            update=self.update_existing_data,
                            work_id=work_id,
                        )

    def run(self):
        while True:
            try:
                # Get the current timestamp and check
                current_state = self.helper.get_state()
                if current_state is None or "last_run" not in current_state:
                    self.helper.set_state(
                        {"last_run": self.silobreaker_import_start_date}
                    )
                    last_run = parse(self.silobreaker_import_start_date).astimezone(
                        pytz.UTC
                    )
                else:
                    last_run = parse(current_state["last_run"]).astimezone(pytz.UTC)
                now = datetime.now().astimezone(pytz.UTC)
                delta = now - last_run
                delta_days = delta.days
                self.helper.log_info(
                    str(delta_days) + " days to process since last run"
                )
                if delta_days < 1:
                    self.helper.log_info(
                        "Need at least one day to process, doing nothing"
                    )
                    return
                friendly_name = "Silobreaker run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                self.helper.log_info("Processing the last " + str(delta_days) + " days")
                self._import_documents(work_id, delta_days)
                last_run = now.astimezone(pytz.UTC).isoformat()
                message = "Connector successfully run, storing last_run as " + last_run
                self.helper.log_info(message)
                self.helper.set_state({"last_run": last_run})
                self.helper.api.work.to_processed(work_id, message)
                if self.helper.connect_run_and_terminate:
                    self.helper.log_info("Connector stop")
                    sys.exit(0)
                time.sleep(self.get_interval())
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)

            except Exception as e:
                self.helper.log_error(str(e))

                if self.helper.connect_run_and_terminate:
                    self.helper.log_info("Connector stop")
                    sys.exit(0)

                time.sleep(60)


if __name__ == "__main__":
    try:
        silobreakerConnector = Silobreaker()
        silobreakerConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
