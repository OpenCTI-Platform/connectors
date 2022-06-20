import datetime
import os
import re
import sys
import time

import requests
import stix2
import yaml
from dateutil.parser import parse
from pycti import (
    Identity,
    Indicator,
    Malware,
    OpenCTIConnectorHelper,
    get_config_variable,
)
from requests.auth import HTTPBasicAuth


class Mandiant:
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
        self.mandiant_api_url = get_config_variable(
            "MANDIANT_API_URL", ["mandiant", "api_url"], config
        )
        self.mandiant_api_v4_key_id = get_config_variable(
            "MANDIANT_API_V4_KEY_ID", ["mandiant", "api_v4_key_id"], config
        )
        self.mandiant_api_v4_key_secret = get_config_variable(
            "MANDIANT_API_V4_KEY_SECRET", ["mandiant", "api_v4_key_secret"], config
        )
        self.mandiant_collections = get_config_variable(
            "MANDIANT_COLLECTIONS", ["mandiant", "collections"], config
        ).split(",")
        self.mandiant_threat_actor_as_intrusion_set = get_config_variable(
            "MANDIANT_THREAT_ACTOR_AS_INTRUSION_SET",
            ["mandiant", "threat_actor_as_intrusion_set"],
            config,
            False,
            True,
        )
        self.mandiant_import_start_date = get_config_variable(
            "MANDIANT_IMPORT_START_DATE",
            ["mandiant", "import_start_date"],
            config,
        )
        self.mandiant_interval = get_config_variable(
            "MANDIANT_INTERVAL", ["mandiant", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.added_after = int(parse(self.mandiant_import_start_date).timestamp())

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Mandiant",
            description="Mandiant is recognized by enterprises, governments and law enforcement agencies worldwide as the market leader in threat intelligence and expertise gained on the frontlines of cyber security. ",
        )

        self.marking = self.helper.api.marking_definition.create(
            definition_type="COMMERCIAL",
            definition="MANDIANT",
            x_opencti_order=99,
            x_opencti_color="#a01526",
        )

        # Init variables
        self.auth_token = None
        self._get_token()
        self.cache = {}

    def get_interval(self):
        return int(self.mandiant_interval) * 60

    def _get_token(self):
        headers = {
            "accept": "application/json",
            "x-app-name": "opencti-connector-5.3.7",
        }
        r = requests.post(
            self.mandiant_api_url + "/token",
            auth=HTTPBasicAuth(
                self.mandiant_api_v4_key_id, self.mandiant_api_v4_key_secret
            ),
            data={"grant_type": "client_credentials"},
            headers=headers,
        )
        if r.status_code != 200:
            raise ValueError("Mandiant Authentication failed")
        data = r.json()
        self.auth_token = data.get("access_token")

    def _redacted_as_none(self, key, object):
        if key not in object or object[key] == "redacted":
            return None
        return object[key]

    def _query(
        self,
        url,
        limit=None,
        offset=None,
        start_epoch=None,
        end_epoch=None,
        retry=False,
    ):
        headers = {
            "authorization": "Bearer " + self.auth_token,
            "accept": "application/json",
            "x-app-name": "opencti-connector-5.3.7",
        }
        params = {}
        if limit is not None:
            params["limit"] = str(limit)
        if offset is not None:
            params["offset"] = str(offset)
        if start_epoch is not None:
            params["start_epoch"] = str(int(start_epoch))
        if end_epoch is not None:
            params["end_epoch"] = str(int(end_epoch))

        r = requests.get(url, params=params, headers=headers)
        if r.status_code == 200:
            return r.json()
        elif (r.status_code == 401 or r.status_code == 403) and not retry:
            self._get_token()
            return self._query(url, limit, offset, start_epoch, end_epoch, True)
        elif r.status_code == 401 or r.status_code == 403:
            raise ValueError("Query failed, permission denied")
        else:
            result = r.json()
            if result and "error" in result:
                if "future" in result["error"]:
                    return None
            raise ValueError("An unknown error occurred")

    def _import_actor(self, work_id, current_state):
        url = self.mandiant_api_url + "/v4/actor"
        no_more_result = False
        limit = 30
        offset = current_state["actor"]
        while no_more_result is False:
            self.helper.log_info(
                "Iterating with limit=" + str(limit) + " and offset=" + str(offset)
            )
            result = self._query(url, limit, offset)
            if result is not None and len(result["threat-actors"]) > 0:
                actors = []
                for actor in result["threat-actors"]:
                    try:
                        if self.mandiant_threat_actor_as_intrusion_set:
                            stix_actor = stix2.IntrusionSet(
                                id=actor["id"].replace("threat-actor", "intrusion-set"),
                                name=self._redacted_as_none("name", actor),
                                description=self._redacted_as_none(
                                    "description", actor
                                ),
                                modified=self._redacted_as_none("last_updated", actor),
                                aliases=self._redacted_as_none("aliases", actor),
                                confidence=self.helper.connect_confidence_level,
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[
                                    stix2.TLP_AMBER.get("id"),
                                    self.marking["standard_id"],
                                ],
                            )
                        else:
                            stix_actor = stix2.ThreatActor(
                                id=actor["id"],
                                name=self._redacted_as_none("name", actor),
                                description=self._redacted_as_none(
                                    "description", actor
                                ),
                                modified=self._redacted_as_none("last_updated", actor),
                                aliases=self._redacted_as_none("aliases", actor),
                                confidence=self.helper.connect_confidence_level,
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[
                                    stix2.TLP_AMBER.get("id"),
                                    self.marking["standard_id"],
                                ],
                            )
                        actors.append(stix_actor)
                    except Exception as e:
                        self.helper.log_error(str(e))
                self.helper.send_stix2_bundle(
                    stix2.Bundle(
                        objects=actors,
                        allow_custom=True,
                    ).serialize(),
                    update=self.update_existing_data,
                    work_id=work_id,
                )
                offset = offset + limit
                current_state["actor"] = offset
                self.helper.set_state(current_state)
            else:
                no_more_result = True
        return current_state

    def _import_malware(self, work_id, current_state):
        url = self.mandiant_api_url + "/v4/malware"
        no_more_result = False
        limit = 10
        offset = current_state["malware"]
        while no_more_result is False:
            self.helper.log_info(
                "Iterating with limit=" + str(limit) + " and offset=" + str(offset)
            )
            result = self._query(url, limit, offset)
            if result is not None and len(result["malware"]) > 0:
                malwares = []
                for malware in result["malware"]:
                    try:
                        stix_malware = stix2.Malware(
                            id=malware["id"],
                            is_family=True,
                            name=self._redacted_as_none("name", malware),
                            description=self._redacted_as_none("description", malware),
                            modified=self._redacted_as_none("last_updated", malware),
                            aliases=self._redacted_as_none("aliases", malware),
                            confidence=self.helper.connect_confidence_level,
                            created_by_ref=self.identity["standard_id"],
                            object_marking_refs=[
                                stix2.TLP_AMBER.get("id"),
                                self.marking["standard_id"],
                            ],
                        )
                        malwares.append(stix_malware)
                    except Exception as e:
                        self.helper.log_error(str(e))
                self.helper.send_stix2_bundle(
                    stix2.Bundle(
                        objects=malwares,
                        allow_custom=True,
                    ).serialize(),
                    update=self.update_existing_data,
                    work_id=work_id,
                )
                offset = offset + limit
                current_state["malware"] = offset
                self.helper.set_state(current_state)
            else:
                no_more_result = True
        return current_state

    def _import_vulnerability(self, work_id, current_state):
        url = self.mandiant_api_url + "/v4/vulnerability"
        no_more_result = False
        limit = 1000
        start_epoch = current_state["vulnerability"]
        end_epoch = start_epoch + 3600
        while no_more_result is False:
            self.helper.log_info(
                "Iterating with start_epoch="
                + str(start_epoch)
                + ", end_epoch="
                + str(end_epoch)
            )
            result = self._query(url, limit, None, start_epoch, end_epoch)
            if result is not None and len(result["vulnerability"]) > 0:
                vulnerabilities = []
                for vulnerability in result["vulnerability"]:
                    try:
                        custom_properties = {}
                        if (
                            "common_vulnerability_scores" in vulnerability
                            and "v3.1" in vulnerability["common_vulnerability_scores"]
                        ):
                            score = vulnerability["common_vulnerability_scores"]["v3.1"]
                            custom_properties = {
                                "x_opencti_base_score": self._redacted_as_none(
                                    "base_score", score
                                ),
                                "x_opencti_attack_vector": self._redacted_as_none(
                                    "attack_vector", score
                                ),
                                "x_opencti_integrity_impact": self._redacted_as_none(
                                    "integrity_impact", score
                                ),
                                "x_opencti_availability_impact": self._redacted_as_none(
                                    "availability_impact", score
                                ),
                                "x_opencti_confidentiality_impact": self._redacted_as_none(
                                    "confidentiality_impact", score
                                ),
                            }
                        stix_vulnerability = stix2.Vulnerability(
                            id=vulnerability["id"],
                            name=self._redacted_as_none("cve_id", vulnerability),
                            description=self._redacted_as_none(
                                "description", vulnerability
                            ),
                            created=self._redacted_as_none(
                                "publish_date", vulnerability
                            ),
                            confidence=self.helper.connect_confidence_level,
                            created_by_ref=self.identity["standard_id"],
                            object_marking_refs=[
                                stix2.TLP_AMBER.get("id"),
                                self.marking["standard_id"],
                            ],
                            allow_custom=True,
                            custom_properties=custom_properties,
                        )
                        vulnerabilities.append(stix_vulnerability)
                    except Exception as e:
                        self.helper.log_error(str(e))
                self.helper.send_stix2_bundle(
                    stix2.Bundle(
                        objects=vulnerabilities,
                        allow_custom=True,
                    ).serialize(),
                    update=self.update_existing_data,
                    work_id=work_id,
                )
            elif end_epoch > int(time.time()):
                no_more_result = True
            start_epoch = end_epoch
            end_epoch = start_epoch + 3600
            current_state["vulnerability"] = int(start_epoch)
            self.helper.set_state(current_state)
        return current_state

    def _import_indicator(self, work_id, current_state):
        url = self.mandiant_api_url + "/v4/indicator"
        no_more_result = False
        limit = 1000
        start_epoch = current_state["indicator"]
        end_epoch = start_epoch + 3600
        while no_more_result is False:
            self.helper.log_info(
                "Iterating with start_epoch="
                + str(start_epoch)
                + ", end_epoch="
                + str(end_epoch)
            )
            result = self._query(url, limit, None, start_epoch, end_epoch)
            if result is not None and len(result["indicators"]) > 0:
                indicators = []
                for indicator in result["indicators"]:
                    try:
                        pattern = None
                        type = None
                        if indicator["type"] == "ipv4":
                            pattern = "[ipv4-addr:value = '" + indicator["value"] + "']"
                            type = "IPv4-Addr"
                        elif indicator["type"] == "ipv6":
                            pattern = "[ipv6-addr:value = '" + indicator["value"] + "']"
                            type = "IPv6-Addr"
                        elif indicator["type"] == "fqdn":
                            pattern = (
                                "[domain-name:value = '" + indicator["value"] + "']"
                            )
                            type = "Domain-Name"
                        elif indicator["type"] == "url":
                            pattern = "[url:value = '" + indicator["value"] + "']"
                            type = "Url"
                        elif indicator["type"] == "md5":
                            pattern = "[file:hashes.MD5 = '" + indicator["value"] + "']"
                            type = "File"
                        elif indicator["type"] == "sha1":
                            pattern = (
                                "[file:hashes.SHA-1 = '" + indicator["value"] + "']"
                            )
                            type = "File"
                        elif indicator["type"] == "sha-256":
                            pattern = (
                                "[file:hashes.SHA-256 = '" + indicator["value"] + "']"
                            )
                            type = "File"
                        if pattern is not None:
                            stix_indicator = stix2.Indicator(
                                id=Indicator.generate_id(pattern),
                                pattern=pattern,
                                pattern_type="stix",
                                allow_custom=True,
                                name=self._redacted_as_none("value", indicator)
                                if self._redacted_as_none("value", indicator)
                                is not None
                                else pattern,
                                description=self._redacted_as_none(
                                    "description", indicator
                                ),
                                created=self._redacted_as_none("first_seen", indicator),
                                modified=self._redacted_as_none(
                                    "last_updated", indicator
                                ),
                                confidence=self.helper.connect_confidence_level,
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[
                                    stix2.TLP_AMBER.get("id"),
                                    self.marking["standard_id"],
                                ],
                                custom_properties={
                                    "x_opencti_main_observable_type": type,
                                    "x_opencti_create_observables": True,
                                },
                            )
                            indicators.append(stix_indicator)
                    except Exception as e:
                        self.helper.log_error(str(e))
                self.helper.send_stix2_bundle(
                    stix2.Bundle(
                        objects=indicators,
                        allow_custom=True,
                    ).serialize(),
                    update=self.update_existing_data,
                    work_id=work_id,
                )
            elif end_epoch > int(time.time()):
                no_more_result = True
            start_epoch = end_epoch
            end_epoch = start_epoch + 3600
            current_state["indicator"] = int(start_epoch)
            self.helper.set_state(current_state)
        return current_state

    def _import_report(self, work_id, current_state):
        url = self.mandiant_api_url + "/v4/reports"
        no_more_result = False
        limit = 1000
        start_epoch = current_state["report"]
        end_epoch = start_epoch + 3600
        while no_more_result is False:
            self.helper.log_info(
                "Iterating with start_epoch="
                + str(start_epoch)
                + ", end_epoch="
                + str(end_epoch)
            )
            result = self._query(url, limit, None, start_epoch, end_epoch)
            if result is not None and len(result["objects"]) > 0:
                objects = []
                for report in result["objects"]:
                    url_report = self.mandiant_api_url + "/v4/reports/" + report["id"]
                    result_report = self._query(url_report)
                    if result_report is not None and "id" in result_report:
                        malwares = []
                        if "malware_families" in result_report:
                            for malware in result_report["malware_families"]:
                                stix_malware = stix2.Malware(
                                    id=Malware.generate_id(malware["name"]),
                                    name=malware["name"],
                                )
                                malwares.append(stix_malware)
                                objects.append(stix_malware)
                        affected_industries = []
                        if "affected_industries" in result_report:
                            for industry in result_report["affected_industries"]:
                                stix_identity = stix2.Identity(
                                    id=Identity.generate_id(industry, "class"),
                                    name=industry,
                                    identity_class="class",
                                )
                                affected_industries.append(stix_identity)
                                objects.append(stix_identity)
                        report_objects = malwares + affected_industries
                        stix_report = stix2.Report(
                            id=report["id"],
                            name=self._redacted_as_none("title", result_report),
                            report_types=[
                                self._redacted_as_none("report_type", result_report)
                            ]
                            if self._redacted_as_none("report_type", result_report)
                            is not None
                            else [],
                            description=re.sub(
                                "<[^<]+?>",
                                "",
                                self._redacted_as_none(
                                    "executive_summary", result_report
                                ),
                            )
                            if self._redacted_as_none(
                                "executive_summary", result_report
                            )
                            is not None
                            else "No description",
                            created=datetime.datetime.fromtimestamp(
                                self._redacted_as_none("publish_date", report)
                            ).isoformat(),
                            confidence=self.helper.connect_confidence_level,
                            created_by_ref=self.identity["standard_id"],
                            object_marking_refs=[
                                stix2.TLP_AMBER.get("id"),
                                self.marking["standard_id"],
                            ],
                            objects=report_objects,
                        )
                        objects.append(stix_report)
                self.helper.send_stix2_bundle(
                    stix2.Bundle(
                        objects=objects,
                        allow_custom=True,
                    ).serialize(),
                    update=self.update_existing_data,
                    work_id=work_id,
                )
            elif end_epoch > int(time.time()):
                no_more_result = True
            start_epoch = end_epoch
            end_epoch = start_epoch + 3600
            current_state["report"] = int(start_epoch)
            self.helper.set_state(current_state)
        return current_state

    def run(self):
        while True:
            try:
                self.helper.log_info("Synchronizing with Mandiant API...")
                timestamp = int(time.time())
                now = datetime.datetime.utcfromtimestamp(timestamp)
                friendly_name = "Mandiant run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                current_state = self.helper.get_state()
                if current_state is None:
                    self.helper.set_state(
                        {
                            "actor": 0,
                            "malware": 0,
                            "vulnerability": self.added_after,
                            "indicator": self.added_after,
                            "report": 0,
                        }
                    )

                if "actor" in self.mandiant_collections:
                    current_state = self.helper.get_state()
                    self.helper.log_info(
                        "Get ACTOR after position " + str(current_state["actor"])
                    )
                    new_state = self._import_actor(work_id, current_state)
                    self.helper.log_info("Setting new state " + str(new_state))
                    self.helper.set_state(new_state)
                if "malware" in self.mandiant_collections:
                    current_state = self.helper.get_state()
                    self.helper.log_info(
                        "Get MALWARE after position " + str(current_state["malware"])
                    )
                    new_state = self._import_malware(work_id, current_state)
                    self.helper.log_info("Setting new state " + str(new_state))
                    self.helper.set_state(new_state)
                if "vulnerability" in self.mandiant_collections:
                    current_state = self.helper.get_state()
                    self.helper.log_info(
                        "Get VULNERABILITY after position "
                        + str(current_state["vulnerability"])
                    )
                    new_state = self._import_vulnerability(work_id, current_state)
                    self.helper.log_info("Setting new state " + str(new_state))
                    self.helper.set_state(new_state)
                if "indicator" in self.mandiant_collections:
                    current_state = self.helper.get_state()
                    self.helper.log_info(
                        "Get INDICATOR after position "
                        + str(current_state["indicator"])
                    )
                    new_state = self._import_indicator(work_id, current_state)
                    self.helper.set_state(new_state)
                if "report" in self.mandiant_collections:
                    current_state = self.helper.get_state()
                    self.helper.log_info(
                        "Get REPORT after position " + str(current_state["report"])
                    )
                    new_state = self._import_report(work_id, current_state)
                    self.helper.set_state(new_state)

                message = "End of synchronization"
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)
                time.sleep(self.get_interval())
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        mandiantConnector = Mandiant()
        mandiantConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
