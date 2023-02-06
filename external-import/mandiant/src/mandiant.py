import base64
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
    Indicator,
    Note,
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
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
        self.mandiant_report_types_ignored = get_config_variable(
            "MANDIANT_REPORT_TYPES_IGNORED",
            ["mandiant", "report_types_ignored"],
            config,
        ).split(",")
        self.added_after = int(parse(self.mandiant_import_start_date).timestamp())

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Mandiant",
            description="Mandiant is recognized by enterprises, governments and law enforcement agencies worldwide as the market leader in threat intelligence and expertise gained on the frontlines of cyber security.",
        )
        # Init variables
        self.auth_token = None
        self._get_token()
        self.cache = {}

    def cleanhtml(self, raw_html):
        CLEANR = re.compile("<.*?>|&([a-z0-9]+|#[0-9]{1,6}|#x[0-9a-f]{1,6});")
        cleantext = re.sub(CLEANR, "", raw_html)
        return cleantext

    def get_interval(self):
        return int(self.mandiant_interval) * 60

    def _get_token(self):
        headers = {
            "accept": "application/json",
            "x-app-name": "opencti-connector-5.5.3",
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

    def _process_aliases(self, object):
        if "aliases" in object:
            aliases = []
            for alias in object["aliases"]:
                aliases.append(re.sub("[\(\[].*?[\)\]]", "", alias["name"]).strip())
            object["aliases"] = aliases
            return self._redacted_as_none("aliases", object)
        return None

    def _query(
        self,
        url,
        limit=None,
        offset=None,
        next=None,
        start_epoch=None,
        end_epoch=None,
        retry=False,
        app_header=None,
    ):
        if app_header is None:
            app_header = "application/json"

        headers = {
            "authorization": "Bearer " + self.auth_token,
            "accept": app_header,
            "x-app-name": "opencti-connector-5.5.3",
        }
        params = {}
        if limit is not None:
            params["limit"] = str(limit)
        if offset is not None:
            params["offset"] = str(offset)
        if next is not None:
            params["next"] = str(next)
        if start_epoch is not None:
            params["start_epoch"] = str(int(start_epoch))
        if end_epoch is not None:
            params["end_epoch"] = str(int(end_epoch))

        r = requests.get(url, params=params, headers=headers)
        if r.status_code == 200:
            return r.json()
        elif (r.status_code == 401 or r.status_code == 403) and not retry:
            self._get_token()
            return self._query(url, limit, offset, next, start_epoch, end_epoch, True)
        elif r.status_code == 401 or r.status_code == 403:
            raise ValueError("Query failed, permission denied")
        else:
            result = r.json()
            if result and "error" in result:
                if "future" in result["error"]:
                    return None
            raise ValueError("An unknown error occurred")

    def _getreportpdf(self, url, retry=False):
        headers = {
            "accept": "application/pdf",
            "x-app-name": "opencti-connector-5.5.3",
            "authorization": "Bearer " + self.auth_token,
        }
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            self.helper.log_info("Report PDF fetched successfully")
            return r.content
        elif (r.status_code == 401 or r.status_code == 403) and not retry:
            self._get_token()
            return self._getreportpdf(url, True)
        elif r.status_code == 401 or r.status_code == 403:
            raise ValueError("Query failed, permission denied")
        else:
            self.helper.log_info("An error has ocurred getting PDF report")

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
            if (
                result is not None
                and result["threat-actors"] is not None
                and len(result["threat-actors"]) > 0
            ):
                objects = []
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
                                aliases=self._process_aliases(actor),
                                confidence=self.helper.connect_confidence_level,
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_AMBER.get("id")],
                                allow_custom=True,
                            )
                        else:
                            stix_actor = stix2.ThreatActor(
                                id=actor["id"],
                                name=self._redacted_as_none("name", actor),
                                description=self._redacted_as_none(
                                    "description", actor
                                ),
                                modified=self._redacted_as_none("last_updated", actor),
                                aliases=self._process_aliases(actor),
                                confidence=self.helper.connect_confidence_level,
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_AMBER.get("id")],
                                allow_custom=True,
                            )
                        objects.append(stix_actor)
                        # Get the actor
                        result_actor = self._query(url + "/" + actor["id"])
                        if "industries" in result_actor:
                            for industry in result_actor["industries"]:
                                stix_identity = stix2.Identity(
                                    id=industry["id"],
                                    created_by_ref=self.identity["standard_id"],
                                    name=industry["name"],
                                    identity_class="class",
                                    allow_custom=True,
                                )
                                stix_relationship = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "targets",
                                        stix_actor.get("id"),
                                        stix_identity.get("id"),
                                        industry["first_seen"]
                                        if "first_seen" in industry
                                        else None,
                                        parse(industry["last_seen"])
                                        + datetime.timedelta(seconds=1)
                                        if "last_seen" in industry
                                        else None,
                                    ),
                                    relationship_type="targets",
                                    source_ref=stix_actor.get("id"),
                                    target_ref=stix_identity.get("id"),
                                    start_time=industry["first_seen"]
                                    if "first_seen" in industry
                                    else None,
                                    stop_time=parse(industry["last_seen"])
                                    + datetime.timedelta(seconds=1)
                                    if "last_seen" in industry
                                    else None,
                                    allow_custom=True,
                                    created_by_ref=self.identity["standard_id"],
                                )
                                objects.append(stix_identity)
                                objects.append(stix_relationship)
                        if "cve" in result_actor:
                            for cve in result_actor["cve"]:
                                stix_vulnerability = stix2.Vulnerability(
                                    id=cve["id"],
                                    created_by_ref=self.identity["standard_id"],
                                    name=cve["cve_id"],
                                    allow_custom=True,
                                )
                                stix_relationship = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "targets",
                                        stix_actor.get("id"),
                                        stix_vulnerability.get("id"),
                                        cve["first_seen"]
                                        if "first_seen" in cve
                                        else None,
                                        parse(cve["last_seen"])
                                        + datetime.timedelta(seconds=1)
                                        if "last_seen" in cve
                                        else None,
                                    ),
                                    relationship_type="targets",
                                    source_ref=stix_actor.get("id"),
                                    target_ref=stix_vulnerability.get("id"),
                                    start_time=cve["first_seen"]
                                    if "first_seen" in cve
                                    else None,
                                    stop_time=parse(cve["last_seen"])
                                    + datetime.timedelta(seconds=1)
                                    if "last_seen" in cve
                                    else None,
                                    allow_custom=True,
                                    created_by_ref=self.identity["standard_id"],
                                )
                                objects.append(stix_vulnerability)
                                objects.append(stix_relationship)
                        if "locations" in result_actor:
                            if "source" in result_actor["locations"]:
                                for source in result_actor["locations"]["source"]:
                                    if "country" in source:
                                        stix_location = stix2.Location(
                                            id=source["country"]["id"],
                                            name=source["country"]["name"],
                                            country=source["country"]["name"],
                                            allow_custom=True,
                                            custom_properties={
                                                "x_opencti_location_type": "Country"
                                            },
                                            created_by_ref=self.identity["standard_id"],
                                        )
                                        stix_relationship = stix2.Relationship(
                                            id=StixCoreRelationship.generate_id(
                                                "originates-from",
                                                stix_actor.get("id"),
                                                stix_location.get("id"),
                                                source["country"]["first_seen"]
                                                if "first_seen" in source["country"]
                                                else None,
                                                parse(source["country"]["last_seen"])
                                                + datetime.timedelta(seconds=1)
                                                if "last_seen" in source["country"]
                                                else None,
                                            ),
                                            relationship_type="originates-from",
                                            source_ref=stix_actor.get("id"),
                                            target_ref=stix_location.get("id"),
                                            start_time=source["country"]["first_seen"]
                                            if "first_seen" in source["country"]
                                            else None,
                                            stop_time=parse(
                                                source["country"]["last_seen"]
                                            )
                                            + datetime.timedelta(seconds=1)
                                            if "last_seen" in source["country"]
                                            else None,
                                            created_by_ref=self.identity["standard_id"],
                                        )
                                        objects.append(stix_location)
                                        objects.append(stix_relationship)
                            if "target" in result_actor["locations"]:
                                for target in result_actor["locations"]["target"]:
                                    if "country" in target:
                                        stix_location = stix2.Location(
                                            id=target["country"]["id"],
                                            name=target["country"]["name"],
                                            allow_custom=True,
                                            country=target["country"]["name"],
                                            custom_properties={
                                                "x_opencti_location_type": "Country"
                                            },
                                            created_by_ref=self.identity["standard_id"],
                                        )
                                        stix_relationship = stix2.Relationship(
                                            id=StixCoreRelationship.generate_id(
                                                "targets",
                                                stix_actor.get("id"),
                                                stix_location.get("id"),
                                                target["country"]["first_seen"]
                                                if "first_seen" in target["country"]
                                                else None,
                                                parse(target["country"]["last_seen"])
                                                + datetime.timedelta(seconds=1)
                                                if "last_seen" in target["country"]
                                                else None,
                                            ),
                                            relationship_type="targets",
                                            source_ref=stix_actor.get("id"),
                                            target_ref=stix_location.get("id"),
                                            start_time=target["country"]["first_seen"]
                                            if "first_seen" in target["country"]
                                            else None,
                                            stop_time=parse(
                                                target["country"]["last_seen"]
                                            )
                                            + datetime.timedelta(seconds=1)
                                            if "last_seen" in target["country"]
                                            else None,
                                            created_by_ref=self.identity["standard_id"],
                                        )
                                        objects.append(stix_location)
                                        objects.append(stix_relationship)
                        if "malware" in result_actor:
                            for malware in result_actor["malware"]:
                                stix_malware = stix2.Malware(
                                    id=malware["id"],
                                    is_family=True,
                                    created_by_ref=self.identity["standard_id"],
                                    name=malware["name"],
                                    allow_custom=True,
                                )
                                stix_relationship = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "uses",
                                        stix_actor.get("id"),
                                        stix_malware.get("id"),
                                        malware["first_seen"]
                                        if "first_seen" in malware
                                        else None,
                                        parse(malware["last_seen"])
                                        + datetime.timedelta(seconds=1)
                                        if "last_seen" in malware
                                        else None,
                                    ),
                                    relationship_type="uses",
                                    source_ref=stix_actor.get("id"),
                                    target_ref=stix_malware.get("id"),
                                    start_time=malware["first_seen"]
                                    if "first_seen" in malware
                                    else None,
                                    stop_time=parse(malware["last_seen"])
                                    + datetime.timedelta(seconds=1)
                                    if "last_seen" in malware
                                    else None,
                                    created_by_ref=self.identity["standard_id"],
                                )
                                objects.append(stix_malware)
                                objects.append(stix_relationship)
                        if "tool" in result_actor:
                            for tool in result_actor["tool"]:
                                stix_tool = stix2.Tool(
                                    id=tool["id"],
                                    created_by_ref=self.identity["standard_id"],
                                    name=tool["name"],
                                    allow_custom=True,
                                )
                                stix_relationship = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "uses",
                                        stix_actor.get("id"),
                                        stix_tool.get("id"),
                                        tool["first_seen"]
                                        if "first_seen" in tool
                                        else None,
                                        parse(tool["last_seen"])
                                        + datetime.timedelta(seconds=1)
                                        if "last_seen" in tool
                                        else None,
                                    ),
                                    relationship_type="uses",
                                    source_ref=stix_actor.get("id"),
                                    target_ref=stix_tool.get("id"),
                                    start_time=tool["first_seen"]
                                    if "first_seen" in tool
                                    else None,
                                    stop_time=parse(tool["last_seen"])
                                    + datetime.timedelta(seconds=1)
                                    if "last_seen" in tool
                                    else None,
                                    created_by_ref=self.identity["standard_id"],
                                )
                                objects.append(stix_tool)
                                objects.append(stix_relationship)
                    except Exception as e:
                        self.helper.log_error(str(e))
                self.helper.send_stix2_bundle(
                    stix2.Bundle(
                        objects=objects,
                        allow_custom=True,
                    ).serialize(),
                    update=self.update_existing_data,
                    work_id=work_id,
                )
                offset = offset + limit
                current_state["actor"] = offset
            else:
                no_more_result = True
        return current_state

    def _import_malware(self, work_id, current_state):
        url = self.mandiant_api_url + "/v4/malware"
        no_more_result = False
        limit = 30
        offset = current_state["malware"]
        while no_more_result is False:
            self.helper.log_info(
                "Iterating with limit=" + str(limit) + " and offset=" + str(offset)
            )
            result = self._query(url, limit, offset)
            if (
                result is not None
                and result["malware"] is not None
                and len(result["malware"]) > 0
            ):
                objects = []
                for malware in result["malware"]:
                    try:
                        stix_malware = stix2.Malware(
                            id=malware["id"],
                            is_family=True,
                            name=self._redacted_as_none("name", malware),
                            description=self._redacted_as_none("description", malware),
                            modified=self._redacted_as_none("last_updated", malware),
                            aliases=self._process_aliases(malware),
                            confidence=self.helper.connect_confidence_level,
                            created_by_ref=self.identity["standard_id"],
                            object_marking_refs=[stix2.TLP_AMBER.get("id")],
                        )
                        objects.append(stix_malware)
                        # Get the malware
                        result_malware = self._query(url + "/" + malware["id"])
                        if "industries" in result_malware:
                            for industry in result_malware["industries"]:
                                stix_identity = stix2.Identity(
                                    id=industry["id"],
                                    created_by_ref=self.identity["standard_id"],
                                    name=industry["name"],
                                    identity_class="class",
                                    allow_custom=True,
                                )
                                stix_relationship = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "targets",
                                        stix_malware.get("id"),
                                        stix_identity.get("id"),
                                        industry["first_seen"]
                                        if "first_seen" in industry
                                        else None,
                                        parse(industry["last_seen"])
                                        + datetime.timedelta(seconds=1)
                                        if "last_seen" in industry
                                        else None,
                                    ),
                                    relationship_type="targets",
                                    source_ref=stix_malware.get("id"),
                                    target_ref=stix_identity.get("id"),
                                    start_time=industry["first_seen"]
                                    if "first_seen" in industry
                                    else None,
                                    stop_time=parse(industry["last_seen"])
                                    + datetime.timedelta(seconds=1)
                                    if "last_seen" in industry
                                    else None,
                                    allow_custom=True,
                                    created_by_ref=self.identity["standard_id"],
                                )
                                objects.append(stix_identity)
                                objects.append(stix_relationship)
                        if "cve" in result_malware:
                            for cve in result_malware["cve"]:
                                stix_vulnerability = stix2.Vulnerability(
                                    id=cve["id"],
                                    created_by_ref=self.identity["standard_id"],
                                    name=cve["cve_id"],
                                    allow_custom=True,
                                )
                                stix_relationship = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "targets",
                                        result_malware.get("id"),
                                        stix_vulnerability.get("id"),
                                        cve["first_seen"]
                                        if "first_seen" in cve
                                        else None,
                                        parse(cve["last_seen"])
                                        + datetime.timedelta(seconds=1)
                                        if "last_seen" in cve
                                        else None,
                                    ),
                                    relationship_type="targets",
                                    source_ref=result_malware.get("id"),
                                    target_ref=stix_vulnerability.get("id"),
                                    start_time=cve["first_seen"]
                                    if "first_seen" in cve
                                    else None,
                                    stop_time=parse(cve["last_seen"])
                                    + datetime.timedelta(seconds=1)
                                    if "last_seen" in cve
                                    else None,
                                    allow_custom=True,
                                    created_by_ref=self.identity["standard_id"],
                                )
                                objects.append(stix_vulnerability)
                                objects.append(stix_relationship)
                    except Exception as e:
                        self.helper.log_error(str(e))
                if len(objects) > 0:
                    self.helper.send_stix2_bundle(
                        stix2.Bundle(
                            objects=objects,
                            allow_custom=True,
                        ).serialize(),
                        update=self.update_existing_data,
                        work_id=work_id,
                    )
                offset = offset + limit
                current_state["malware"] = offset
            else:
                no_more_result = True
        return current_state

    def _import_vulnerability(self, work_id, current_state):
        url = self.mandiant_api_url + "/v4/vulnerability"
        no_more_result = False
        limit = 1000
        start_epoch = current_state["vulnerability"]
        end_epoch = start_epoch + 3600
        next = None
        while no_more_result is False:
            self.helper.log_info(
                "Iterating with start_epoch="
                + str(start_epoch)
                + ", end_epoch="
                + str(end_epoch)
                + ", next="
                + str(next)
            )
            result = self._query(url, limit, None, next, start_epoch, end_epoch)
            if (
                result is not None
                and result["vulnerability"] is not None
                and len(result["vulnerability"]) > 0
            ):
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
                            description=self.cleanhtml(
                                self._redacted_as_none("description", vulnerability)
                            ),
                            created=self._redacted_as_none(
                                "publish_date", vulnerability
                            ),
                            confidence=self.helper.connect_confidence_level,
                            created_by_ref=self.identity["standard_id"],
                            object_marking_refs=[stix2.TLP_AMBER.get("id")],
                            allow_custom=True,
                            custom_properties=custom_properties,
                        )
                        vulnerabilities.append(stix_vulnerability)
                    except Exception as e:
                        self.helper.log_error(str(e))
                if len(vulnerabilities) > 0:
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
            if (
                result is not None
                and result["vulnerability"] is not None
                and len(result["vulnerability"]) == 1000
                and "next" in result
                and len(result["next"]) > 0
            ):
                next = result["next"]
            else:
                next = None
                start_epoch = end_epoch
                end_epoch = start_epoch + 3600
                current_state["vulnerability"] = int(start_epoch)
        return current_state

    def _import_indicator(self, work_id, current_state):
        url = self.mandiant_api_url + "/v4/indicator"
        no_more_result = False
        limit = 1000
        start_epoch = current_state["indicator"]
        end_epoch = start_epoch + 3600
        next = None
        while no_more_result is False:
            self.helper.log_info(
                "Iterating with start_epoch="
                + str(start_epoch)
                + ", end_epoch="
                + str(end_epoch)
                + ", next="
                + str(next)
            )
            result = self._query(url, limit, None, next, start_epoch, end_epoch)
            if (
                result is not None
                and result["indicators"] is not None
                and len(result["indicators"]) > 0
            ):
                objects = []
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
                                object_marking_refs=[stix2.TLP_AMBER.get("id")],
                                custom_properties={
                                    "x_opencti_main_observable_type": type,
                                    "x_opencti_create_observables": True,
                                },
                            )
                            objects.append(stix_indicator)
                            if "attributed_associations" in indicator:
                                for attribution in indicator["attributed_associations"]:
                                    attribution_id = (
                                        attribution["id"].replace(
                                            "threat-actor", "intrusion-set"
                                        )
                                        if self.mandiant_threat_actor_as_intrusion_set
                                        else attribution["id"]
                                    )
                                    stix_relationship = stix2.Relationship(
                                        id=StixCoreRelationship.generate_id(
                                            "indicates",
                                            stix_indicator.get("id"),
                                            attribution_id,
                                            indicator["first_seen"]
                                            if "first_seen" in indicator
                                            else None,
                                            parse(indicator["last_seen"])
                                            + datetime.timedelta(seconds=1)
                                            if "last_seen" in indicator
                                            else None,
                                        ),
                                        relationship_type="indicates",
                                        source_ref=stix_indicator.get("id"),
                                        target_ref=attribution_id,
                                        start_time=indicator["first_seen"]
                                        if "first_seen" in indicator
                                        else None,
                                        stop_time=parse(indicator["last_seen"])
                                        + datetime.timedelta(seconds=1)
                                        if "last_seen" in indicator
                                        else None,
                                        allow_custom=True,
                                        created_by_ref=self.identity["standard_id"],
                                    )
                                    objects.append(stix_relationship)
                    except Exception as e:
                        self.helper.log_error(str(e))
                if len(objects) > 0:
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
            if (
                result is not None
                and result["indicators"] is not None
                and len(result["indicators"]) == 1000
                and "next" in result
                and len(result["next"]) > 0
            ):
                next = result["next"]
            else:
                next = None
                start_epoch = end_epoch
                end_epoch = start_epoch + 3600
                current_state["indicator"] = int(start_epoch)
        return current_state

    def _import_report(self, work_id, current_state):
        url = self.mandiant_api_url + "/v4/reports"
        no_more_result = False
        limit = 1000
        start_epoch = current_state["report"]
        end_epoch = start_epoch + 3600
        next = None
        while no_more_result is False:
            self.helper.log_info(
                "Iterating with start_epoch="
                + str(start_epoch)
                + ", end_epoch="
                + str(end_epoch)
                + ", next="
                + str(next)
            )
            result = self._query(url, limit, None, next, start_epoch, end_epoch)
            if (
                result is not None
                and result["objects"] is not None
                and len(result["objects"]) > 0
            ):
                for reportOut in result["objects"]:
                    # Ignoring reports that are not listed in the parameters.
                    if (
                        reportOut.get("report_type")
                        in self.mandiant_report_types_ignored
                    ):
                        pass
                    elif reportOut.get("report_type") == "News Analysis":
                        try:
                            url_report = (
                                self.mandiant_api_url
                                + "/v4/report/"
                                + reportOut.get("report_id")
                            )
                            report = self._query(url_report)
                            self.helper.log_debug(
                                "Processing report ID "
                                + str(reportOut.get("report_id"))
                            )
                            bundle_objects = []
                            publish_date = parse(report["publishDate"])
                            report_id = Report.generate_id(
                                report["reportId"], publish_date
                            )
                            file = None
                            try:
                                report_pdf = self._getreportpdf(url_report)
                                file_data_encoded = base64.b64encode(report_pdf)
                                filename = str(reportOut.get("report_id")) + ".pdf"
                                file = {
                                    "name": filename,
                                    "data": file_data_encoded.decode("utf-8"),
                                    "mime_type": "application/pdf",
                                }
                            except Exception as e:
                                self.helper.log_info(
                                    "Failed to get PDF report for ID "
                                    + str(reportOut.get("report_id"))
                                )
                                self.helper.log_info("ERROR: " + str(e))
                            note = self.cleanhtml(report["isightComment"])
                            note_id = Note.generate_id(publish_date, note)
                            self.helper.log_debug("Note ID " + str(note_id))
                            stix_note = stix2.Note(
                                id=note_id,
                                abstract="ANALYST COMMENT",
                                content=note,
                                created=publish_date,
                                created_by_ref=self.identity["standard_id"],
                                object_refs=[report_id],
                            )
                            stix_report = stix2.Report(
                                id=report_id,
                                name=self._redacted_as_none("title", report),
                                report_types=[
                                    self._redacted_as_none("reportType", report)
                                ]
                                if self._redacted_as_none("reportType", report)
                                is not None
                                else [],
                                description=re.sub(
                                    "<[^<]+?>",
                                    "",
                                    self._redacted_as_none("fromMedia", report),
                                )
                                if self._redacted_as_none("fromMedia", report)
                                is not None
                                else "No description",
                                published=publish_date,
                                labels=[
                                    report.get("tmhAccuracyRanking"),
                                    "News Analysis",
                                ],
                                confidence=self.helper.connect_confidence_level,
                                created_by_ref=self.identity["standard_id"],
                                object_refs=[note_id],
                                allow_custom=True,
                                x_opencti_files=[file] if file is not None else [],
                                object_marking_refs=[stix2.TLP_AMBER.get("id")],
                                external_references=[
                                    {
                                        "source_name": report["outlet"],
                                        "url": report["storyLink"],
                                    }
                                ],
                            )
                            bundle_objects.append(stix_report)
                            bundle_objects.append(stix_note)
                            # Creating and sending the bundle to OCTI
                            try:
                                self.helper.log_debug(
                                    "Objects to be sent " + str(bundle_objects)
                                )
                                self.helper.send_stix2_bundle(
                                    stix2.Bundle(
                                        objects=bundle_objects,
                                        allow_custom=True,
                                    ).serialize(),
                                    update=self.update_existing_data,
                                    bypass_split=True,
                                    work_id=work_id,
                                )
                            except Exception as e:
                                self.helper.log_info(
                                    "Failed to process this report ID "
                                    + str(reportOut.get("report_id"))
                                )
                                self.helper.log_info("ERROR: " + str(e))
                        except Exception as e:
                            self.helper.log_info(
                                "Failed to process News Analysis Report "
                                + str(reportOut.get("report_id"))
                            )
                            self.helper.log_info("ERROR: " + str(e))
                    else:
                        stix_bundle = None
                        try:
                            url_report = (
                                self.mandiant_api_url
                                + "/v4/report/"
                                + reportOut.get("report_id")
                            )
                            stix_bundle = self._query(
                                url_report,
                                app_header="application/stix+json;version=2.1",
                            )
                            self.helper.log_debug(
                                "Processing report ID "
                                + str(reportOut.get("report_id"))
                            )
                            report_labels = []
                            adding_sector_class = {"identity_class": "class"}
                            adding_location_class = {
                                "x_opencti_location_type": "Country"
                            }
                            # Removing the Mandiant entity
                            for idx, each_object in enumerate(
                                stix_bundle.get("objects")
                            ):
                                try:
                                    if (
                                        each_object.get("type") == "identity"
                                        and each_object.get("identity_class")
                                        == "organization"
                                    ):
                                        stix_bundle.get("objects").pop(idx)

                                except Exception as e:
                                    self.helper.log_info(
                                        "Failed removing Mandiant Entity "
                                        + str(reportOut.get("report_id"))
                                    )
                                    self.helper.log_info("ERROR: " + str(e))
                            # Changing Threat Actor to Intrusion Set if it has been defined.
                            for each_object in stix_bundle.get("objects"):
                                try:
                                    if (
                                        self.mandiant_threat_actor_as_intrusion_set
                                        and each_object.get("type") == "threat-actor"
                                    ):
                                        each_object["type"] = "intrusion-set"
                                        each_object["id"] = each_object.get(
                                            "id"
                                        ).replace("threat-actor", "intrusion-set")
                                    elif (
                                        self.mandiant_threat_actor_as_intrusion_set
                                        and each_object.get("type") == "relationship"
                                    ):
                                        each_object["source_ref"] = each_object.get(
                                            "source_ref"
                                        ).replace("threat-actor", "intrusion-set")
                                        each_object["target_ref"] = each_object.get(
                                            "target_ref"
                                        ).replace("threat-actor", "intrusion-set")
                                    elif (
                                        self.mandiant_threat_actor_as_intrusion_set
                                        and each_object.get("type") == "report"
                                    ):
                                        new_object_refs = []
                                        for each_object_refs in each_object.get(
                                            "object_refs"
                                        ):
                                            new_each_object_refs = (
                                                each_object_refs.replace(
                                                    "threat-actor", "intrusion-set"
                                                )
                                            )
                                            new_object_refs.append(new_each_object_refs)
                                        each_object["object_refs"] = new_object_refs
                                except Exception as e:
                                    self.helper.log_info(
                                        "Failed to change Threat Actor to Intrusion Set "
                                        + str(reportOut.get("report_id"))
                                    )
                                    self.helper.log_info("ERROR: " + str(e))
                            # Updating the identities as sectors
                            for each_object in stix_bundle.get("objects"):
                                if each_object.get("type") == "identity":
                                    each_object.update(adding_sector_class)
                                    report_labels.append(each_object.get("name"))
                            # Updating the locations as country
                            for each_object in stix_bundle.get("objects"):
                                if each_object.get("type") == "location":
                                    each_object.update(adding_location_class)
                            # Adding the created by ref and getting the PDF report.
                            for each_object in stix_bundle.get("objects"):
                                # Adding Sectors as labels for the report
                                if each_object.get("type") == "report":
                                    each_object.update(
                                        {
                                            "created_by_ref": str(
                                                self.identity["standard_id"]
                                            )
                                        }
                                    )
                                    # Appending Report type as Labels
                                    for each_report_type in each_object.get(
                                        "report_types"
                                    ):
                                        report_labels.append(each_report_type)
                                    # Updating the labels for the report.
                                    each_object.update({"labels": report_labels})
                                    self.helper.log_debug(
                                        "Labels Object " + str(report_labels)
                                    )
                                    # Fetching the PDF for the report
                                    try:
                                        report_pdf = self._getreportpdf(url_report)
                                        file_data_encoded = base64.b64encode(report_pdf)
                                        filename = (
                                            str(reportOut.get("report_id")) + ".pdf"
                                        )
                                        file = {
                                            "name": filename,
                                            "data": file_data_encoded.decode("utf-8"),
                                            "mime_type": "application/pdf",
                                        }
                                        each_object.update({"x_opencti_files": [file]})
                                    except Exception as e:
                                        self.helper.log_info(
                                            "Failed to get PDF report for ID "
                                            + str(reportOut.get("report_id"))
                                        )
                                        self.helper.log_info("ERROR: " + str(e))
                        except Exception as e:
                            self.helper.log_info(
                                "Failed to process News Analyis Report "
                                + str(reportOut.get("report_id"))
                            )
                            self.helper.log_info("ERROR: " + str(e))
                        # Creating and sending the bundle to OCTI
                        try:
                            bundle = stix2.Bundle(
                                objects=stix_bundle.get("objects"),
                                allow_custom=True,
                            )
                            self.helper.send_stix2_bundle(
                                bundle.serialize(),
                                update=self.update_existing_data,
                                work_id=work_id,
                            )
                        except Exception as e:
                            self.helper.log_info(
                                "Failed to process this report ID "
                                + str(reportOut.get("report_id"))
                            )
                            self.helper.log_info("ERROR: " + str(e))
                next_pointer = result.get("next")
                self.helper.log_debug("Report next_pointer ID " + str(next_pointer))
            elif end_epoch > int(time.time()):
                no_more_result = True
            if (
                result is not None
                and result["objects"] is not None
                and len(result["objects"]) == 1000
                and "next" in result
                and len(result["next"]) > 0
            ):
                next = result["next"]
            else:
                next = None
                start_epoch = end_epoch
                end_epoch = start_epoch + 3600
                current_state["report"] = int(start_epoch)
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
                            "report": self.added_after,
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
                if "report" in self.mandiant_collections:
                    current_state = self.helper.get_state()
                    self.helper.log_info(
                        "Get REPORT after position " + str(current_state["report"])
                    )
                    new_state = self._import_report(work_id, current_state)
                    self.helper.set_state(new_state)
                if "indicator" in self.mandiant_collections:
                    current_state = self.helper.get_state()
                    self.helper.log_info(
                        "Get INDICATOR after position "
                        + str(current_state["indicator"])
                    )
                    new_state = self._import_indicator(work_id, current_state)
                    self.helper.set_state(new_state)

                message = "End of synchronization"
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)

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
        mandiantConnector = Mandiant()
        mandiantConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
