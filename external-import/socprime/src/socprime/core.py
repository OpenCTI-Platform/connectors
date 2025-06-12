import datetime
import os
import sys
import time
from copy import deepcopy
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Union

import pycti
import yaml
from dateutil.parser import parse as parse_date_str
from pycti import StixCoreRelationship
from pycti.connector.opencti_connector_helper import (
    OpenCTIConnectorHelper,
    get_config_variable,
)
from socprime.mitre_attack import MitreAttack
from socprime.tdm_api_client import ApiClient
from stix2 import (
    AttackPattern,
    Bundle,
    Identity,
    Indicator,
    IntrusionSet,
    Malware,
    Relationship,
    Tool,
    Vulnerability,
)


class ParsedRule(NamedTuple):
    name: str
    description: str | None
    siem_type: str
    pattern: str
    status: str | None
    author: str | None
    sigma_tags: list[str]
    release_date: datetime.datetime | None


class SocprimeConnector:
    _DEFAULT_CONNECTOR_RUN_INTERVAL_SEC = 3600
    _STATE_LAST_RUN = "last_run"
    _stix_object_types_to_udate = (Indicator, Relationship)

    def __init__(self):
        config = self._read_configuration()
        self.helper = OpenCTIConnectorHelper(config)
        tdm_api_key = get_config_variable(
            "SOCPRIME_API_KEY", ["socprime", "api_key"], config
        )
        if not tdm_api_key:
            raise Exception("Configuration error. SOCPRIME_API_KEY is required.")
        self._content_list_names = get_config_variable(
            "SOCPRIME_CONTENT_LIST_NAME", ["socprime", "content_list_name"], config
        )
        self._job_ids = get_config_variable(
            "SOCPRIME_JOB_IDS", ["socprime", "job_ids"], config
        )
        self._siem_types_for_refs = get_config_variable(
            "SOCPRIME_SIEM_TYPE", ["socprime", "siem_type"], config
        )
        self._indicator_siem_type = get_config_variable(
            "SOCPRIME_INDICATOR_SIEM_TYPE",
            ["socprime", "indicator_siem_type"],
            config,
            default="sigma",
        )
        self.interval_sec = get_config_variable(
            env_var="SOCPRIME_INTERVAL_SEC",
            yaml_path=["socprime", "interval_sec"],
            config=config,
            isNumber=True,
            default=self._DEFAULT_CONNECTOR_RUN_INTERVAL_SEC,
        )
        self.tdm_api_client = ApiClient(api_key=tdm_api_key)
        self.mitre_attack = MitreAttack()

    @staticmethod
    def _read_configuration() -> Dict[str, str]:
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        if not os.path.isfile(config_file_path):
            return {}
        return yaml.load(open(config_file_path), Loader=yaml.FullLoader)

    def get_siem_types_for_refs(self) -> List[str]:
        if not self._siem_types_for_refs:
            return []
        elif isinstance(self._siem_types_for_refs, list):
            return self._siem_types_for_refs
        else:
            return [x.strip() for x in str(self._siem_types_for_refs).split(",")]

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(time.time())

    def _load_state(self) -> Dict[str, Any]:
        current_state = self.helper.get_state()
        if not current_state:
            return {}
        return current_state

    @staticmethod
    def _get_state_value(
        state: Optional[Mapping[str, Any]], key: str, default: Optional[Any] = None
    ) -> Any:
        if state is not None:
            return state.get(key, default)
        return default

    def _is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            self.helper.connector_logger.info("Connector first run")
            return True
        time_diff = current_time - last_run
        return time_diff >= self.interval_sec

    @classmethod
    def _sleep(cls, delay_sec: Optional[int] = None) -> None:
        time.sleep(delay_sec)

    def get_stix_objects_from_rule(
        self,
        rule: dict,
        siem_types: Optional[List[str]] = None,
        author_id: Optional[str] = None,
    ) -> List:
        stix_objects = []
        parsed_rule = self._parse_rule(rule)
        labels = deepcopy(parsed_rule.sigma_tags)
        if parsed_rule.author:
            labels.append(f"Sigma Author: {parsed_rule.author}")
        indicator = Indicator(
            id=pycti.Indicator.generate_id(pattern=parsed_rule.pattern),
            type="indicator",
            name=parsed_rule.name,
            description=parsed_rule.description,
            pattern=parsed_rule.pattern,
            pattern_type=self._get_pattern_type(parsed_rule),
            labels=labels,
            confidence=self.convert_sigma_status_to_stix_confidence(
                sigma_level=parsed_rule.status
            ),
            external_references=self._get_external_refs_from_rule(
                rule, siem_types=siem_types
            ),
            created_by_ref=author_id,
            valid_from=parsed_rule.release_date,
            valid_until=None,
        )
        stix_objects.append(indicator)

        stix_objects.extend(
            self._get_tools_and_relations_from_indicator(indicator=indicator, rule=rule)
        )
        stix_objects.extend(
            self._get_techniques_and_relations_from_indicator(
                indicator=indicator, rule=rule
            )
        )
        stix_objects.extend(
            self._get_intrusion_sets_and_relations_from_indicator(
                indicator=indicator, rule=rule
            )
        )

        stix_objects.extend(
            self._get_vulnerabilities_and_relations_from_indicator(
                indicator=indicator, rule=rule
            )
        )

        return stix_objects

    @staticmethod
    def _get_pattern_type(parsed_rule: ParsedRule) -> str:
        pattern_type = parsed_rule.siem_type
        if pattern_type == "powershell":
            pattern_type = "powershell query"
        return pattern_type

    @classmethod
    def _parse_rule(cls, rule: dict) -> ParsedRule:
        siem_type = rule["siem_type"]
        if siem_type == "sigma":
            sigma_body = cls._get_sigma_body_from_rule(rule)
            sigma_status = sigma_body.get("status")
            sigma_author = sigma_body.get("author")
            sigma_tags = sigma_body.get("tags") or []
        else:
            sigma_status = rule["sigma"].get("status")
            sigma_author = rule["tags"].get("author") if rule.get("tags") else None
            if not sigma_author:
                sigma_author = None
            if isinstance(sigma_author, list):
                sigma_author = ", ".join(sigma_author)
            sigma_tags = []

        try:
            release_date = parse_date_str(rule.get("release_date"))
        except Exception:
            release_date = None

        return ParsedRule(
            pattern=rule["sigma"]["text"],
            status=sigma_status,
            author=sigma_author,
            sigma_tags=sigma_tags,
            name=rule["case"]["name"],
            description=rule.get("description"),
            release_date=release_date,
            siem_type=siem_type,
        )

    @staticmethod
    def _get_tools_from_rule(rule: dict) -> List[str]:
        res = []
        if "tags" in rule and isinstance(rule["tags"], dict):
            if "tool" in rule["tags"] and isinstance(rule["tags"]["tool"], list):
                res.extend(rule["tags"]["tool"])
        return res

    def _get_tools_and_relations_from_indicator(
        self, indicator: Indicator, rule: dict
    ) -> List[Union[Tool, Malware, Relationship]]:
        res = []
        indicator_id = pycti.Indicator.generate_id(pattern=indicator.pattern)
        for tool_name in self._get_tools_from_rule(rule):
            tool = self.mitre_attack.get_tool_by_name(tool_name)
            if tool:
                res.append(tool)
                rel = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "indicates", indicator_id, tool.id
                    ),
                    relationship_type="indicates",
                    source_ref=indicator_id,
                    target_ref=tool.id,
                )
                res.append(rel)
        return res

    @staticmethod
    def _get_techniques_from_rule(rule: dict) -> List[str]:
        res = []
        if "tags" in rule and isinstance(rule["tags"], dict):
            if "technique" in rule["tags"] and isinstance(
                rule["tags"]["technique"], list
            ):
                for d in rule["tags"]["technique"]:
                    res.append(d["id"])
        return res

    def _get_techniques_and_relations_from_indicator(
        self, indicator: Indicator, rule: dict
    ) -> List[Union[AttackPattern, Relationship]]:
        res = []
        indicator_id = pycti.Indicator.generate_id(pattern=indicator.pattern)
        for technique_id in self._get_techniques_from_rule(rule):
            technique = self.mitre_attack.get_technique_by_id(technique_id)
            if technique:
                res.append(technique)
                rel = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "indicates", indicator_id, technique.id
                    ),
                    relationship_type="indicates",
                    source_ref=indicator_id,
                    target_ref=technique.id,
                )
                res.append(rel)
        return res

    @staticmethod
    def _get_actors_from_rule(rule: dict) -> List[str]:
        res = []
        if "tags" in rule and isinstance(rule["tags"], dict):
            if "actor" in rule["tags"] and isinstance(rule["tags"]["actor"], list):
                res.extend(rule["tags"]["actor"])
        return res

    def _get_intrusion_sets_and_relations_from_indicator(
        self, indicator: Indicator, rule: dict
    ) -> List[Union[IntrusionSet, Relationship]]:
        res = []
        indicator_id = pycti.Indicator.generate_id(pattern=indicator.pattern)
        for actor_name in self._get_actors_from_rule(rule):
            intusion_set = self.mitre_attack.get_intrusion_set_by_name(actor_name)
            if intusion_set:
                res.append(intusion_set)
                rel = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "indicates", indicator_id, intusion_set.id
                    ),
                    relationship_type="indicates",
                    source_ref=indicator_id,
                    target_ref=intusion_set.id,
                )
                res.append(rel)
        return res

    @classmethod
    def _get_external_refs_from_rule(
        cls, rule: dict, siem_types: Optional[List[str]] = None
    ) -> List[dict]:
        res = []
        context_resources = rule.get("context_resources")
        if isinstance(context_resources, dict):
            for link_type, doc in context_resources.items():
                if isinstance(doc, dict) and isinstance(doc.get("links"), list):
                    for link in doc["links"]:
                        if link_type and link:
                            if link_type == "detection":
                                res.append(
                                    {
                                        "source_name": "Detection Sigma",
                                        "url": f"{link}#sigma",
                                    }
                                )
                                if siem_types:
                                    for siem_type in siem_types:
                                        res.append(
                                            {
                                                "source_name": f"Detection {siem_type}",
                                                "url": f"{link}#{siem_type}",
                                            }
                                        )
                            else:
                                link_type: str
                                res.append(
                                    {
                                        "source_name": (
                                            link_type.upper()
                                            if link_type == "cve"
                                            else link_type.capitalize()
                                        ),
                                        "url": link,
                                    }
                                )

        if rule["siem_type"] == "sigma":
            link_to_socprime = cls._get_link_to_socprime(rule)
            if link_to_socprime:
                res.append({"source_name": "SOC Prime", "url": link_to_socprime})
        return res

    @staticmethod
    def _get_sigma_body_from_rule(rule: dict) -> dict:
        return yaml.safe_load(rule["sigma"]["text"].replace("---", ""))

    @classmethod
    def _get_link_to_socprime(cls, rule: dict) -> str | None:
        body = cls._get_sigma_body_from_rule(rule)
        if isinstance(body, dict) and body.get("id"):
            sigma_id = body["id"]
            return f"https://socprime.com/rs/rule/{sigma_id}"

    @staticmethod
    def convert_sigma_status_to_stix_confidence(sigma_level: str) -> Optional[int]:
        mapping = {
            "stable": 85,
            "test": 50,
            "experimental": 15,
            "deprecated": 0,
            "unsupported": 0,
        }
        return mapping.get(str(sigma_level).lower())

    def _get_available_siem_types(self, rule_ids: List[str]) -> Dict[str, List[str]]:
        res = {}
        if rule_ids:
            try:
                query = "case.id: (" + " OR ".join(rule_ids) + ")"
                for siem_type in self.get_siem_types_for_refs():
                    rules = self.tdm_api_client.search_rules(
                        siem_type=siem_type, client_query_string=query
                    )
                    for rule in rules:
                        case_id = rule["case"]["id"]
                        if case_id not in res:
                            res[case_id] = []
                        res[case_id].append(siem_type)
            except Exception as err:
                self.helper.connector_logger.error(
                    "Error while getting availables siem types.",
                    meta={"error": str(err)},
                )
        return res

    def _get_rules_from_content_lists_and_jobs(self) -> list[str]:
        list_names = self._get_content_list_names()
        job_ids = self._get_job_ids()
        if not list_names and not job_ids:
            raise Exception(
                "Configuration error. At least one job id or one content list name must be provided."
            )
        res = []
        for list_name in list_names:
            res.extend(
                self._get_rules_from_one_content_list(content_list_name=list_name)
            )
        for job_id in job_ids:
            res.extend(self._get_rules_from_one_job(job_id=job_id))
        return res

    def _get_content_list_names(self) -> list[str]:
        if not self._content_list_names:
            return []
        names = str(self._content_list_names).split(",")
        names = [x.strip() for x in names if x.strip()]
        return names

    def _get_rules_from_one_content_list(self, content_list_name: str) -> List[dict]:
        self.helper.connector_logger.info(
            f"Getting rules from content list {content_list_name}"
        )
        try:
            return self.tdm_api_client.get_rules_from_content_list(
                content_list_name=content_list_name,
                siem_type=self._indicator_siem_type,
            )
        except Exception as err:
            self.helper.connector_logger.error(
                f"Error while getting rules from content list - {err}",
                meta={"error": str(err)},
            )
            return []

    def _get_job_ids(self) -> list[str]:
        if not self._job_ids:
            return []
        ids = str(self._job_ids).split(",")
        ids = [x.strip() for x in ids if x.strip()]
        return ids

    def _get_rules_from_one_job(self, job_id: str) -> List[dict]:
        self.helper.connector_logger.info(f"Getting rules from job {job_id}")
        try:
            return self.tdm_api_client.get_rules_from_job(job_id=job_id)
        except Exception as err:
            self.helper.connector_logger.error(
                f"Error while getting rules from job - {err}", meta={"error": str(err)}
            )
            return []

    def _create_author_identity(self, work_id: str) -> str:
        """Creates SOC Prime author and returns its id."""
        name = "SOC Prime"
        author_identity = Identity(
            id=pycti.Identity.generate_id(name=name, identity_class="organization"),
            type="identity",
            name=name,
            identity_class="organization",
            confidence=85,
            description="SOC Prime operates the world’s largest and most advanced Platform for collaborative cyber defense. "
            + "The SOC Prime Platform integration with OpenCTI provides the latest detections within Sigma rules.",
            contact_information="support@socprime.com",
            external_references=[
                {"source_name": "SOC Prime", "url": "https://socprime.com/"}
            ],
        )

        serialized_bundle = Bundle(objects=[author_identity]).serialize()
        self.helper.send_stix2_bundle(serialized_bundle, work_id=work_id)
        return author_identity.get("id")

    def send_rules_from_tdm(self, work_id: str) -> None:
        author_id = self._create_author_identity(work_id)

        bundle_objects = []
        rules = self._get_rules_from_content_lists_and_jobs()
        available_siem_types = self._get_available_siem_types(
            rule_ids=[x["case"]["id"] for x in rules]
        )

        rules_count = 0
        for rule in rules:
            try:
                rule_stix_objects = self.get_stix_objects_from_rule(
                    rule=rule,
                    siem_types=available_siem_types.get(rule["case"]["id"]),
                    author_id=author_id,
                )
                bundle_objects.extend(rule_stix_objects)
                rules_count += 1
            except Exception as err:
                case_id = rule.get("case", {}).get("id")
                self.helper.connector_logger.error(
                    f"Error while parsing rule {case_id} - {err}",
                    meta={"error": str(err)},
                )

        self.helper.connector_logger.info(f"Sending {rules_count} rules")

        self._send_stix_objects(objects_list=bundle_objects, work_id=work_id)

    def _send_stix_objects(self, objects_list: list, work_id: str) -> None:
        objects = [
            x
            for x in objects_list
            if not isinstance(x, self._stix_object_types_to_udate)
        ]
        if objects:
            bundle = Bundle(objects=objects).serialize()
            self.helper.send_stix2_bundle(bundle, work_id=work_id)

        objects = [
            x for x in objects_list if isinstance(x, self._stix_object_types_to_udate)
        ]
        if objects:
            bundle = Bundle(objects=objects).serialize()
            self.helper.send_stix2_bundle(bundle, work_id=work_id)

    def run(self):
        self.helper.connector_logger.info("Starting SOC Prime connector...")
        while True:
            self.helper.connector_logger.info("Running SOC Prime connector...")
            run_interval = self.interval_sec

            try:
                timestamp = self._current_unix_timestamp()
                current_state = self._load_state()

                self.helper.connector_logger.info(f"Loaded state: {current_state}")

                last_run = self._get_state_value(current_state, self._STATE_LAST_RUN)
                if self._is_scheduled(last_run, timestamp):
                    now = datetime.datetime.utcfromtimestamp(timestamp)
                    friendly_name = "SOC Prime run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    self.send_rules_from_tdm(work_id)

                    new_state = current_state.copy()
                    new_state[self._STATE_LAST_RUN] = self._current_unix_timestamp()

                    self.helper.connector_logger.info(f"Storing new state: {new_state}")
                    self.helper.set_state(new_state)
                    message = (
                        "State stored, next run in: "
                        + str(self.interval_sec)
                        + " seconds"
                    )
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.connector_logger.info(message)
                else:
                    next_run = self.interval_sec - (timestamp - last_run)
                    run_interval = min(run_interval, next_run)

                    self.helper.connector_logger.info(
                        f"Connector will not run, next run in: {next_run} seconds"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.connector_logger.info("Connector stop")
                sys.exit(0)

            if self.helper.connect_run_and_terminate:
                self.helper.connector_logger.info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)

            self._sleep(delay_sec=run_interval)

    def _get_vulnerabilities_and_relations_from_indicator(
        self, indicator: Indicator, rule: dict
    ) -> List[Union[Vulnerability, Relationship]]:
        res = []
        indicator_id = pycti.Indicator.generate_id(pattern=indicator.pattern)
        for cve in self._get_cves_from_rule(rule):
            vuln = self._get_vuln_by_cve_id(cve_id=cve)
            if vuln:
                res.append(vuln)
                rel = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "indicates", indicator_id, vuln.id
                    ),
                    relationship_type="indicates",
                    source_ref=indicator_id,
                    target_ref=vuln.id,
                )
                res.append(rel)
        return res

    @staticmethod
    def _get_cves_from_rule(rule: dict) -> List[str]:
        res = []
        if "tags" in rule and isinstance(rule["tags"], dict):
            if "cve_id" in rule["tags"] and isinstance(rule["tags"]["cve_id"], list):
                res.extend(rule["tags"]["cve_id"])
        return res

    @staticmethod
    def _get_vuln_by_cve_id(cve_id: str) -> Vulnerability:
        return Vulnerability(
            type="vulnerability",
            id=pycti.Vulnerability.generate_id(name=cve_id),
            name=cve_id,
            external_references=[
                {
                    "source_name": "cve",
                    "external_id": cve_id,
                }
            ],
        )
