import re
import time
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from pycti import OpenCTIConnectorHelper
from threading import Event, Thread
from managers import (IncidentManager, ElasticsearchHelper, EnvironmentManager, RelationshipManager, MyIncident)
from stix2.v21 import IPv4Address, AttackPattern, KillChainPhase
from scalpl import Cut


class Scanner(Thread):
    def __init__(self,
                 config: Cut,
                 env_manager: EnvironmentManager,
                 es: Elasticsearch,
                 helper: OpenCTIConnectorHelper,
                 incident_manager: IncidentManager,
                 relationship_manager: RelationshipManager,
                 shutdown_event: Event):
        super(Scanner, self).__init__()
        self.config = config
        self.env_manager = env_manager
        self.author = self.env_manager.author
        self.elasticsearch = es
        self.es_helper = ElasticsearchHelper()
        self.helper = helper
        self.incident_manager = incident_manager
        self.relationship_manager = relationship_manager
        self.shutdown_event: Event = shutdown_event
        self.interval = 60
        self.ipv4_pattern = re.compile("[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}")
        self.confidence = int(config.get("connector.confidence_level", 90))

    def get_elasticsearch(self) -> Elasticsearch:
        return self.elasticsearch

    def get_attack_pattern_and_kill_chain_phases(self, search: str, search_in: str = "x_mitre_id") -> dict:
        attack_patterns = self.helper.api.attack_pattern.list(
            filters={"key": search_in, "values": [search]}
        )
        chosen_attack_pattern = None
        for attack_pattern in attack_patterns:
            name = attack_pattern["name"]
            # self.helper.log_info(f"ATP {name}")
            if search.lower() in attack_pattern[search_in].lower():
                chosen_attack_pattern = attack_pattern
                break
        kill_chain_phases = []
        if chosen_attack_pattern is None:
            if search_in == "name":
                return {}
            else:
                return self.get_attack_pattern_and_kill_chain_phases(search, "name")
        else:
            for kcp in chosen_attack_pattern["killChainPhases"]:
                name = kcp["standard_id"]
                # self.helper.log_info(f"KCP {name}")
                kill_chain_phases.append(kcp["standard_id"])
        return {"attack_pattern": chosen_attack_pattern, "kill_chain_phases": kill_chain_phases}

    def link_attack_pattern(self, my_incident: MyIncident, attack_pattern: AttackPattern, scan,
                            kill_chain_phases: [KillChainPhase]):
        self.env_manager.add_item_to_report(attack_pattern["standard_id"])
        attack_pattern_relationships = self.helper.api.stix_core_relationship.list(
            relationship_type="uses",
            fromId=my_incident.stix_id,
            toId=attack_pattern["standard_id"]
        )
        if len(attack_pattern_relationships) == 0:
            attack_pattern_relationship = self.helper.api.stix_core_relationship.create(
                relationship_type="uses",
                fromId=my_incident.stix_id,
                toId=attack_pattern["standard_id"],
                killChainPhases=kill_chain_phases,
                start_time=scan.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                stop_time=scan.last_event.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                confidence=self.confidence,
                createdBy=self.author
            )
            self.env_manager.add_item_to_report(attack_pattern_relationship["standard_id"])
        else:
            attack_pattern_relationship = attack_pattern_relationships[0]
            attack_pattern_relationship = self.helper.api.stix_core_relationship.create(
                stix_id=attack_pattern_relationship["standard_id"],
                relationship_type="uses",
                fromId=my_incident.stix_id,
                toId=attack_pattern["standard_id"],
                killChainPhases=kill_chain_phases,
                start_time=scan.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                stop_time=scan.last_event.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                confidence=self.confidence,
                update=True,
                createdBy=self.author
            )

    def get_should_run(self, state_name: str) -> dict:
        try:
            # Get the current timestamp and check
            timestamp = int(time.time())
            result = {"timestamp":  timestamp}
            current_state = self.helper.get_state()

            if current_state is not None and state_name in current_state:
                result["last_run"] = current_state[state_name]
                self.helper.log_info(
                    "Connector last run: "
                    + datetime.utcfromtimestamp(result["last_run"]).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )
            else:
                result["last_run"] = None
                self.helper.log_info("Connector has never run")
            # If the last_run is more than interval-1 day
            if result["last_run"] is None or (
                    (timestamp - result["last_run"])
                    > (int(self.interval) - 1)
            ):
                result["should_run"] = True
            else:
                result["should_run"] = False
            return result
        except Exception as e:
            return {}

    def mark_last_run(self, state_name, timestamp):
        try:
            self.helper.log_info(
                f"Connector successfully run, storing {state_name} as "
                + str(timestamp)
            )
            current_state = self.helper.get_state()
            if current_state is None:
                self.helper.set_state({state_name: timestamp})
            else:
                current_state[state_name] = timestamp
                self.helper.set_state(current_state)
        except Exception as e:
            self.helper.log_error(f"Exception while saving state {state_name} : {e}")

    def add_exclude_ignored_networks_to_search(self, search: Search) -> Search:
        ignore_networks: [str] = self.env_manager.get_ignore_networks()
        for ignore_network in ignore_networks:
            search = search.exclude("match", source__ip=ignore_network)

        return search

    def get_query(self, start: datetime = None, end: datetime = None) -> Search:
        pass

    def get_agg_query(self, start: datetime = None, end: datetime = None) -> Search:
        pass

    def run(self) -> None:
        pass
