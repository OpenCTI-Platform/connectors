import re
import threading
import traceback
from datetime import datetime, timedelta
from threading import Event

import ciso8601
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from pycti import OpenCTIConnectorHelper, get_config_variable
from scanners import Scanner
from managers import IncidentManager, EnvironmentManager, RelationshipManager, MyIncident
from scalpl import Cut
from stix2.v21 import IPv4Address


class SshTarget:
    def __init__(self, ip_address: str, start: datetime):
        self.ip_address: str = ip_address
        self.auth_failures: int = 0
        self.start = start
        self.end = start
        self.scan = False
        self.success = False
        self.finished = False


class SshHost:
    def __init__(self, ip_address: str):
        self.ip_address: str = ip_address
        self.id = None
        self.targets: [SshTarget] = []
        self.hits: int = 1


class FakeScan:
    def __init__(self, start: datetime, last_event: datetime):
        self.start = start
        self.last_event = last_event


# The ssh scanner uses failed login authentications from zeek ssh logs to identify brute force ssh attempts.
# If failed
# T1110.001
# If successful
# T1021.004
class SshScanner(Scanner):
    def __init__(self,
                 config: Cut,
                 env_manager: EnvironmentManager,
                 es: Elasticsearch,
                 helper: OpenCTIConnectorHelper,
                 incident_manager: IncidentManager,
                 relationship_manager: RelationshipManager,
                 shutdown_event: Event):
        super(SshScanner, self).__init__(config, env_manager, es, helper, incident_manager,
                                         relationship_manager, shutdown_event)
        self.state_tracking_token = "ssh_scanner_last_run"
        self.known_malicious_hosts = []
        self._lock = threading.Lock()

    def add_known_malicious_incident(self, ip_address: str, incident: MyIncident):
        with self._lock:
            self.known_malicious_hosts.append({"ip_address": ip_address, "incident": incident})

    def get_public_to_public_ssh_traffic_query(self, start: datetime, end: datetime) -> Search:
        s = Search(using=self.elasticsearch, index="filebeat*") \
            .filter("match", fileset__name="connection") \
            .filter("match", destination__port="22")
        for pubnet in self.env_manager.public_networks:
            s = s.query("match", source__ip=pubnet)\
                .query("match", destination__ip=pubnet)

        s.sort("zeek.connection.ts")
        s.extra(track_total_hits=True)

        s = self.es_helper.set_time_range(s, "zeek.connection.ts", start, end)

        return s

    def get_public_to_private_ssh_traffic_query(self, start: datetime, end: datetime):
        s = Search(using=self.elasticsearch, index="filebeat*") \
            .filter("match", fileset__name="connection") \
            .filter("match", destination__port="22")
        for pubnet in self.env_manager.public_networks:
            s = s.query("match", source__ip=pubnet) \
                .exclude("match", destination__ip=pubnet)

        s.sort("zeek.connection.ts")
        s.extra(track_total_hits=True)

        s = self.es_helper.set_time_range(s, "zeek.connection.ts", start, end)

        return s

    def get_malicious_host_ssh_traffic_query(self, ip_address, start: datetime, end: datetime):
        query = """{"query": {"bool": {"should": [{"term":{"source.ip": """ + \
                f"\"{ip_address}\"" + \
                """}},{"term":{"destination.ip": """ + \
                f"\"{ip_address}\"" + \
                """}}],"minimum_should_match": 1}}}"""
        s = Search(using=self.elasticsearch, index="filebeat*")
        s.update_from_dict(query)
        s = s.filter("match", fileset__name="ssh")
        s.sort("zeek.ssh.ts")
        s.extra(track_total_hits=True)

        s = self.es_helper.set_time_range(s, "zeek.ssh.ts", start, end)

        return s

    def process_search(self, search: Search):
        malicious_hosts: dict[str, SshHost] = {}
        for hit in search.scan():
            ts = hit["@timestamp"]
            timestamp = ciso8601.parse_datetime(ts)

            if hit.source.ip in malicious_hosts:
                malicious_host = malicious_hosts[hit.source.ip]
                malicious_host.hits += 1
            else:
                malicious_host = SshHost(hit.source.ip)
                malicious_hosts[hit.source.ip] = malicious_host

            current_target = None
            for target in malicious_host.targets:
                if target.ip_address == hit.destination.ip and not target.finished:
                    current_target = target
                    break

            if current_target is not None:
                if timestamp < current_target.start:
                    current_target.start = timestamp
                if timestamp > current_target.end:
                    current_target.end = timestamp
            else:
                current_target = SshTarget(hit.destination.ip, timestamp)
                malicious_host.targets.append(current_target)

            if "ssh" in hit.zeek:
                if "auth" in hit.zeek.ssh:
                    if "attempts" in hit.zeek.ssh.auth:
                        current_target.auth_failures += hit.zeek.ssh.auth.attempts
                    if "success" in hit.zeek.ssh.auth:
                        if hit.zeek.ssh.auth.success == "true":
                            current_target.finished = True
                            current_target.success = True
                    else:
                        current_target.finished = True
                else:
                    current_target.scan = True
                    current_target.finished = True
            else:
                current_target.scan = True
                current_target.finished = True
        self.helper.log_info(f"returning {malicious_hosts}")
        return malicious_hosts

    def process_results(self, malicious_hosts):
        self.helper.log_info("Processing malicious hosts")
        valid_accounts_attack_pattern = self.get_attack_pattern_and_kill_chain_phases("VALID ACCOUNTS", "name")
        valid_accounts_kill_chain_phases = []
        if "killChainPhases" in valid_accounts_attack_pattern:
            for kcp in valid_accounts_attack_pattern["killChainPhases"]:
                valid_accounts_kill_chain_phases.append(kcp["standard_id"])
        brute_force_attack_pattern = self.get_attack_pattern_and_kill_chain_phases("T1110")
        brute_force_kill_chain_phases = []
        if "killChainPhases" in valid_accounts_attack_pattern:
            for kcp in valid_accounts_attack_pattern["killChainPhases"]:
                brute_force_kill_chain_phases.append(kcp["standard_id"])
        for malicious_host_key in malicious_hosts:
            self.helper.log_info(f"Processing malicious host {malicious_host_key}")
            malicious_host = malicious_hosts[malicious_host_key]
            if malicious_host.id is None:
                if re.match(self.ipv4_pattern, malicious_host_key):
                    ipv4_address: IPv4Address = self.env_manager.find_or_create_ipv4(malicious_host_key)
                    self.helper.log_info(f"IPv4Address is {ipv4_address}")
                    malicious_host.id = ipv4_address["standard_id"]
                else:
                    ipv6_address = self.env_manager.find_or_create_ipv6(malicious_host_key)
                    self.helper.log_info(f"IPv6Address is {ipv6_address}")
                    malicious_host.id = ipv6_address["standard_id"]

            self.helper.api.stix_cyber_observable.add_label(
                id=malicious_host.id,
                label_name="malicious-activity"
            )

            self.env_manager.add_item_to_report(malicious_host.id)

            for target in malicious_host.targets:
                ip_sector = self.env_manager.get_sector_for_ip_addr(target.ip_address)
                my_incident = self.incident_manager.find_or_create_incident(target.start.timestamp() * 1000,
                                                                            target.end.timestamp() * 1000)
                if my_incident.stix_id == "":
                    self.incident_manager.write_incident_to_opencti(my_incident)

                description = f"{malicious_host_key} initiated ssh connections to {target.ip_address}."
                relationship = self.relationship_manager.find_or_create_relationship(
                    relationship_type="related-to",
                    fromId=malicious_host.id,
                    toId=my_incident.stix_id,
                    start_time=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    stop_time=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    confidence=self.confidence,
                    createdBy=self.author,
                    description=description
                )
                self.env_manager.add_item_to_report(relationship["standard_id"])

                fake_scan = FakeScan(target.start, target.end)
                self.link_attack_pattern(my_incident,
                                         valid_accounts_attack_pattern["attack_pattern"],
                                         fake_scan,
                                         valid_accounts_attack_pattern["kill_chain_phases"] if "kill_chain_phases" in
                                                                                               valid_accounts_attack_pattern else None)

                if target.auth_failures > 2:
                    self.link_attack_pattern(my_incident,
                                             brute_force_attack_pattern["attack_pattern"],
                                             fake_scan,
                                             brute_force_attack_pattern["kill_chain_phases"] if "kill_chain_phases" in
                                                                                                brute_force_attack_pattern else None)

                if ip_sector is not None:
                    self.env_manager.add_item_to_report(ip_sector)
                    relationship = self.relationship_manager.find_or_create_relationship(
                        relationship_type="targets",
                        fromId=my_incident.stix_id,
                        toId=ip_sector,
                        start_time=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                        stop_time=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                        confidence=self.confidence,
                        createdBy=self.author
                    )

                    self.env_manager.add_item_to_report(relationship["standard_id"])

                for threat_actor in self.env_manager.threat_actors:
                    relationship = self.relationship_manager.find_or_create_relationship(
                        relationship_type="targets",
                        fromId=threat_actor,
                        toId=ip_sector,
                        start_time=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                        stop_time=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                        confidence=self.confidence,
                        createdBy=self.author
                    )
                    if relationship is not None:
                        self.env_manager.add_item_to_report(relationship["standard_id"])

                for intrusion_set in self.env_manager.intrusion_sets:
                    relationship = self.relationship_manager.find_or_create_relationship(
                        relationship_type="targets",
                        fromId=intrusion_set,
                        toId=ip_sector,
                        start_time=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                        stop_time=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                        confidence=self.confidence,
                        createdBy=self.author
                    )
                    if relationship is not None:
                        self.env_manager.add_item_to_report(relationship["standard_id"])

                target_id = None
                if re.match(self.ipv4_pattern, target.ip_address):
                    ipv4_address: IPv4Address = self.env_manager.find_or_create_ipv4(target.ip_address)
                    self.helper.log_info(f"IPv4Address is {ipv4_address}")
                    target_id = ipv4_address["standard_id"]
                else:
                    ipv6_address = self.env_manager.find_or_create_ipv6(target.ip_address)
                    self.helper.log_info(f"IPv6Address is {ipv6_address}")
                    target_id = ipv6_address["standard_id"]

                if target_id is not None:
                    od_objects = [target_id, my_incident.stix_id,
                                  malicious_host.id, valid_accounts_attack_pattern["attack_pattern"]["standard_id"]]
                    if target.auth_failures > 3:
                        od_objects.append(brute_force_attack_pattern["attack_pattern"]["standard_id"])
                    self.env_manager.add_item_to_report(target_id)
                    observed_data = self.helper.api.observed_data.create(
                        createdBy=self.author,
                        first_observed=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                        last_observed=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                        objects=[target_id, my_incident.stix_id,
                                 malicious_host.id, valid_accounts_attack_pattern["attack_pattern"]["standard_id"]],
                        number_observed=1,
                        confidence=self.confidence
                    )
                    self.env_manager.add_item_to_report(observed_data["standard_id"])
                    description = f"{malicious_host_key} initiated ssh connections to {target.ip_address} " + \
                                  f"during this attempt.  There were {target.auth_failures} authentication failures."

                    relationship = self.relationship_manager.find_or_create_relationship(
                        relationship_type="related-to",
                        fromId=target_id,
                        toId=my_incident.stix_id,
                        start_time=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                        stop_time=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                        confidence=self.confidence,
                        createdBy=self.author,
                        description=description
                    )
                    if relationship is not None:
                        self.env_manager.add_item_to_report(relationship["standard_id"])
                    self.helper.api.stix_cyber_observable.add_label(
                        id=target_id,
                        label_name="targeted"
                    )

    def run(self) -> None:
        self.helper.log_info("SSH scanner thread starting")

        """Main loop"""
        while not self.shutdown_event.is_set():
            try:
                run_stuff = self.get_should_run(self.state_tracking_token)
                if "should_run" in run_stuff and run_stuff["should_run"]:
                    now = datetime.utcfromtimestamp(run_stuff["timestamp"])
                    last_timestamp = datetime.utcfromtimestamp(run_stuff["last_run"]) if run_stuff["last_run"] is not \
                                                                                         None else None
                    search: Search = self.get_public_to_public_ssh_traffic_query(start=last_timestamp, end=now)
                    self.helper.log_info(f"{search.to_dict()}")
                    malicious_hosts = self.process_search(search)
                    self.process_results(malicious_hosts)

                    search: Search = self.get_public_to_private_ssh_traffic_query(start=last_timestamp, end=now)
                    self.helper.log_info(f"{search.to_dict()}")
                    malicious_hosts = self.process_search(search)
                    self.process_results(malicious_hosts)

                    current_malicious_entries = []
                    with self._lock:
                        current_malicious_entries = self.known_malicious_hosts.copy()
                        self.known_malicious_hosts.clear()

                    for current_malicious_entry in current_malicious_entries:
                        search = self.get_malicious_host_ssh_traffic_query(current_malicious_entry["ip_address"],
                                                                           current_malicious_entry["incident"].start,
                                                                           current_malicious_entry["incident"].end)
                        malicious_hosts = self.process_search(search)
                        self.process_results(malicious_hosts)

                    self.mark_last_run(self.state_tracking_token, run_stuff["timestamp"])
                    self.shutdown_event.wait(self.interval)
            except Exception as e:
                self.helper.log_error(f"Exception in ssh scanner {e}")
                traceback.print_exc()
