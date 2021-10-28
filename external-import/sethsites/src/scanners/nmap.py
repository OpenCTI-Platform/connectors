import re
import ciso8601
import traceback
from datetime import datetime
from threading import Event

import pytz
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from pycti import OpenCTIConnectorHelper
from scanners import Scanner
from managers import IncidentManager, MyIncident, EnvironmentManager, RelationshipManager
from scalpl import Cut
from stix2.v21 import IPv4Address, IPv6Address


class NmapPortTarget:
    def __init__(self, port_number, state):
        self.port_number: int = port_number
        self.state: str = state
        self.attempts: int = 1


class NmapScanTarget:
    def __init__(self, ip_address: str, start: datetime):
        self.ip_address: str = ip_address
        self.ports: dict[int, NmapPortTarget] = {}
        self.hits: int = 1
        self.start = start
        self.end = start


class NmapScan:
    def __init__(self, start: datetime, end: datetime, incident: MyIncident):
        self.period_start: datetime = start
        self.start: datetime = start
        self.last_event: datetime = end
        self.period_end: datetime = end
        self.targets: dict[str: NmapScanTarget] = {}
        self.incident = incident
        self.start_end_reset = False


class NmapScanHost:
    def __init__(self, ip_address: str):
        self.ip_address: str = ip_address
        self.id = None
        self.scans: [NmapScan] = []
        self.hits: int = 1


# The nmap scanner uses rejected packets from zeek logs to identify port scans.  Not all hosts set back REJ packets
# but it should be good enough to identify sweep attempts
# T1046
class NmapScanner(Scanner):
    def __init__(self,
                 config: Cut,
                 env_manager: EnvironmentManager,
                 es: Elasticsearch,
                 helper: OpenCTIConnectorHelper,
                 incident_manager: IncidentManager,
                 relationship_manager: RelationshipManager,
                 shutdown_event: Event):
        super(NmapScanner, self).__init__(config, env_manager, es, helper, incident_manager, relationship_manager,
                                          shutdown_event)
        self.state_tracking_token = "nmap_scanner_last_run"

    def get_query(self, start: datetime = None, end: datetime = None) -> Search:
        s = Search(using=self.elasticsearch, index="filebeat*") \
            .filter("match", network__transport="tcp") \
            .filter("match", zeek__connection__state="REJ")
        s = self.add_exclude_ignored_networks_to_search(s)
        s = self.es_helper.set_time_range(s, "zeek.connection.ts", start, end)
        return s

    def get_agg_query(self, start: datetime = None, end: datetime = None) -> Search:
        s = Search(using=self.elasticsearch, index="filebeat*") \
            .filter("match", network__transport="tcp") \
            .filter("match", zeek__connection__state="REJ")
        s = self.add_exclude_ignored_networks_to_search(s)
        s = self.es_helper.set_time_range(s, "zeek.connection.ts", start, end)
        s.aggs.bucket("source", "terms", field="source.ip", size=999999) \
            .bucket("history", "date_histogram", field="zeek.connection.ts", fixed_interval="1m", min_doc_count=100)
        return s

    def run(self) -> None:
        self.helper.log_info("Nmap scanner thread starting")

        """Main loop"""
        while not self.shutdown_event.is_set():
            try:
                run_stuff = self.get_should_run(self.state_tracking_token)
                if "should_run" in run_stuff and run_stuff["should_run"]:
                    now = datetime.utcfromtimestamp(run_stuff["timestamp"])
                    last_timestamp = datetime.utcfromtimestamp(run_stuff["last_run"]) if run_stuff["last_run"] is not \
                                                                                         None else None
                    search: Search = self.get_agg_query(start=last_timestamp, end=now)

                    s = search.execute()
                    malicious_hosts: dict[str, NmapScanHost] = {}
                    for item in s.aggregations.source.buckets:
                        self.helper.log_info(f"Processing {item.key} pinged {item.doc_count} times")
                        if item.key in malicious_hosts:
                            malicious_host = malicious_hosts[item.key]
                        else:
                            malicious_host = NmapScanHost(item.key)
                            malicious_hosts[item.key] = malicious_host

                        current_incident = {}
                        for history_item in item.history.buckets:
                            if "end_time" in current_incident:
                                if current_incident["end_time"] == history_item.key:
                                    current_incident["end_time"] = history_item.key + 300000
                                    current_incident["hit_count"] = current_incident["hit_count"] + \
                                                                    history_item.doc_count
                                else:
                                    # self.helper.log_info(f"{current_incident}")
                                    my_incident = self.incident_manager.find_or_create_incident(
                                        current_incident["start_time"],
                                        current_incident["end_time"]
                                    )
                                    nmap_scan = NmapScan(
                                        datetime.fromtimestamp(current_incident["start_time"] / 1000, tz=pytz.UTC),
                                        datetime.fromtimestamp(current_incident["end_time"] / 1000, tz=pytz.UTC),
                                        my_incident)
                                    malicious_host.scans.append(nmap_scan)
                                    current_incident = {}
                            else:
                                current_incident["start_time"] = history_item.key
                                current_incident["end_time"] = history_item.key + 300000
                                current_incident["hit_count"] = history_item.doc_count

                    # self.incident_manager.write_incidents_to_opencti()
                    # malicious_hosts: dict[str: NmapScanHost] = {}

                    search: Search = self.get_agg_query(start=last_timestamp, end=now)

                    for hit in search.scan():
                        ts = hit.zeek.connection.ts
                        timestamp = ciso8601.parse_datetime(ts)
                        # self.helper.log_info(f"{ts} {hit.destination.ip} {hit.zeek.connection.state}")
                        if hit.source.ip in malicious_hosts:
                            malicious_host = malicious_hosts[hit.source.ip]
                            malicious_host.hits += 1
                        else:
                            malicious_host = NmapScanHost(hit.source.ip)
                            malicious_hosts[hit.source.ip] = malicious_host

                        current_scan = None
                        for scan in malicious_host.scans:
                            # self.helper.log_info(f"{scan.start} {ciso8601.parse_datetime(ts)} {scan.end}")
                            if scan.period_start < timestamp < scan.period_end:
                                current_scan = scan
                                break
                        if current_scan is not None:
                            if timestamp < current_scan.start:
                                current_scan.start = timestamp
                            if timestamp > current_scan.last_event:
                                current_scan.last_event = timestamp
                            if hit.destination.ip in current_scan.targets:
                                target = current_scan.targets[hit.destination.ip]
                                target.hits += 1

                                if timestamp < target.start:
                                    target.start = timestamp
                                if timestamp > target.end:
                                    target.end = timestamp
                            else:
                                target = NmapScanTarget(hit.destination.ip, timestamp)
                                current_scan.targets[hit.destination.ip] = target

                            if "port" in hit.destination:
                                if hit.destination.port not in target.ports:
                                    port = NmapPortTarget(hit.destination.port, hit.zeek.connection.state)
                                    target.ports[hit.destination.port] = port
                                else:
                                    port = target.ports[hit.destination.port]
                                    port.attempts += 1

                    attack_pattern = self.get_attack_pattern_and_kill_chain_phases("T1046")

                    kill_chain_phases = []
                    if "killChainPhases" in attack_pattern:
                        for kcp in attack_pattern["killChainPhases"]:
                            kill_chain_phases.append(kcp["standard_id"])
                    for malicious_host_key in malicious_hosts:
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

                        self.helper.log_info(f"{malicious_host.id}")
                        for scan in malicious_host.scans:
                            my_incident = self.incident_manager.find_or_create_incident(scan.start.timestamp() * 1000,
                                                                                        scan.last_event.timestamp() * 1000)
                            if my_incident.stix_id == "":
                                self.incident_manager.write_incident_to_opencti(my_incident)

                            relationship = self.relationship_manager.find_or_create_relationship(
                                relationship_type="related-to",
                                fromId=malicious_host.id,
                                toId=my_incident.stix_id,
                                start_time=scan.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                stop_time=scan.last_event.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                confidence=self.confidence,
                                createdBy=self.author
                            )
                            if relationship is not None:
                                self.env_manager.add_item_to_report(relationship["standard_id"])

                            self.link_attack_pattern(my_incident,
                                                     attack_pattern["attack_pattern"],
                                                     scan,
                                                     attack_pattern["kill_chain_phases"] if "kill_chain_phases" in
                                                                                            attack_pattern else None)

                            for target_key in scan.targets:
                                target = scan.targets[target_key]
                                ip_sector = self.env_manager.get_sector_for_ip_addr(target_key)
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
                                    if relationship is not None:
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
                                if re.match(self.ipv4_pattern, target_key):
                                    ipv4_address: IPv4Address = self.env_manager.find_or_create_ipv4(target_key)
                                    self.helper.log_info(f"IPv4Address is {ipv4_address}")
                                    target_id = ipv4_address["standard_id"]
                                else:
                                    ipv6_address = self.env_manager.find_or_create_ipv6(target_key)
                                    self.helper.log_info(f"IPv6Address is {ipv6_address}")
                                    target_id = ipv6_address["standard_id"]

                                if target_id is not None:
                                    self.env_manager.add_item_to_report(target_id)
                                    observed_data = self.helper.api.observed_data.create(
                                        createdBy=self.author,
                                        first_observed=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                        last_observed=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                        objects=[target_id, my_incident.stix_id,
                                                 malicious_host.id, attack_pattern["attack_pattern"]["standard_id"]],
                                        number_observed=target.hits,
                                        confidence=self.confidence
                                    )
                                    if observed_data is not None:
                                        self.env_manager.add_item_to_report(observed_data["standard_id"])
                                    description=f"{malicious_host_key} scanned {len(target.ports)} ports on " + \
                                                f"{target_key}.  {target_key} was hit a total of {target.hits} " + \
                                                f"times during this scan.  The ports scanned were " + \
                                                f"["
                                    counter = 0
                                    for port in target.ports:
                                        if counter > 0:
                                            description = description + ", " + str(port)
                                        else:
                                            description = description + str(port)
                                    description = description + "]"

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

                    self.mark_last_run(self.state_tracking_token, run_stuff["timestamp"])
                self.shutdown_event.wait(self.interval)
            except Exception as e:
                self.helper.log_error(f"Exception in nmap scanner {e}")
                traceback.print_exc()
