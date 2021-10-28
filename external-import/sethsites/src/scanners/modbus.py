import re
import traceback
from datetime import datetime, timedelta
from threading import Event

import ciso8601
import pytz
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2.v21 import IPv4Address, IPv6Address
from scanners import Scanner
from managers import IncidentManager, EnvironmentManager, RelationshipManager, MyIncident
from scalpl import Cut


class ModbusActivity:
    def __init__(self, function):
        self.function = function
        self.hits = 1
        self.logged = 0


class ModbusTarget:
    def __init__(self, ip_address, start: datetime):
        self.ip_address = ip_address
        self.functions = {}
        self.hits = 1
        self.logged = 0
        self.start = start
        self.end = start


class ModbusScan:
    def __init__(self, start: datetime, end: datetime = None, incident: MyIncident = None,
                 fudge_time: timedelta = timedelta(minutes=10)):
        self.fudge_time = fudge_time
        self.incident = incident
        self.targets = {}
        self.start_offset = start - self.fudge_time
        self.start = start
        self.last_event = end if end is not None else start
        self.end_offset = self.last_event + self.fudge_time
        self.hits = 1
        self.flood = False
        self.scan = False
        self.modify = False
        self.steal = False
        self.logged = 0

    def setStartTime(self, start: datetime):
        self.start_offset = start - self.fudge_time
        self.start = start

    def setEndTime(self, end: datetime):
        self.last_event = end
        self.end_offset = end + self.fudge_time


class ModbusAttacker:
    def __init__(self, ip_address):
        self.id = ""
        self.ip_address = ip_address
        self.scans = []
        self.logged = 0


# The modbus scanner uses modbus packets from zeek connection logs to identify modbus scans.
# Looks for discovery, control and overload
# T1018
class ModbusScanner(Scanner):
    def __init__(self,
                 config: Cut,
                 env_manager: EnvironmentManager,
                 es: Elasticsearch,
                 helper: OpenCTIConnectorHelper,
                 incident_manager: IncidentManager,
                 relationship_manager: RelationshipManager,
                 shutdown_event: Event):
        super(ModbusScanner, self).__init__(config, env_manager, es, helper, incident_manager, relationship_manager,
                                            shutdown_event)
        self.state_tracking_token = "modbus_scanner_last_run"
        self.timestamp = "zeek.modbus.ts"

    def get_query(self, start: datetime = None, end: datetime = None) -> Search:
        s = Search(using=self.elasticsearch, index="filebeat*") \
            .filter("match", fileset__name="modbus")
        for host in self.env_manager.get_hosts_with_tag("modbus master"):
            s = s.exclude("match", source__ip=host)
        s = self.add_exclude_ignored_networks_to_search(s)
        s = self.es_helper.set_time_range(s, self.timestamp, start, end)
        # self.helper.log_info(f"Query is {s.to_dict()}")
        return s

    def get_agg_query(self, start: datetime = None, end: datetime = None) -> Search:
        s = Search(using=self.elasticsearch, index="filebeat*") \
            .filter("match", fileset__name="modbus")
        for host in self.env_manager.get_hosts_with_tag("modbus master"):
            s = s.exclude("match", source__ip=host)
        s = self.add_exclude_ignored_networks_to_search(s)
        s = self.es_helper.set_time_range(s, self.timestamp, start, end)
        s.aggs.bucket("source", "terms", field="source.ip", size=999999) \
            .bucket("history", "date_histogram", field=self.timestamp, fixed_interval="1m", min_doc_count=5)
        # self.helper.log_info(f"Query is {s.to_dict()}")
        return s

    def run(self) -> None:
        self.helper.log_info("Modbus scanner thread starting")

        """Main loop"""
        while not self.shutdown_event.is_set():
            try:
                modbus_servers = []
                modbus_server_ips = self.env_manager.get_hosts_with_tag("modbus server")
                self.helper.log_info(f"{modbus_server_ips}")
                for modbus_server_ip in modbus_server_ips:
                    self.helper.log_info(f"{modbus_server_ip}")
                    modbus_servers.append(modbus_server_ip)

                run_stuff = self.get_should_run(self.state_tracking_token)
                if "should_run" in run_stuff and run_stuff["should_run"]:
                    now = datetime.utcfromtimestamp(run_stuff["timestamp"])
                    last_timestamp = datetime.utcfromtimestamp(run_stuff["last_run"]) if run_stuff["last_run"] is not \
                                                                                         None else None
                    search1: Search = self.get_agg_query(start=last_timestamp, end=now)

                    s = search1.execute()
                    # Process the flooding attempts
                    malicious_hosts: dict[str, ModbusAttacker] = {}
                    for item in s.aggregations.source.buckets:
                        # self.helper.log_info(f"Processing {item.key} pinged {item.doc_count} times")

                        if item.key in malicious_hosts:
                            malicious_host = malicious_hosts[item.key]
                        else:
                            malicious_host = ModbusAttacker(item.key)
                            malicious_hosts[item.key] = malicious_host

                        current_incident = {}
                        for history_item in item.history.buckets:

                            if "end_time" in current_incident:
                                if current_incident["end_time"] == history_item.key:
                                    current_incident["end_time"] = history_item.key + 300000
                                    current_incident["hit_count"] = current_incident["hit_count"] + \
                                                                    history_item.doc_count
                                else:
                                    my_incident = self.incident_manager.find_or_create_incident(
                                        current_incident["start_time"],
                                        current_incident["end_time"]
                                    )
                                    nmap_scan = ModbusScan(
                                        datetime.fromtimestamp(my_incident.start / 1000, tz=pytz.UTC),
                                        datetime.fromtimestamp(my_incident.end / 1000, tz=pytz.UTC),
                                        my_incident)
                                    self.helper.log_info("Setting flood")
                                    nmap_scan.flood = True
                                    malicious_host.scans.append(nmap_scan)
                                    current_incident = {}
                            else:
                                current_incident["start_time"] = history_item.key
                                current_incident["end_time"] = history_item.key + 300000
                                current_incident["hit_count"] = history_item.doc_count

                    # self.incident_manager.write_incidents_to_opencti()

                    search2: Search = self.get_query(start=last_timestamp, end=now)
                    search2 = search2.params(scroll='60m')

                    for hit in search2.scan():
                        timestamp = hit.zeek.modbus.ts
                        ts = ciso8601.parse_datetime(timestamp)

                        if hit.source.ip in malicious_hosts:
                            malicious_host = malicious_hosts[hit.source.ip]
                        else:
                            malicious_host = ModbusAttacker(hit.source.ip)
                            malicious_hosts[hit.source.ip] = malicious_host

                        current_scan = None
                        for scan in malicious_host.scans:
                            if scan.start_offset <= ts <= scan.end_offset:
                                current_scan = scan

                                if ts < current_scan.start:
                                    current_scan.setStartTime(ts)
                                if ts > current_scan.last_event:
                                    current_scan.setEndTime(ts)
                                break
                        if current_scan is None:
                            inc_timestamp = ts.timestamp()
                            current_incident = self.incident_manager.find_or_create_incident(inc_timestamp * 1000,
                                                                                             inc_timestamp * 1000)
                            current_scan = ModbusScan(ts, incident=current_incident)
                            malicious_host.scans.append(current_scan)

                        if hit.destination.ip not in modbus_servers:
                            current_scan.scan = True
                        else:
                            if hit.zeek.modbus.function in ["WRITE_SINGLE_COIL", "WRITE_MULTIPLE_COILS"]:
                                current_scan.modify = True
                            if hit.zeek.modbus.function in ["READ_SINGLE_COIL", "READ_MULTIPLE_COILS"]:
                                current_scan.steal = True

                        if hit.destination.ip in current_scan.targets:
                            target = current_scan.targets[hit.destination.ip]
                            target.hits += 1

                            if ts < target.start:
                                target.start = ts
                            if ts > target.end:
                                target.end = ts
                        else:
                            target = ModbusTarget(hit.destination.ip, ts)
                            current_scan.targets[hit.destination.ip] = target

                        if hit.zeek.modbus.function not in target.functions:
                            port = ModbusActivity(hit.zeek.modbus.function)
                            target.functions[hit.zeek.modbus.function] = port
                        else:
                            function = target.functions[hit.zeek.modbus.function]
                            function.hits += 1

                    # cup_attack_pattern = self.get_attack_pattern_and_kill_chain_phases("COMMONLY USED PORT", "name")
                    rogue_attack_pattern = self.get_attack_pattern_and_kill_chain_phases("ROGUE MASTER", "name")
                    scan_attack_pattern = self.get_attack_pattern_and_kill_chain_phases("T1018")
                    flood_attack_pattern = self.get_attack_pattern_and_kill_chain_phases("T1498.001")
                    damage_attack_pattern = self.get_attack_pattern_and_kill_chain_phases("DAMAGE TO PROPERTY", "name")
                    ucm_attack_pattern = self.get_attack_pattern_and_kill_chain_phases("UNAUTHORIZED COMMAND MESSAGE",
                                                                                       "name")
                    mps_attack_pattern = self.get_attack_pattern_and_kill_chain_phases("MONITOR PROCESS STATE", "name")

                    for malicious_host_key in malicious_hosts:
                        self.helper.log_info(f"Malicious host key is {malicious_host_key}")
                        malicious_host = malicious_hosts[malicious_host_key]
                        if malicious_host.id == "":
                            if re.match(self.ipv4_pattern, malicious_host_key):
                                ipv4_address: IPv4Address = self.env_manager.find_or_create_ipv4(malicious_host_key)
                                self.helper.log_info(f"IPv4Address is {ipv4_address}")
                                malicious_host.id = ipv4_address["standard_id"]
                            else:
                                ipv6_address = self.env_manager.find_or_create_ipv6(malicious_host_key)
                                self.helper.log_info(f"IPv6Address is {ipv6_address}")
                                malicious_host.id = ipv6_address["standard_id"]

                        self.env_manager.add_item_to_report(malicious_host.id)
                        self.helper.api.stix_cyber_observable.add_label(
                            id=malicious_host.id,
                            label_name="malicious-activity"
                        )

                        for scan in malicious_host.scans:
                            my_incident = scan.incident
                            if my_incident.stix_id == "":
                                my_incident = self.incident_manager.write_incident_to_opencti(my_incident)

                            command_counts = {}
                            for target_key in scan.targets:
                                target = scan.targets[target_key]
                                for function_key in target.functions:
                                    function = target.functions[function_key]
                                    if function_key in command_counts:
                                        command_counts[function_key] += function.hits
                                    else:
                                        command_counts[function_key] = function.hits

                            description = f"{malicious_host_key} initiated modbus traffic to {len(scan.targets)} " +  \
                                          f"target(s) during this attack.  The systems targeted in this attack are " + \
                                          f"[{', '.join(scan.targets)}]. "
                            for function in command_counts:
                                description = description + f"{function} was called {command_counts[function]} times. "

                            relationship = self.relationship_manager.find_or_create_relationship(
                                relationship_type="related-to",
                                fromId=malicious_host.id,
                                toId=my_incident.stix_id,
                                start_time=scan.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                stop_time=scan.last_event.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                confidence=self.confidence,
                                createdBy=self.author,
                                description=description
                            )
                            if relationship is not None:
                                self.env_manager.add_item_to_report(relationship["standard_id"])

                            for target_key in scan.targets:
                                target = scan.targets[target_key]
                                ip_sector = self.env_manager.get_sector_for_ip_addr(target_key)
                                if ip_sector is not None:
                                    relationship = self.relationship_manager.find_or_create_relationship(
                                        relationship_type="targets",
                                        fromId=my_incident.stix_id,
                                        toId=ip_sector,
                                        start_time=scan.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                        stop_time=scan.last_event.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
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
                                    observed_data = self.helper.api.observed_data.create(
                                        createdBy=self.author,
                                        first_observed=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                        last_observed=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                        objects=[target_id, my_incident.stix_id, malicious_host.id],
                                        number_observed=target.hits,
                                        confidence=self.confidence
                                    )
                                    if observed_data is not None:
                                        self.env_manager.add_item_to_report(observed_data["standard_id"])
                                    relationship = self.relationship_manager.find_or_create_relationship(
                                        relationship_type="related-to",
                                        fromId=target_id,
                                        toId=my_incident.stix_id,
                                        start_time=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                        stop_time=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                        confidence=self.confidence,
                                        createdBy=self.author,
                                        description=f"{malicious_host_key} called {len(target.functions)} functions on " +
                                                    f"{target_key}.  {target_key} was hit a total of {target.hits} " +
                                                    f"times during this attack.  The functions called were " +
                                                    f"[{', '.join(target.functions)}]"
                                    )
                                    if relationship is not None:
                                        self.env_manager.add_item_to_report(relationship["standard_id"])
                                    self.helper.api.stix_cyber_observable.add_label(
                                        id=target_id,
                                        label_name="targeted"
                                    )

                            if scan.flood:
                                for atp in [rogue_attack_pattern, flood_attack_pattern, ucm_attack_pattern]:
                                    self.link_attack_pattern(my_incident, atp["attack_pattern"], scan, atp["kill_chain_phases"])
                            if scan.modify:
                                for atp in [rogue_attack_pattern, damage_attack_pattern, ucm_attack_pattern]:
                                    self.link_attack_pattern(my_incident, atp["attack_pattern"], scan, atp["kill_chain_phases"])
                            if scan.steal:
                                for atp in [rogue_attack_pattern, mps_attack_pattern, ucm_attack_pattern]:
                                    self.link_attack_pattern(my_incident, atp["attack_pattern"], scan, atp["kill_chain_phases"])
                            if scan.scan:
                                for atp in [scan_attack_pattern]:
                                    self.link_attack_pattern(my_incident, atp["attack_pattern"], scan, atp["kill_chain_phases"])

                    # self.helper.log_info(f"attack pattern {attack_pattern}")
                    self.mark_last_run(self.state_tracking_token, run_stuff["timestamp"])
                self.shutdown_event.wait(self.interval)
            except Exception as e:
                self.helper.log_error(f"Exception in nmap scanner {e}")
                traceback.print_exc()
