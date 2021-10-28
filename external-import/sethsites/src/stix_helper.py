from stix2.v21 import (Location, Identity, IPv4Address, Relationship, Bundle, NetworkTraffic, Indicator,
                       ThreatActor, IntrusionSet)


class StixHelper:
    def __init__(self, environment=None):
        if environment is None:
            environment = {}
        self.environment = environment

    def generate_environment_stix_bundle(self):
        bundle_objects = []
        private_networks = []
        public_networks = []

        for city in self.environment["cities"]:
            location = Location(
                id=city["id"],
                city=city["name"],
                latitude=city["latitude"],
                longitude=city["longitude"]
            )
            bundle_objects.append(location)

            for network in city["networks"]:
                if network["public"] == "true":
                    public_networks.append(network)
                else:
                    private_networks.append(network)

                ip_network = IPv4Address(
                    id=network["id"],
                    value=network["ip_range"],

                )
                bundle_objects.append(ip_network)

                network_relationship = Relationship(
                    source_ref=network["id"],
                    target_ref=city["id"],
                    relationship_type="located-at",
                    confidence=100
                )
                bundle_objects.append(network_relationship)

            for sector in city["sectors"]:
                stix_sector = Identity(
                    id=sector["id"],
                    name=sector["name"],
                    description=sector["name"],
                    identity_class="sector"
                )
                bundle_objects.append(stix_sector)

                sector_relationship = Relationship(
                    source_ref=sector["id"],
                    target_ref=city["id"],
                    relationship_type="related-to",
                    confidence=100
                )
                bundle_objects.append(sector_relationship)

                for host in sector["hosts"]:
                    stix_host = IPv4Address(
                        id=host["id"],
                        value=host["ip_address"]
                    )
                    bundle_objects.append(stix_host)

                    host_sector_relationship = Relationship(
                        source_ref=host["id"],
                        target_ref=sector["id"],
                        relationship_type="related-to",
                        confidence=100
                    )
                    bundle_objects.append(host_sector_relationship)

                    host_city_relationship = Relationship(
                        source_ref=host["id"],
                        target_ref=city["id"],
                        relationship_type="located-at",
                        confidence=100
                    )
                    bundle_objects.append(host_city_relationship)

            for public_network in public_networks:
                public_range = public_network["ip_range"]
                for private_network in private_networks:
                    private_range = private_network["ip_range"]

                    network_traffic = NetworkTraffic(
                        src_ref=public_network["id"],
                        dst_ref=private_network["id"],
                        protocols=['ipv4',
                                   'icmp']
                    )
                    bundle_objects.append(network_traffic)

                    ping_indicator = Indicator(
                        name=f"Ping from public to private :: {public_range} -> {private_range}",
                        pattern_type="stix",
                        indicator_types=["malicious-activity"],
                        pattern=f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:src_ref.type = " +
                                f"'ipv4-addr' AND network-traffic:src_ref.value = '{public_range}' AND " +
                                f"network-traffic:dst_ref.value = '{private_range}' AND " +
                                "network-traffic:protocols[*] = 'icmp']"
                    )
                    bundle_objects.append(ping_indicator)

                    network_traffic_relationship = Relationship(
                        source_ref=network_traffic["id"],
                        target_ref=ping_indicator["id"],
                        relationship_type="indicates",
                        confidence=100
                    )

                    bundle_objects.append(network_traffic_relationship)

                network_traffic = NetworkTraffic(
                    src_ref=public_network["id"],
                    dst_port=22,
                    protocols=['ipv4', 'tcp', 'ssh']
                )
                bundle_objects.append(network_traffic)

                ssh_indicator = Indicator(
                    name=f"SSH from public network :: {public_range} -> any",
                    pattern_type="stix",
                    indicator_types=["malicious-activity"],
                    pattern="[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = " +
                            f"'{public_range}' AND network-traffic:dst_port = '22' AND network-traffic:protocols[*] " +
                            f"= 'tcp']"
                )
                bundle_objects.append(ssh_indicator)

                network_traffic_relationship = Relationship(
                    source_ref=network_traffic["id"],
                    target_ref=ssh_indicator["id"],
                    relationship_type="indicates",
                    confidence=100
                )

                bundle_objects.append(network_traffic_relationship)

        for threat in self.environment["threats"]:
            threat_actor = ThreatActor(
                id=threat["id"],
                name=threat["name"],
                description=threat["description"],
                confidence=100
            )
            bundle_objects.append(threat_actor)

            for city in self.environment["cities"]:
                ta_city_relationship = Relationship(
                    source_ref=threat_actor["id"],
                    target_ref=city["id"],
                    relationship_type="related-to",
                    confidence=100
                )
                bundle_objects.append(ta_city_relationship)

            for int_set in threat["intrusion_sets"]:
                intrusion_set = IntrusionSet(
                    id=int_set["id"],
                    name=int_set["name"],
                    description=int_set["description"]
                )
                bundle_objects.append(intrusion_set)

                int_set_relationship = Relationship(
                    source_ref=intrusion_set["id"],
                    target_ref=threat_actor["id"],
                    relationship_type="related-to",
                    confidence=100
                )
                bundle_objects.append(int_set_relationship)

        return Bundle(objects=bundle_objects)
