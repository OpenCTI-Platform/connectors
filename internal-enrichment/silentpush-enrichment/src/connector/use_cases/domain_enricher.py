from connectors_sdk.models import (
    AutonomousSystem,
    DomainName,
    Hostname,
    IPV4Address,
    Organization,
)
from connectors_sdk.models.enums import RelationshipType

from .enricher import Enricher


class DomainEnricher(Enricher):
    API_TYPE = "domain"
    OCTI_CLASS = DomainName

    def build_domain(self) -> None:
        """
        Add Domain enriched data to the octi bundle
        """

        self.domain = self.OCTI_CLASS(
            value=self.stix_entity.get("value"),
            score=self.enriched_data.get("sp_risk_score"),
        )
        self.source = self.domain
        self.build_labels()
        self.octi_observables.append(self.source)

    def build_registrar(self) -> None:
        """
        Add Registrar enriched data to the octi bundle
        """
        registrar_name = self.enriched_data.get("domaininfo", {}).get("registrar")
        if not registrar_name:
            return
        registrar = Organization(
            name=registrar_name,
        )
        self.add_target_and_relationship(
            registrar, RelationshipType.RELATED_TO, "Registrar"
        )

    def build_ns_reputation(self) -> None:
        """
        Add Name Server enriched data to the octi bundle
        """
        ns_list = self.enriched_data.get("ns_reputation", {}).get("ns_srv_reputation")
        if not ns_list:
            return
        for ns in ns_list:
            domain_name = ns.get("domain")
            if domain_name == self.domain.value:
                continue
            self.helper.connector_logger.debug(f"building Name Server: {ns}")
            domain = DomainName(
                value=domain_name,
            )
            self.add_target_and_relationship(
                domain, RelationshipType.RELATED_TO, "Apex Domain"
            )
            ns_server = ns.get("ns_server")
            if not ns_server:
                continue
            hostname = Hostname(value=ns_server)
            self.add_target_and_relationship(
                hostname, RelationshipType.RELATED_TO, "Nameserver"
            )

    def build_asns(self) -> None:
        """
        Build relationships      [ASN]
                                  /
                               [DOMAIN]->[IPv4]->[ASN]
                                  \
                               [HOSTNAME]
        and add it to the octi bundle
        """
        diversity_json = self.client.get_diversity_data(self.domain.value)
        if not diversity_json or not diversity_json.get("records"):
            return
        for asn in diversity_json.get("records"):
            if asn.get("host"):
                hostname = Hostname(value=asn.get("host"))
                self.add_target_and_relationship(
                    hostname, RelationshipType.RELATED_TO, "Hostname"
                )
            for asn_timeline in asn.get("asn_timelines", []):
                ip = asn_timeline.get("ip")
                if not ip:
                    continue
                ipv4 = IPV4Address(value=ip)
                self.add_target_and_relationship(
                    ipv4, RelationshipType.RELATED_TO, "A Record"
                )
                asn_number = asn_timeline.get("asn")
                if not asn_number:
                    continue
                asn_name = asn_timeline.get("asn_name")
                autonomous_system = AutonomousSystem(number=asn_number, name=asn_name)
                self.add_target_and_relationship(
                    autonomous_system, RelationshipType.BELONGS_TO, "ASN"
                )
                self.add_target_and_relationship(
                    autonomous_system, RelationshipType.BELONGS_TO, "ASN", ipv4
                )

    def extract_labels(self) -> dict:
        """
        Extract all boolean flags and return (value, color).
        """
        host_flags = self.enriched_data.get("host_flags", [{}])[0]
        ns_changes = self.enriched_data.get("nschanges", {})
        ns_reputation = self.enriched_data.get("ns_reputation", {})
        domain_urls = self.enriched_data.get("domain_urls", {}).get(
            "results_summary", {}
        )
        domain_info = self.enriched_data.get("domaininfo", {})

        return {
            "alexa_top10k": (domain_urls.get("alexa_top10k"), "#4caf50"),
            "is_dynamic_domain": (
                domain_urls.get("is_dynamic_domain"),
                "#af4c68",
            ),
            "is_url_shortener": (domain_urls.get("is_url_shortener"), "#a1713a"),
            "tranco_top10k": (domain_urls.get("tranco_top10k"), "#782b2e"),
            "is_new": (domain_info.get("is_new"), "#e09109"),
            "host_has_expired_certificate": (
                host_flags.get("host_has_expired_certificate"),
                "#4f96bd",
            ),
            "host_has_open_directory": (
                host_flags.get("host_has_open_directory"),
                "#841a99",
            ),
            "host_has_open_s3_bucket": (
                host_flags.get("host_has_open_s3_bucket"),
                "#070354",
            ),
            "is_private_suffix": (
                self.enriched_data.get("is_private_suffix"),
                "#c795cc",
            ),
            "is_expired": (ns_reputation.get("is_expired"), "#c75f98"),
            "is_parked": (ns_reputation.get("is_parked"), "#4caf50"),
            "is_sinkholed": (ns_reputation.get("is_sinkholed"), "#af4c68"),
            "has_change_circular": (ns_changes.get("has_change_circular"), "#a1713a"),
            "has_change_expire_from": (
                ns_changes.get("has_change_expire_from"),
                "#782b2e",
            ),
            "has_change_expire_to": (ns_changes.get("has_change_expire_to"), "#e09109"),
            "has_change_ns_in_domain_from": (
                ns_changes.get("has_change_ns_in_domain_from"),
                "#4f96bd",
            ),
            "has_change_ns_in_domain_to": (
                ns_changes.get("has_change_ns_in_domain_to"),
                "#841a99",
            ),
            "has_change_ns_srv_domain_density_low_from": (
                ns_changes.get("has_change_ns_srv_domain_density_low_from"),
                "#070354",
            ),
            "has_change_ns_srv_domain_density_low_to": (
                ns_changes.get("has_change_ns_srv_domain_density_low_to"),
                "#c795cc",
            ),
            "has_change_parked_from": (
                ns_changes.get("has_change_parked_from"),
                "#c75f98",
            ),
            "has_change_parked_to": (ns_changes.get("has_change_parked_to"), "#4caf50"),
            "has_change_sinkhole_from": (
                ns_changes.get("has_change_sinkhole_from"),
                "#af4c68",
            ),
            "has_change_sinkhole_to": (
                ns_changes.get("has_change_sinkhole_to"),
                "#a1713a",
            ),
            "last_change_circular_to": (
                ns_changes.get("last_change_circular_to"),
                "#782b2e",
            ),
            "last_change_expire_from": (
                ns_changes.get("last_change_expire_from"),
                "#e09109",
            ),
            "last_change_expire_to": (
                ns_changes.get("last_change_expire_to"),
                "#4f96bd",
            ),
            "last_change_ns_in_domain_from": (
                ns_changes.get("last_change_ns_in_domain_from"),
                "#841a99",
            ),
            "last_change_ns_in_domain_to": (
                ns_changes.get("last_change_ns_in_domain_to"),
                "#070354",
            ),
            "last_change_ns_srv_domain_density_low_from": (
                ns_changes.get("last_change_ns_srv_domain_density_low_from"),
                "#c795cc",
            ),
            "last_change_ns_srv_domain_density_low_to": (
                ns_changes.get("last_change_ns_srv_domain_density_low_to"),
                "#c75f98",
            ),
            "last_change_parked_from": (
                ns_changes.get("last_change_parked_from"),
                "#4caf50",
            ),
            "last_change_parked_to": (
                ns_changes.get("last_change_parked_to"),
                "#af4c68",
            ),
            "last_change_sinkhole_from": (
                ns_changes.get("last_change_sinkhole_from"),
                "#a1713a",
            ),
            "last_change_sinkhole_to": (
                ns_changes.get("last_change_sinkhole_to"),
                "#782b2e",
            ),
        }

    def enrich(self) -> None:
        """
        Enrich a Domain-Name or Hostname
        """
        self.build_domain()
        self.build_registrar()
        self.build_ns_reputation()
        self.build_asns()
        self.build_favicon()
        self.build_certificates()
