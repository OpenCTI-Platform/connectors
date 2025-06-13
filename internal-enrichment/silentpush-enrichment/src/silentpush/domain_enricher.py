import json
import uuid

import pycti
import requests
from pycti import CustomObservableHostname, StixCoreRelationship
from settings import API_KEY, API_VERIFY_CERT
from stix2 import AutonomousSystem, DomainName, Identity, IPv4Address, Relationship

from .enricher import Enricher


class DomainEnricher(Enricher):
    """
    The Domain Enrichment class
    """

    _domain = None
    _domain_urls = dict()
    _domain_info = dict()
    _ns_reputation = dict()

    def _extract_domain_string_frequency_probability(self):
        domain_string = (
            self._enriched_data.get("domain_string_frequency_probability", {}) or {}
        )
        return {
            "x-avg_probability": domain_string.get("avg_probability"),
            "x-dga_probability_score": domain_string.get("dga_probability_score"),
        }

    def _extract_domain_urls(self):
        return {
            "x-alexa_rank": self._domain_urls.get("alexa_rank"),
            "x-tranco_rank": self._domain_urls.get("tranco_rank"),
            # TODO: probably there's more verdicrs to extract
            "x-phishing": (self._domain_urls.get("verdicts", {}) or {}).get("phishing"),
        }

    def _extract_domain_info(self):
        return {
            "age": self._domain_info.get("age"),
            "domain": self._domain_info.get("domain"),
            "first_seen": self._domain_info.get("first_seen"),
            "last_seen": self._domain_info.get("last_seen"),
            "registrar": self._domain_info.get("registrar"),
            "whois_age": self._domain_info.get("whois_age"),
            "whois_created_date": self._domain_info.get("whois_created_date"),
            "zone": self._domain_info.get("zone"),
        }

    def _extract_flags(self):
        host_flags = self._enriched_data.get("host_flags")[0]
        ns_changes = self._enriched_data.get("nschanges", {}) or {}
        return {
            "alexa_top10k": (self._domain_urls.get("alexa_top10k"), "#4caf50"),
            "is_dynamic_domain": (
                self._domain_urls.get("is_dynamic_domain"),
                "#af4c68",
            ),
            "is_url_shortener": (self._domain_urls.get("is_url_shortener"), "#a1713a"),
            "tranco_top10k": (self._domain_urls.get("tranco_top10k"), "#782b2e"),
            "is_new": (self._domain_info.get("is_new"), "#e09109"),
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
                self._enriched_data.get("is_private_suffix"),
                "#c795cc",
            ),
            "is_expired": (self._ns_reputation.get("is_expired"), "#c75f98"),
            "is_parked": (self._ns_reputation.get("is_parked"), "#4caf50"),
            "is_sinkholed": (self._ns_reputation.get("is_sinkholed"), "#af4c68"),
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

    def _build_ns_reputations(self):
        """
        Adds Nameserver within their reputations enriched data to
        the stix bundle
        """

        for ns in self._ns_reputation.get("ns_srv_reputation", []):
            self._helper.log_debug(f"building ns reputation '{ns.get('ns_server')}'")
            if ns.get("domain") != self._domain.value:
                domain = DomainName(type="domain-name", value=ns.get("domain"))
                self._observed_data_refs.append(domain.id)
                self._stix_objects.append(domain)
                relationship = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", self._domain.value, domain.id
                    ),
                    relationship_type="related-to",
                    target_ref=domain.id,
                    description="Apex Domain",
                    source_ref=self._domain.id,
                    allow_custom=True,
                    created_by_ref=self._author["id"],
                )
                self._stix_objects.append(relationship)
            if not ns.get("ns_server"):
                continue
            nameserver = CustomObservableHostname(
                value=ns.get("ns_server"),
                custom_properties={
                    "x-ns_server_domain_density": ns.get("ns_server_domain_density"),
                    "x-ns_server_domains_listed": ns.get("ns_server_domains_listed"),
                    "x-ns_server_reputation": ns.get("ns_server_reputation"),
                },
            )
            self._observed_data_refs.append(nameserver.id)
            self._stix_objects.append(nameserver)
            self._helper.log_debug(nameserver)
            relationship = Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", self._domain.value, nameserver.id
                ),
                relationship_type="related-to",
                target_ref=nameserver.id,
                description="Nameserver",
                source_ref=self._domain.id,
                allow_custom=True,
                created_by_ref=self._author["id"],
            )
            self._stix_objects.append(relationship)

    def _build_registrar(self):
        """
        Adds Registrar enriched data to the stix bundle
        """

        domain_info = self._extract_domain_info()
        self._helper.log_debug(f"domain_info: {domain_info}")
        if not domain_info.get("registrar"):
            return
        registrar = Identity(
            id=pycti.Identity.generate_id(domain_info.get("registrar"), "organization"),
            type="identity",
            name=domain_info.get("registrar"),
            description="Registrar",
            identity_class="organization",
            # no custom extensions, leaving it here for future implementations
            custom_properties={
                "x-whois_age": domain_info.get("whois_age"),
                "x-whois_created_date": domain_info.get("whois_created_date"),
                "x-info": domain_info.get("info"),
            },
        )
        self._stix_objects.append(registrar)
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to", self._domain.value, registrar.id
            ),
            relationship_type="related-to",
            target_ref=registrar.id,
            description="Registrar",
            source_ref=self._domain.id,
            allow_custom=True,
            created_by_ref=self._author["id"],
        )
        self._stix_objects.append(relationship)

    # @NOTE: relationship between domain and ASN not allowed
    def _build_asns(self):
        """
        Builds a relationship [DOMAIN]->[IPv4]->[ASN]
                                  \
                               [HOSTNAME]
        and add it to the stix bundle
        """
        from settings import ip_diversity_uri

        ip_diversity_uri = ip_diversity_uri.format(
            domain=self._stix_entity.get("value")
        )
        response = requests.get(
            ip_diversity_uri, headers={"x-api-key": API_KEY}, verify=API_VERIFY_CERT
        )
        asns = (json.loads(response.content).get("response", {}) or {}).get(
            "records", {}
        )
        self._helper.log_debug(f"ip diversity response {ip_diversity_uri}: {response}")
        for asn in asns:
            if asn.get("host"):
                hostname = CustomObservableHostname(
                    value=asn.get("host"),
                    custom_properties={
                        "x_asn_diversity": asn.get("asn_diversity"),
                        "x_ip_diversity_all": asn.get("ip_diversity_all"),
                    },
                )
                self._observed_data_refs.append(hostname.id)
                self._stix_objects.append(hostname)
                self._helper.log_debug(hostname)
                if hostname.value != self._domain.value:
                    relationship = Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to", self._domain.value, hostname.id
                        ),
                        relationship_type="related-to",
                        target_ref=hostname.id,
                        description="Hostname",
                        source_ref=self._domain.id,
                        allow_custom=True,
                        created_by_ref=self._author["id"],
                    )
                    self._stix_objects.append(relationship)
            for asn_timeline in asn.get("timeline"):
                if not asn_timeline.get("ip"):
                    continue
                ipv4 = IPv4Address(
                    id=f"ipv4-addr--{uuid.uuid4()}",
                    type="ipv4-addr",
                    value=asn_timeline.get("ip"),
                    **self._build_extensions(),
                )
                self._observed_data_refs.append(ipv4.id)
                self._stix_objects.append(ipv4)
                relationship = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", self._domain.value, ipv4.id
                    ),
                    relationship_type="related-to",
                    target_ref=ipv4.id,
                    description="A Record",
                    source_ref=self._domain.id,
                    allow_custom=True,
                    created_by_ref=self._author["id"],
                )
                self._stix_objects.append(relationship)
                if not asn_timeline.get("asn"):
                    continue
                _asn = AutonomousSystem(
                    number=int(asn_timeline.get("asn")), name=asn_timeline.get("asname")
                )
                self._observed_data_refs.append(_asn.id)
                self._stix_objects.append(_asn)
                relationship = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "resolves-to", ipv4.value, _asn.id
                    ),
                    relationship_type="belongs-to",
                    target_ref=_asn.id,
                    description="ASN",
                    source_ref=ipv4.id,
                )
                self._stix_objects.append(relationship)

    def _build_domain(self):
        """
        Adds Domain enriched data to the stix bundle
        """

        self._domain = DomainName(
            id=f"domain-name--{uuid.uuid4()}",
            type="domain-name",
            value=self._stix_entity.get("value"),
            custom_properties={
                "score": self._enriched_data.get("sp_risk_score"),
                **self._extract_domain_string_frequency_probability(),
                **self._extract_domain_urls(),
                # **self._extract_scores(),
            },
            **self._build_extensions(),
        )
        self._observed_data_refs.append(self._domain.id)
        self._stix_objects.append(self._domain)

    def _do_request(self):
        """
        Calls Silent Push API to enrich Domain
        """

        from settings import enrich_uri

        enrich_uri = enrich_uri.format(
            type="domain", ioc=self._stix_entity.get("value")
        )
        return requests.get(
            enrich_uri, headers={"x-api-key": API_KEY}, verify=API_VERIFY_CERT
        )

    def enrich(self):
        """
        Enriches a domain

        :raises ValueError: if Silent Push API response returns error
        """

        response = self._do_request()
        self._enriched_data = json.loads(response.content).get("response")
        if self._enriched_data.get("error"):
            raise ValueError(
                f"Can't enrich '{self._stix_entity.get('value')}': "
                f"{self._enriched_data.get('error')}"
            )
        self._domain_urls = (self._enriched_data.get("domain_urls", {}) or {}).get(
            "results_summary", {}
        )
        self._domain_urls = (self._enriched_data.get("ns_changes", {}) or {}).get(
            "results_summary", {}
        )
        self._domain_info = self._enriched_data.get("domaininfo", {}) or {}
        self._ns_reputation = self._enriched_data.get("ns_reputation", {}) or {}
        self._build_domain()
        self._build_registrar()
        self._build_ns_reputations()
        self._build_flags()
        self._build_certificates(self._domain)
        self._build_favicon(self._domain)
        self._build_asns()
