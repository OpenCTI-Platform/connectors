import json
from abc import abstractmethod

import pycti
from pycti import (
    STIX_EXT_OCTI,
    CustomObservableHostname,
    OpenCTIStix2,
    StixCoreRelationship,
)
from stix2 import AutonomousSystem, Location, Relationship
from stix2.exceptions import PropertyPresenceError

from .enricher import Enricher


class IPEnricher(Enricher):
    """
    Parent class to be inherited by IPv4 and IPv6 classes
    """

    _ip = None
    _sanitized_ip = None

    @abstractmethod
    def _build_subnet(self) -> list:
        raise NotImplementedError(
            f"`{__class__.__name__}._build_subnet` method not implemented"
        )

    @abstractmethod
    def _build_ip(self) -> list:
        raise NotImplementedError(
            f"`{__class__.__name__}._build_ip` method not implemented"
        )

    @abstractmethod
    def _do_request(self) -> list:
        raise NotImplementedError(
            f"`{__class__.__name__}._do_request` method not implemented"
        )

    def _extract_asn_enriched_data(self):
        asn_enriched_data = dict()
        for k, v in self._enriched_data.items():
            if k.startswith("asn_") or k == "asn" or k == "asname":
                asn_enriched_data[k] = v
        self._helper.log_debug(f"asn extracted: {asn_enriched_data}")
        return asn_enriched_data

    def _extract_reputations(
        self,
    ):
        return {
            "x_reputation": self._enriched_data.get("asn_reputation"),
            "x_takedown_reputation": self._enriched_data.get("asn_takedown_reputation"),
            "x_ip_reputation": self._enriched_data.get("ip_reputation"),
            "x_subnet_reputation": self._enriched_data.get("subnet_reputation"),
        }

    def _extract_flags(self):
        return {
            "known_benign": (
                (self._enriched_data.get("benign_info", {}) or {}).get("known_benign"),
                "#4caf50",
            ),
            "is_proxy": (
                (self._enriched_data.get("ip_flags") or {}).get("is_proxy"),
                "#af4c68",
            ),
            "is_sinkhole": (
                (self._enriched_data.get("ip_flags") or {}).get("is_sinkhole"),
                "#a1713a",
            ),
            "is_vpn": (
                (self._enriched_data.get("ip_flags") or {}).get("is_vpn"),
                "#782b2e",
            ),
            "ip_has_expired_certificate": (
                self._enriched_data.get("ip_has_expired_certificate"),
                "#e09109",
            ),
            "ip_has_open_directory": (
                self._enriched_data.get("ip_has_open_directory"),
                "#4f96bd",
            ),
            "ip_is_dsl_dynamic": (
                self._enriched_data.get("ip_is_dsl_dynamic"),
                "#841a99",
            ),
            "ip_is_ipfs_node": (self._enriched_data.get("ip_is_ipfs_node"), "#070354"),
            "ip_is_tor_exit_node": (
                self._enriched_data.get("ip_is_tor_exit_node"),
                "#c795cc",
            ),
            "known_sinkhole_ip": (
                (self._enriched_data.get("sinkhole_info") or {}).get(
                    "known_sinkhole_ip"
                ),
                "#c75f98",
            ),
        }

    def _extract_subnet(self):
        return {
            "subnet": self._enriched_data.get("subnet"),
            "subnet_allocation_age": self._enriched_data.get("subnet_allocation_age"),
            "subnet_allocation_date": self._enriched_data.get("subnet_allocation_date"),
        }

    def _extract_scores(self):
        return {
            "x_rank_score": self._enriched_data.get("asn_rank_score"),
            "x_listing_score": self._enriched_data.get("listing_score"),
            "x_malscore": self._enriched_data.get("malscore"),
            "x_subnet_reputation_score": self._enriched_data.get(
                "subnet_reputation_score"
            ),
            "x_ip_reputation_score": self._enriched_data.get("ip_reputation_score"),
            "x_reputation_score": self._enriched_data.get("asn_reputation_score"),
            "x_ip_is_dsl_dynamic_score": self._enriched_data.get(
                "ip_is_dsl_dynamic_score"
            ),
        }

    def _build_asn(self):
        """
        Adds ASN enriched data to the stix bundle
        """

        asn_enriched = self._extract_asn_enriched_data()
        OpenCTIStix2.put_attribute_in_extension(  # TODO: seems doesn't work
            self._stix_entity,
            STIX_EXT_OCTI,
            "ASN Rank",
            {"ASN Rank": asn_enriched.get("asn_rank")},
        )
        self._helper.log_debug(f"building asn {asn_enriched.get('asn')}")
        if not asn_enriched.get("asn"):
            return
        asn = AutonomousSystem(
            number=asn_enriched.get("asn"),
            name=asn_enriched.get("asname"),
            custom_properties={
                "x_rank": asn_enriched.get("asn_rank"),
                "x_allocation_age": asn_enriched.get("asn_allocation_age"),
                "x_allocation_date": asn_enriched.get("asn_allocation_date"),
            },
        )
        self._observed_data_refs.append(asn.id)
        # TODO: asn.score = asn_enriched.get("asn_score")
        self._stix_objects.append(asn)
        relationship = Relationship(
            id=StixCoreRelationship.generate_id("resolves-to", self._ip.value, asn.id),
            relationship_type="belongs-to",
            target_ref=asn.id,
            description="ASN",
            source_ref=self._ip.id,
            created_by_ref=self._author["id"],
        )
        self._stix_objects.append(relationship)

    def _build_location(self):
        """
        Adds geo location enriched data to the stix bundle
        """

        _location = self._enriched_data.get("ip_location", {})
        if not _location or not _location.get("country_name"):
            return
        self._helper.log_debug(
            f"building location {self._enriched_data.get('ip_location')}"
        )
        try:
            location = Location(
                id=pycti.Location.generate_id(_location.get("country_name"), "Country"),
                country=_location.get("country_name"),
                region=_location.get("continent_name"),
                created_by_ref=self._author["id"],
            )
            self._stix_objects.append(location)
            self._helper.log_debug(f"location {location}")
            relationship = Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", location.get("country_name"), location.id
                ),
                relationship_type="related-to",
                target_ref=location.id,
                description=location.get("country_name"),
                source_ref=self._ip.id,
                allow_custom=True,
                created_by_ref=self._author["id"],
            )
            self._stix_objects.append(relationship)
            self._helper.log_debug(f"relation {relationship}")
        except PropertyPresenceError:
            self._helper.log_warning(
                f"can't build location with response {self._enriched_data.get('ip_location')}"
            )

    def _build_ptr(self):
        """
        Adds PTR enriched data to the stix bundle
        """

        if not self._enriched_data.get("ip_ptr"):
            return
        self._helper.log_debug(f"building PTR: {self._enriched_data.get('ip_ptr')}")
        hostname = CustomObservableHostname(
            value=self._enriched_data.get("ip_ptr"),
        )
        self._observed_data_refs.append(hostname.id)
        self._stix_objects.append(hostname)
        self._helper.log_debug(hostname)
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to", self._ip.value, hostname.id
            ),
            relationship_type="related-to",
            target_ref=hostname.id,
            description="PTR",
            source_ref=self._ip.id,
            allow_custom=True,
            created_by_ref=self._author["id"],
        )
        self._stix_objects.append(relationship)

    def enrich(self):
        """
        Enriches an IPv4 or IPv6

        :raises ValueError: if Silent Push API response returns error
        """

        response = self._do_request()
        self._response = json.loads(response.content).get("response")
        self._helper.log_debug(f"enrich response: {self._response}")
        self._enriched_data = self._response.get("ip2asn")[0]
        if self._enriched_data.get("error"):
            raise ValueError(
                f"Can't enrich '{self._stix_entity.get('value')}': "
                f"{self._enriched_data.get('error')}"
            )
        self._helper.log_debug(f"self._enriched_data: {self._enriched_data}")
        self._build_ip()
        self._build_location()
        self._build_asn()
        self._build_flags()
        self._build_subnet()
        self._build_ptr()
        self._build_certificates(self._ip)
        self._build_favicon(self._ip)
