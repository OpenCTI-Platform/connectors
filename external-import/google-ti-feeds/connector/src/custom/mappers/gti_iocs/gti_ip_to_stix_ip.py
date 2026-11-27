"""Converts a GTI IP to a STIX IP object and indicator."""

import ipaddress
from datetime import datetime, timezone
from typing import Any

import pycountry
from connector.src.custom.mappers.gti_iocs.base_ioc_mapper import BaseIOCMapper
from connector.src.custom.mappers.relationship_reasons import (
    ip_autonomous_system_reason,
    ip_country_reason,
    optional_reason,
)
from connector.src.custom.models.gti.gti_ip_addresses_model import (
    GTIIPData,
)
from connector.src.stix.octi.models.ipv4_address_model import OctiIPv4AddressModel
from connector.src.stix.octi.models.ipv6_address_model import OctiIPv6AddressModel
from connector.src.stix.octi.models.location_model import OctiLocationModel
from connector.src.stix.octi.observable_type_ov_enum import ObservableTypeOV
from connector.src.stix.v21.models.scos.as_model import AutonomousSystemModel
from connector.src.stix.v21.models.scos.ipv4_address_model import IPv4AddressModel
from connector.src.stix.v21.models.scos.ipv6_address_model import IPv6AddressModel
from stix2 import (  # type: ignore[import-untyped]
    AutonomousSystem,
    IPv4Address,
    IPv6Address,
    Location,
)


def country_from_code(code: str | None) -> tuple[str, list[str]] | None:
    """Return the country name and aliases of an ISO 3166-1 alpha-2 code.

    The name is the common name when pycountry has one ('Taiwan'), else the ISO
    name. Aliases hold the other names and the codes, so OpenCTI can match a
    country it already knows under another name.

    Returns:
        (name, aliases), or None for an unknown or missing code.

    """
    country = pycountry.countries.get(alpha_2=code) if code else None
    if country is None:
        return None
    name = getattr(country, "common_name", None) or country.name
    candidates = (
        country.name,
        getattr(country, "official_name", None),
        country.alpha_2,
        country.alpha_3,
    )
    aliases = [alias for alias in dict.fromkeys(candidates) if alias and alias != name]
    return name, aliases


class GTIIPToSTIXIP(BaseIOCMapper[GTIIPData]):
    """Converts a GTI IP to a STIX IP object and indicator."""

    ioc_type = "ip_address"

    def __init__(
        self,
        *args: Any,
        ip_link_to_asn: bool = False,
        ip_link_to_country: bool = False,
        **kwargs: Any,
    ) -> None:
        """Initialize the mapper.

        Args:
            *args: See `BaseIOCMapper`.
            ip_link_to_asn: Whether to link the IP to its autonomous system.
            ip_link_to_country: Whether to link the IP to its country.
            **kwargs: See `BaseIOCMapper`.

        """
        super().__init__(*args, **kwargs)
        self.ip_link_to_asn = ip_link_to_asn
        self.ip_link_to_country = ip_link_to_country

    @property
    def ip(self) -> GTIIPData:
        """The GTI ip address being converted."""
        return self.ioc

    def to_stix(self) -> list[Any]:
        """Convert the GTI IP, adding its autonomous system and country when enabled.

        Returns:
            list[Any]: The objects of `BaseIOCMapper.to_stix`, then each linked
                object followed by its relationship from the IP: 'belongs-to' the
                autonomous system, 'located-at' the country.

        """
        stix_objects = super().to_stix()
        observable = stix_objects[0]
        attributes = self.ip.attributes
        autonomous_system = self._create_autonomous_system()
        country = self._create_country()
        links = []
        if autonomous_system is not None and attributes and attributes.asn is not None:
            links.append(
                (
                    "belongs-to",
                    autonomous_system,
                    ip_autonomous_system_reason(attributes.asn, attributes.as_owner),
                )
            )
        if country is not None and attributes and attributes.country:
            links.append(
                (
                    "located-at",
                    country,
                    ip_country_reason(country.name, attributes.country),
                )
            )
        for relationship_type, target, reason in links:
            stix_objects.append(target)
            stix_objects.append(
                self._create_ioc_relationship(
                    relationship_type,
                    observable,
                    target,
                    description=optional_reason(reason),
                )
            )
        return stix_objects

    def _natively_linked_fields(self) -> frozenset[str]:
        """Return the network fields carried by linked objects, left out of the description."""
        fields = set()
        if self._create_autonomous_system() is not None:
            fields.add("asn")
        if self._create_country() is not None:
            fields.add("country")
        return frozenset(fields)

    def _create_country(self) -> Location | None:
        """Create the Country location of the IP when enabled and the code is known."""
        attributes = self.ip.attributes
        code = attributes.country if attributes else None
        if not self.ip_link_to_country or not code:
            return None
        country = country_from_code(code)
        if country is None:
            return None
        name, aliases = country
        timestamps = self._get_timestamps()
        return OctiLocationModel.create_country(
            name=name,
            country_code=code,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            custom_properties={"x_opencti_aliases": aliases},
            created=timestamps["created"],
            modified=timestamps["modified"],
        ).to_stix2_object()

    def _create_autonomous_system(self) -> AutonomousSystem | None:
        """Create the autonomous system of the IP when enabled and known."""
        attributes = self.ip.attributes
        if not self.ip_link_to_asn or not attributes or attributes.asn is None:
            return None
        return AutonomousSystemModel(
            type="autonomous-system",
            spec_version="2.1",
            number=attributes.asn,
            name=attributes.as_owner,
            rir=attributes.regional_internet_registry,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={"x_opencti_created_by_ref": self.organization.id},
        ).to_stix2_object()

    def _detect_ip_version(self) -> str:
        """Detect if IP is IPv4 or IPv6.

        Returns:
            str: "ipv4" or "ipv6"

        Raises:
            ValueError: If IP format is invalid

        """
        try:
            ip_obj = ipaddress.ip_address(self.ip.id)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                return "ipv4"
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                return "ipv6"
            else:
                raise ValueError(f"Unknown IP address type: {type(ip_obj)}")
        except ValueError as e:
            raise ValueError(f"Invalid IP address format '{self.ip.id}': {e}") from e

    def _create_stix_observable(self) -> IPv4Address | IPv6Address:
        """Create the STIX IP observable object (IPv4 or IPv6).

        Returns:
         IPv4Address | IPv6Address: The STIX IP observable model object.

        """
        score = self._get_score()

        ip_version = self._detect_ip_version()

        timestamps = self._get_timestamps()

        ip_model: IPv4AddressModel | IPv6AddressModel
        if ip_version == "ipv4":
            ip_model = OctiIPv4AddressModel.create(
                value=self.ip.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                score=score,
                custom_properties=self._observable_custom_properties(),
                created=timestamps["created"],
                modified=timestamps["modified"],
            )
        else:
            ip_model = OctiIPv6AddressModel.create(
                value=self.ip.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                score=score,
                custom_properties=self._observable_custom_properties(),
                created=timestamps["created"],
                modified=timestamps["modified"],
            )

        return ip_model.to_stix2_object()

    def _get_timestamps(self) -> dict[str, datetime]:
        """Extract creation and modification timestamps from IP attributes.

        Returns:
            dict[str, datetime]: dictionary with 'created' and 'modified' timestamps

        """
        created = datetime.now(timezone.utc)
        modified = datetime.now(timezone.utc)

        if self.ip.attributes:
            if self.ip.attributes.last_analysis_date:
                created = datetime.fromtimestamp(
                    self.ip.attributes.last_analysis_date, tz=timezone.utc
                )
            if self.ip.attributes.last_modification_date:
                modified = datetime.fromtimestamp(
                    self.ip.attributes.last_modification_date, tz=timezone.utc
                )

        return {"created": created, "modified": modified}

    def _build_stix_pattern(self) -> str:
        """Build STIX pattern for the IP indicator.

        Returns:
            str: STIX pattern string

        """
        ip_version = self._detect_ip_version()

        if ip_version == "ipv4":
            return f"[ipv4-addr:value = '{self.ip.id}']"
        else:
            return f"[ipv6-addr:value = '{self.ip.id}']"

    def _observable_type(self) -> ObservableTypeOV:
        """Return the main observable type of the indicator."""
        if self._detect_ip_version() == "ipv4":
            return ObservableTypeOV.IPV4_ADDR
        return ObservableTypeOV.IPV6_ADDR
