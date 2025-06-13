"""Converts a GTI IP address to a STIX IP object."""

import ipaddress
from datetime import datetime, timezone
from typing import Dict, Optional, Union

from connector.src.custom.models.gti_reports.gti_ip_addresses_model import (
    GTIIPData,
)
from connector.src.stix.octi.models.ipv4_address_model import OctiIPv4AddressModel
from connector.src.stix.octi.models.ipv6_address_model import OctiIPv6AddressModel
from connector.src.stix.v21.models.scos.ipv4_address_model import IPv4AddressModel
from connector.src.stix.v21.models.scos.ipv6_address_model import IPv6AddressModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class GTIIPToSTIXIP(BaseMapper):
    """Converts a GTI IP address to a STIX IP object."""

    def __init__(
        self,
        ip: GTIIPData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
    ) -> None:
        """Initialize the GTIIPToSTIXIP object.

        Args:
        ip (GTIIPData): The GTI IP data to convert.
        organization (Identity): The organization identity object.
        tlp_marking (MarkingDefinition): The TLP marking definition.

        """
        self.ip = ip
        self.organization = organization
        self.tlp_marking = tlp_marking

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

    def _create_stix_ip(self) -> Union[IPv4AddressModel, IPv6AddressModel]:
        """Create the STIX IP observable object (IPv4 or IPv6).

        Returns:
        Union[IPv4AddressModel, IPv6AddressModel]: The STIX IP observable model object.

        """
        mandiant_ic_score = self._get_mandiant_ic_score()

        ip_version = self._detect_ip_version()

        timestamps = self._get_timestamps()

        ip_model: Union[IPv4AddressModel, IPv6AddressModel]
        if ip_version == "ipv4":
            ip_model = OctiIPv4AddressModel.create(
                value=self.ip.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                score=mandiant_ic_score,
                created=timestamps["created"],
                modified=timestamps["modified"],
                create_indicator=True,
            )
        else:
            ip_model = OctiIPv6AddressModel.create(
                value=self.ip.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                create_indicator=True,
                score=mandiant_ic_score,
                created=timestamps["created"],
                modified=timestamps["modified"],
            )

        return ip_model

    def to_stix(self) -> Union[IPv4AddressModel, IPv6AddressModel]:
        """Convert the GTI IP to STIX IP.

        Returns:
        List[Any]: List containing the STIX IP observable.

        """
        ip_observable = self._create_stix_ip()

        return ip_observable

    def _get_timestamps(self) -> Dict[str, datetime]:
        """Extract creation and modification timestamps from IP attributes.

        Returns:
            Dict[str, datetime]: Dictionary with 'created' and 'modified' timestamps

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

    def _get_mandiant_ic_score(self) -> Optional[int]:
        """Get mandiant_ic_score from IP attributes.

        Returns:
            Optional[int]: The mandiant_ic_score if available, None otherwise

        """
        if (
            self.ip.attributes
            and self.ip.attributes.gti_assessment
            and self.ip.attributes.gti_assessment.contributing_factors
            and hasattr(
                self.ip.attributes.gti_assessment.contributing_factors,
                "mandiant_confidence_score",
            )
            and self.ip.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            is not None
        ):
            return (
                self.ip.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            )

        if (
            self.ip.attributes
            and self.ip.attributes.gti_assessment
            and self.ip.attributes.gti_assessment.threat_score
        ):
            return self.ip.attributes.gti_assessment.threat_score.value

        return None
