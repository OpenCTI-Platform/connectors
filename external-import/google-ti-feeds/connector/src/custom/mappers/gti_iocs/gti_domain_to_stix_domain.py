"""Converts a GTI domain to a STIX domain object and indicator."""

from datetime import datetime, timezone

from connector.src.custom.mappers.gti_iocs.base_ioc_mapper import BaseIOCMapper
from connector.src.custom.mappers.gti_iocs.stix_pattern import escape_pattern_value
from connector.src.custom.models.gti.gti_domain_model import (
    GTIDomainData,
)
from connector.src.stix.octi.models.domain_model import OctiDomainModel
from connector.src.stix.octi.observable_type_ov_enum import ObservableTypeOV
from stix2 import DomainName  # type: ignore[import-untyped]


class GTIDomainToSTIXDomain(BaseIOCMapper[GTIDomainData]):
    """Converts a GTI domain to a STIX domain object and indicator."""

    ioc_type = "domain"

    @property
    def domain(self) -> GTIDomainData:
        """The GTI domain being converted."""
        return self.ioc

    def _create_stix_observable(self) -> DomainName:
        """Create the STIX domain observable object.

        Returns:
        DomainNameModel: The STIX domain observable model object.

        """
        score = self._get_score()

        domain_model = OctiDomainModel.create(
            value=self.domain.id,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            score=score,
            custom_properties=self._observable_custom_properties(),
        )

        return domain_model.to_stix2_object()

    def _get_timestamps(self) -> dict[str, datetime]:
        """Extract creation and modification timestamps from domain attributes.

        Returns:
            dict[str, datetime]: dictionary with 'created' and 'modified' timestamps

        """
        created = datetime.now(timezone.utc)
        modified = datetime.now(timezone.utc)

        if self.domain.attributes:
            if self.domain.attributes.creation_date:
                created = datetime.fromtimestamp(
                    self.domain.attributes.creation_date, tz=timezone.utc
                )
            if self.domain.attributes.last_modification_date:
                modified = datetime.fromtimestamp(
                    self.domain.attributes.last_modification_date, tz=timezone.utc
                )

        return {"created": created, "modified": modified}

    def _observable_type(self) -> ObservableTypeOV:
        """Return the main observable type of the indicator."""
        return ObservableTypeOV.DOMAIN_NAME

    def _build_stix_pattern(self) -> str:
        """Build STIX pattern for the domain indicator."""
        return f"[domain-name:value='{escape_pattern_value(self.domain.id)}']"
