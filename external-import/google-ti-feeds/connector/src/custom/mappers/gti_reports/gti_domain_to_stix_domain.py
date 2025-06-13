"""Converts a GTI domain to a STIX domain object."""

from datetime import datetime, timezone
from typing import Dict, Optional

from connector.src.custom.models.gti_reports.gti_domain_model import (
    GTIDomainData,
)
from connector.src.stix.octi.models.domain_model import OctiDomainModel
from connector.src.stix.v21.models.scos.domain_name_model import DomainNameModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class GTIDomainToSTIXDomain(BaseMapper):
    """Converts a GTI domain to a STIX domain object."""

    def __init__(
        self,
        domain: GTIDomainData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
    ) -> None:
        """Initialize the GTIDomainToSTIXDomain object.

        Args:
        domain (GTIDomainData): The GTI domain data to convert.
        organization (Identity): The organization identity object.
        tlp_marking (MarkingDefinition): The TLP marking definition.

        """
        self.domain = domain
        self.organization = organization
        self.tlp_marking = tlp_marking

    def _create_stix_domain(self) -> DomainNameModel:
        """Create the STIX domain observable object.

        Returns:
        DomainNameModel: The STIX domain observable model object.

        """
        mandiant_ic_score = self._get_mandiant_ic_score()

        domain_model = OctiDomainModel.create(
            value=self.domain.id,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            create_indicator=True,
            score=mandiant_ic_score,
            **self._get_timestamps(),
        )

        return domain_model

    def to_stix(self) -> DomainNameModel:
        """Convert the GTI domain to STIX domain.

        Returns:
        List[Any]: List containing the STIX domain observable.

        """
        domain_observable = self._create_stix_domain()

        return domain_observable

    def _get_timestamps(self) -> Dict[str, datetime]:
        """Extract creation and modification timestamps from domain attributes.

        Returns:
            Dict[str, datetime]: Dictionary with 'created' and 'modified' timestamps

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

    def _get_mandiant_ic_score(self) -> Optional[int]:
        """Get mandiant_ic_score from domain attributes.

        Returns:
            Optional[int]: The mandiant_ic_score if available, None otherwise

        """
        if (
            self.domain.attributes
            and self.domain.attributes.gti_assessment
            and self.domain.attributes.gti_assessment.contributing_factors
            and hasattr(
                self.domain.attributes.gti_assessment.contributing_factors,
                "mandiant_confidence_score",
            )
            and self.domain.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            is not None
        ):
            return (
                self.domain.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            )

        if (
            self.domain.attributes
            and self.domain.attributes.gti_assessment
            and self.domain.attributes.gti_assessment.threat_score
        ):
            return self.domain.attributes.gti_assessment.threat_score.value

        return None
