"""Converts a GTI URL to a STIX URL object."""

from datetime import datetime, timezone
from typing import Dict, Optional

from connector.src.custom.models.gti_reports.gti_url_model import (
    GTIURLData,
)
from connector.src.stix.octi.models.url_model import OctiUrlModel
from connector.src.stix.v21.models.scos.url_model import URLModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class GTIUrlToSTIXUrl(BaseMapper):
    """Converts a GTI URL to a STIX URL object."""

    def __init__(
        self,
        url: GTIURLData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
    ) -> None:
        """Initialize the GTIUrlToSTIXUrl object.

        Args:
        url (GTIURLData): The GTI URL data to convert.
        organization (Identity): The organization identity object.
        tlp_marking (MarkingDefinition): The TLP marking definition.

        """
        self.url = url
        self.organization = organization
        self.tlp_marking = tlp_marking

    def _create_stix_url(self) -> URLModel:
        """Create the STIX URL observable object.

        Returns:
        URLModel: The STIX URL observable model object.

        """
        mandiant_ic_score = self._get_mandiant_ic_score()

        url_value = self._get_url_value()

        url_model = OctiUrlModel.create(
            value=url_value,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            create_indicator=True,
            score=mandiant_ic_score,
            **self._get_timestamps(),
        )

        return url_model

    def to_stix(self) -> URLModel:
        """Convert the GTI URL to STIX URL.

        Returns:
        List[Any]: List containing the STIX URL observable.

        """
        url_observable = self._create_stix_url()

        return url_observable

    def _get_timestamps(self) -> Dict[str, datetime]:
        """Extract creation and modification timestamps from URL attributes.

        Returns:
            Dict[str, datetime]: Dictionary with 'created' and 'modified' timestamps

        """
        created = datetime.now(timezone.utc)
        modified = datetime.now(timezone.utc)

        if self.url.attributes:
            if self.url.attributes.first_submission_date:
                created = datetime.fromtimestamp(
                    self.url.attributes.first_submission_date, tz=timezone.utc
                )
            if self.url.attributes.last_modification_date:
                modified = datetime.fromtimestamp(
                    self.url.attributes.last_modification_date, tz=timezone.utc
                )

        return {"created": created, "modified": modified}

    def _get_mandiant_ic_score(self) -> Optional[int]:
        """Get mandiant_ic_score from URL attributes.

        Priority order:
        1. contributing_factors.mandiant_confidence_score
        2. threat_score.value

        Returns:
            Optional[int]: The mandiant_ic_score if available, None otherwise

        """
        if (
            self.url.attributes
            and self.url.attributes.gti_assessment
            and self.url.attributes.gti_assessment.contributing_factors
            and hasattr(
                self.url.attributes.gti_assessment.contributing_factors,
                "mandiant_confidence_score",
            )
            and self.url.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            is not None
        ):
            return (
                self.url.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            )

        if (
            self.url.attributes
            and self.url.attributes.gti_assessment
            and self.url.attributes.gti_assessment.threat_score
        ):
            return self.url.attributes.gti_assessment.threat_score.value

        return None

    def _get_url_value(self) -> str:
        """Get the URL value with priority order.

        Priority order:
        1. attributes.url (original URL)
        2. attributes.last_final_url (final URL after redirects)
        3. id (fallback)

        Returns:
            str: The URL value

        """
        if self.url.attributes and self.url.attributes.url:
            return self.url.attributes.url
        elif self.url.attributes and self.url.attributes.last_final_url:
            return self.url.attributes.last_final_url
        else:
            return self.url.id
