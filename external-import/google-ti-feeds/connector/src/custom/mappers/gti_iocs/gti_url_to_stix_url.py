"""Converts a GTI URL to a STIX URL object and indicator."""

from datetime import datetime, timezone

from connector.src.custom.mappers.gti_iocs.base_ioc_mapper import BaseIOCMapper
from connector.src.custom.mappers.gti_iocs.stix_pattern import escape_pattern_value
from connector.src.custom.models.gti.gti_url_model import (
    GTIURLData,
)
from connector.src.stix.octi.models.url_model import OctiUrlModel
from connector.src.stix.octi.observable_type_ov_enum import ObservableTypeOV
from stix2 import URL  # type: ignore[import-untyped]


class GTIUrlToSTIXUrl(BaseIOCMapper[GTIURLData]):
    """Converts a GTI URL to a STIX URL object and indicator."""

    ioc_type = "url"

    @property
    def url(self) -> GTIURLData:
        """The GTI url being converted."""
        return self.ioc

    def _create_stix_observable(self) -> URL:
        """Create the STIX URL observable object.

        Returns:
        OctiUrlModel: The STIX URL observable model object.

        """
        score = self._get_score()

        url_value = self._get_url_value()

        url_model = OctiUrlModel.create(
            value=url_value,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            score=score,
            custom_properties=self._observable_custom_properties(),
        )

        return url_model.to_stix2_object()

    def _get_timestamps(self) -> dict[str, datetime]:
        """Extract creation and modification timestamps from URL attributes.

        Returns:
            dict[str, datetime]: dictionary with 'created' and 'modified' timestamps

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

    def _build_stix_pattern(self) -> str:
        """Build STIX pattern for the URL indicator.

        Returns:
            str: STIX pattern string

        """
        url_value = self._get_url_value()
        return f"[url:value = '{escape_pattern_value(url_value)}']"

    def _observable_type(self) -> ObservableTypeOV:
        """Return the main observable type of the indicator."""
        return ObservableTypeOV.URL

    def _indicator_name(self) -> str:
        """Name the indicator after the URL rather than its GTI ID."""
        return self._get_url_value()
