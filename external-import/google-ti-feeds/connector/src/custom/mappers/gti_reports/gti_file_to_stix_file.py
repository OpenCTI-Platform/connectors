"""Converts a GTI file to a STIX file object."""

from datetime import datetime, timezone
from typing import Dict, Optional

from connector.src.custom.models.gti_reports.gti_file_model import (
    GTIFileData,
)
from connector.src.stix.octi.models.file_model import OctiFileModel
from connector.src.stix.v21.models.scos.file_model import FileModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class GTIFileToSTIXFile(BaseMapper):
    """Converts a GTI file to a STIX file object."""

    def __init__(
        self,
        file: GTIFileData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
    ) -> None:
        """Initialize the GTIFileToSTIXFile object.

        Args:
        file (GTIFileData): The GTI file data to convert.
        organization (Identity): The organization identity object.
        tlp_marking (MarkingDefinition): The TLP marking definition.

        """
        self.file = file
        self.organization = organization
        self.tlp_marking = tlp_marking

    def _create_stix_file(self) -> FileModel:
        """Create the STIX file observable object.

        Returns:
        FileModel: The STIX file observable model object.

        """
        mandiant_ic_score = self._get_mandiant_ic_score()

        hashes = self._build_hashes()

        additional_names = None
        if self.file.attributes and self.file.attributes.names:
            additional_names = self.file.attributes.names

        file_name = None
        if self.file.attributes and self.file.attributes.meaningful_name:
            file_name = self.file.attributes.meaningful_name

        file_size = None
        if self.file.attributes and self.file.attributes.size:
            file_size = self.file.attributes.size

        file_model = OctiFileModel.create(
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            create_indicator=True,
            hashes=hashes,
            name=file_name,
            additional_names=additional_names,
            size=file_size,
            score=mandiant_ic_score,
            **self._get_timestamps(),
        )

        return file_model

    def to_stix(self) -> FileModel:
        """Convert the GTI file to STIX file.

        Returns:
        List[Any]: List containing the STIX file observable.

        """
        file_observable = self._create_stix_file()

        return file_observable

    def _get_timestamps(self) -> Dict[str, datetime]:
        """Extract creation and modification timestamps from file attributes.

        Returns:
            Dict[str, datetime]: Dictionary with 'created' and 'modified' timestamps

        """
        created = datetime.now(timezone.utc)
        modified = datetime.now(timezone.utc)

        if self.file.attributes:
            if self.file.attributes.creation_date:
                created = datetime.fromtimestamp(
                    self.file.attributes.creation_date, tz=timezone.utc
                )
            if self.file.attributes.last_modification_date:
                modified = datetime.fromtimestamp(
                    self.file.attributes.last_modification_date, tz=timezone.utc
                )

        return {"created": created, "modified": modified}

    def _get_mandiant_ic_score(self) -> Optional[int]:
        """Get mandiant_ic_score from file attributes.

        Returns:
            Optional[int]: The mandiant_ic_score if available, None otherwise

        """
        if (
            self.file.attributes
            and self.file.attributes.gti_assessment
            and self.file.attributes.gti_assessment.contributing_factors
            and hasattr(
                self.file.attributes.gti_assessment.contributing_factors,
                "mandiant_confidence_score",
            )
            and self.file.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            is not None
        ):
            return (
                self.file.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            )

        if (
            self.file.attributes
            and self.file.attributes.gti_assessment
            and self.file.attributes.gti_assessment.threat_score
        ):
            return self.file.attributes.gti_assessment.threat_score.value

        return None

    def _build_hashes(self) -> Optional[Dict[str, str]]:
        """Build hashes dictionary from file attributes.

        Returns:
            Optional[Dict[str, str]]: Dictionary of hashes if available, None otherwise

        """
        if not self.file.attributes:
            return None

        hashes = {}
        if self.file.attributes.sha256:
            hashes["SHA-256"] = self.file.attributes.sha256
        if self.file.attributes.sha1:
            hashes["SHA-1"] = self.file.attributes.sha1
        if self.file.attributes.md5:
            hashes["MD5"] = self.file.attributes.md5

        return hashes if hashes else None
