"""Converts a GTI file to a STIX file object and indicator."""

from datetime import datetime, timezone

from connector.src.custom.mappers.gti_iocs.base_ioc_mapper import BaseIOCMapper
from connector.src.custom.models.gti.gti_file_model import (
    GTIFileData,
)
from connector.src.stix.octi.models.file_model import OctiFileModel
from connector.src.stix.octi.observable_type_ov_enum import ObservableTypeOV
from stix2 import File  # type: ignore[import-untyped]


class GTIFileToSTIXFile(BaseIOCMapper[GTIFileData]):
    """Converts a GTI file to a STIX file object and indicator."""

    ioc_type = "file"

    @property
    def file(self) -> GTIFileData:
        """The GTI file being converted."""
        return self.ioc

    def _create_stix_observable(self) -> File:
        """Create the STIX file observable object.

        Returns:
        FileModel: The STIX file observable model object.

        """
        score = self._get_score()

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

        ctime = None
        if self.file.attributes:
            if self.file.attributes.creation_date:
                ctime = datetime.fromtimestamp(
                    self.file.attributes.creation_date, tz=timezone.utc
                )

        file_model = OctiFileModel.create(
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            hashes=hashes,
            name=file_name,
            additional_names=additional_names,
            size=file_size,
            score=score,
            custom_properties=self._observable_custom_properties(),
            ctime=ctime,
        )

        return file_model.to_stix2_object()

    def _get_timestamps(self) -> dict[str, datetime]:
        """Extract creation and modification timestamps from file attributes.

        Returns:
            dict[str, datetime]: dictionary with 'created' and 'modified' timestamps

        """
        created = datetime.now(timezone.utc)
        modified = datetime.now(timezone.utc)

        if self.file.attributes:
            if self.file.attributes.first_submission_date:
                created = datetime.fromtimestamp(
                    self.file.attributes.first_submission_date, tz=timezone.utc
                )
            if self.file.attributes.last_submission_date:
                modified = datetime.fromtimestamp(
                    self.file.attributes.last_submission_date, tz=timezone.utc
                )

        return {"created": created, "modified": modified}

    def _build_hashes(self) -> dict[str, str] | None:
        """Build hashes dictionary from file attributes.

        Returns:
            dict[str, str] | None: dictionary of hashes if available, None otherwise

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

    def _build_stix_pattern(self) -> str:
        """Build STIX pattern for the file indicator.

        Returns:
            str: STIX pattern string

        """
        patterns = []

        if self.file.attributes:
            if self.file.attributes.sha256:
                patterns.append(
                    f"file:hashes.'SHA-256' = '{self.file.attributes.sha256}'"
                )
            if self.file.attributes.md5:
                patterns.append(f"file:hashes.MD5 = '{self.file.attributes.md5}'")
            if self.file.attributes.sha1:
                patterns.append(f"file:hashes.'SHA-1' = '{self.file.attributes.sha1}'")

        if patterns:
            return f"[{' OR '.join(patterns)}]"
        else:
            return f"[file:hashes.'SHA-256' = '{self.file.id}']"

    def _observable_type(self) -> ObservableTypeOV:
        """Return the main observable type of the indicator."""
        return ObservableTypeOV.FILE
