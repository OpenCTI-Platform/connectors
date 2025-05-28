"""Simple converter for Google Threat Intelligence data to STIX format.

This module provides a simpler approach to converting GTI data to STIX format
by using specialized mapper classes.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Union, cast

from connector.src.custom.exceptions import (
    GTIActorConversionError,
    GTIEntityConversionError,
    GTIMalwareConversionError,
    GTIMarkingCreationError,
    GTIOrganizationCreationError,
    GTIReferenceError,
    GTIReportConversionError,
    GTITechniqueConversionError,
    GTIVulnerabilityConversionError,
)
from connector.src.custom.mappers.gti_reports.gti_attack_technique_to_stix_attack_pattern import (
    GTIAttackTechniqueToSTIXAttackPattern,
)
from connector.src.custom.mappers.gti_reports.gti_malware_family_to_stix_malware import (
    GTIMalwareFamilyToSTIXMalware,
)
from connector.src.custom.mappers.gti_reports.gti_report_relationship import (
    GTIReportRelationship,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_identity import (
    GTIReportToSTIXIdentity,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_location import (
    GTIReportToSTIXLocation,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_report import (
    GTIReportToSTIXReport,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_sector import (
    GTIReportToSTIXSector,
)
from connector.src.custom.mappers.gti_reports.gti_threat_actor_to_stix_intrusion_set import (
    GTIThreatActorToSTIXIntrusionSet,
)
from connector.src.custom.mappers.gti_reports.gti_vulnerability_to_stix_vulnerability import (
    GTIVulnerabilityToSTIXVulnerability,
)
from connector.src.custom.models.gti_reports.gti_attack_technique_model import (
    GTIAttackTechniqueData,
)
from connector.src.custom.models.gti_reports.gti_malware_family_model import (
    GTIMalwareFamilyData,
)
from connector.src.custom.models.gti_reports.gti_report_model import GTIReportData
from connector.src.custom.models.gti_reports.gti_threat_actor_model import (
    GTIThreatActorData,
)
from connector.src.custom.models.gti_reports.gti_vulnerability_model import (
    GTIVulnerabilityData,
)
from connector.src.stix.octi.models.identity_organization_model import (
    OctiOrganizationModel,
)
from connector.src.stix.octi.models.tlp_marking_model import TLPMarkingModel
from stix2.v21 import (  # type: ignore
    AttackPattern,
    Identity,
    IntrusionSet,
    Malware,
    MarkingDefinition,
    Report,
    Vulnerability,
)


class ConvertToSTIX:
    """A simple converter for Google Threat Intelligence data to STIX format.

    This class converts GTI data (reports, threat actors, malware families,
    attack techniques, vulnerabilities) to STIX format using dedicated mapper classes.
    """

    def __init__(
        self,
        tlp_level: str = "amber",
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize the GTI STIX converter.

        Args:
            tlp_level: TLP marking level for STIX objects
            logger: Logger for logging messages

        """
        self.logger = logger or logging.getLogger(__name__)

        self.organization = self._create_organization()
        self.tlp_marking = self._create_tlp_marking(tlp_level)

        self.stix_objects: List[Any] = []
        self.object_id_map: Dict[str, str] = {}
        self.latest_report_date: Optional[str] = None

    def convert_all_data(
        self,
        reports: List[GTIReportData],
        related_entities: Dict[str, Dict[str, List[Any]]],
    ) -> List[Dict[str, Any]]:
        """Convert all GTI data to STIX format.

        Args:
            reports: List of GTI reports
            related_entities: Dictionary mapping report IDs to related entities

        Returns:
            List of STIX objects

        Raises:
            GTIEntityConversionError: If there's an error converting an entity

        """
        try:
            self.logger.info("Starting to convert GTI data to STIX format")

            self.stix_objects = [self.organization, self.tlp_marking]
            self.object_id_map = {}
            self.latest_report_date = None

            total_reports = len(reports)
            for i, report in enumerate(reports):
                report_id = report.id
                progress_info = (
                    f"({i + 1}/{total_reports} reports) " if total_reports > 0 else ""
                )
                self.logger.info(
                    f"{progress_info}Converting report {report_id} to STIX format"
                )

                if not hasattr(report, "attributes") or not report.attributes:
                    raise GTIReportConversionError(
                        f"Report {report_id} has no attributes"
                    )

                if (
                    hasattr(report.attributes, "last_modification_date")
                    and report.attributes.last_modification_date
                ):
                    report_date = str(report.attributes.last_modification_date)
                    if (
                        not self.latest_report_date
                        or report_date > self.latest_report_date
                    ):
                        self.latest_report_date = report_date

                try:
                    report_entities = self._convert_report(report)
                    # noinspection PyTypeChecker
                    self.stix_objects.extend(report_entities)
                except GTIReportConversionError as report_err:
                    self.logger.error(
                        f"Error converting report {report_id}: {str(report_err)}"
                    )

                    continue

                if report_id in related_entities:
                    related = related_entities[report_id]

                    ids_to_add = []

                    for malware in related.get("malware_families", []):
                        try:
                            stix_malware = self._convert_malware_family(malware)
                            if stix_malware is not None:
                                self.stix_objects.append(stix_malware)
                                ids_to_add.append(stix_malware.id)
                        except GTIMalwareConversionError as malware_err:
                            self.logger.error(
                                f"Error processing malware family {malware.id}: {str(malware_err)}"
                            )
                            continue

                    for actor in related.get("threat_actors", []):
                        try:
                            stix_actor = self._convert_threat_actor(actor)
                            if stix_actor is not None:
                                self.stix_objects.append(stix_actor)
                                ids_to_add.append(stix_actor.id)
                        except GTIActorConversionError as actor_err:
                            self.logger.error(
                                f"Error processing threat actor {actor.id}: {str(actor_err)}"
                            )
                            continue

                    for technique in related.get("attack_techniques", []):
                        try:
                            stix_technique = self._convert_attack_technique(technique)
                            if stix_technique is not None:
                                self.stix_objects.append(stix_technique)
                                ids_to_add.append(stix_technique.id)
                        except GTITechniqueConversionError as technique_err:
                            self.logger.error(
                                f"Error processing attack technique {technique.id}: {str(technique_err)}"
                            )
                            continue

                    for vulnerability in related.get("vulnerabilities", []):
                        try:
                            stix_vuln = self._convert_vulnerability(vulnerability)
                            if stix_vuln is not None:
                                self.stix_objects.append(stix_vuln)
                                ids_to_add.append(stix_vuln.id)
                        except GTIVulnerabilityConversionError as vuln_err:
                            self.logger.error(
                                f"Error processing vulnerability {vulnerability.id}: {str(vuln_err)}"
                            )
                            continue

                    if ids_to_add:
                        try:
                            self._add_reference_to_report(ids_to_add, report_id)
                        except GTIReferenceError as ref_err:
                            self.logger.error(
                                f"Error adding references to report {report_id}: {str(ref_err)}"
                            )

            self.logger.info(f"Converted {len(self.stix_objects)} STIX objects")
            return self.stix_objects

        except GTIEntityConversionError:
            raise
        except Exception as e:
            # noinspection PyArgumentList
            self.logger.error(  # type: ignore
                f"Error converting GTI data to STIX format: {str(e)}",
                meta={"error": str(e)},
            )

            if self.stix_objects:
                self.logger.info(
                    f"Returning {len(self.stix_objects)} partially converted STIX objects"
                )
                return self.stix_objects
            raise GTIEntityConversionError(
                f"Failed to convert GTI data: {str(e)}"
            ) from e

    @staticmethod
    def _create_organization() -> Identity:
        """Create a STIX Identity object for the organization.

        Returns:
            STIX Identity object

        Raises:
            GTIOrganizationCreationError: If there's an error creating the organization

        """
        try:
            organization_model = OctiOrganizationModel.create(
                name="Google Threat Intelligence",
                description="Google Threat Intelligence provides information on the latest threats.",
                contact_information="https://gtidocs.virustotal.com",
                organization_type="vendor",
                reliability=None,
                aliases=["GTI"],
            )
            # noinspection PyTypeChecker
            return organization_model.to_stix2_object()
        except Exception as e:
            raise GTIOrganizationCreationError(str(e)) from e

    @staticmethod
    def _create_tlp_marking(tlp_level: str) -> MarkingDefinition:
        """Create a TLP marking definition.

        Args:
            tlp_level: TLP level (white, green, amber, red)

        Returns:
            TLP marking definition

        Raises:
            GTIMarkingCreationError: If there's an error creating the TLP marking

        """
        try:
            normalized_level = tlp_level.lower()

            if normalized_level not in (
                "white",
                "green",
                "amber",
                "amber+strict",
                "red",
            ):
                normalized_level = "amber"

            tlp_literal = cast(
                Literal["white", "green", "amber", "amber+strict", "red"],
                normalized_level,
            )

            return TLPMarkingModel(level=tlp_literal).to_stix2_object()
        except Exception as e:
            raise GTIMarkingCreationError(str(e), tlp_level) from e

    def _convert_report(self, report: GTIReportData) -> List[Dict[str, Any]]:
        """Convert a GTI report to STIX format.

        Args:
            report: GTI report data

        Returns:
            List of STIX objects

        Raises:
            GTIReportConversionError: If there's an error converting the report

        """
        try:
            self.logger.debug(f"Converting report {report.id} to STIX format")
            result = []

            try:
                author_mapper = GTIReportToSTIXIdentity(report, self.organization)
                author_identity = author_mapper.to_stix()
                result.append(author_identity)
            except Exception as author_err:
                raise GTIReportConversionError(
                    f"Failed to convert report author: {str(author_err)}",
                    report.id,
                    "author_conversion",
                ) from author_err

            try:
                location_mapper = GTIReportToSTIXLocation(
                    report, self.organization, self.tlp_marking
                )
                locations = location_mapper.to_stix()
                result.extend(locations)
            except Exception as location_err:
                raise GTIReportConversionError(
                    f"Failed to convert report locations: {str(location_err)}",
                    report.id,
                    "location_conversion",
                ) from location_err

            try:
                sector_mapper = GTIReportToSTIXSector(
                    report, self.organization, self.tlp_marking
                )
                sectors = sector_mapper.to_stix()
                result.extend(sectors)
            except Exception as sector_err:
                raise GTIReportConversionError(
                    f"Failed to convert report sectors: {str(sector_err)}",
                    report.id,
                    "sector_conversion",
                ) from sector_err

            try:
                report_mapper = GTIReportToSTIXReport(
                    report,
                    self.organization,
                    self.tlp_marking,
                    author_identity,
                    sectors,
                    locations,
                )
                report_obj = report_mapper.to_stix()
                result.append(report_obj)
            except Exception as report_err:
                raise GTIReportConversionError(
                    f"Failed to convert report object: {str(report_err)}",
                    report.id,
                    "report_object_conversion",
                ) from report_err

            self.object_id_map[report.id] = report_obj.id

            try:
                relationship_mapper = GTIReportRelationship(
                    report, self.organization, self.tlp_marking, report_obj.id
                )
                relationships = relationship_mapper.to_stix()
                result.extend(relationships)
            except Exception as rel_err:
                raise GTIReportConversionError(
                    f"Failed to convert report relationships: {str(rel_err)}",
                    report.id,
                    "relationship_conversion",
                ) from rel_err

            return result

        except GTIReportConversionError:
            raise
        except Exception as e:
            # noinspection PyArgumentList
            self.logger.error(  # type: ignore
                f"Error converting report {report.id}: {str(e)}", meta={"error": str(e)}
            )
            raise GTIReportConversionError(str(e), report.id) from e

    def _convert_malware_family(
        self, malware: GTIMalwareFamilyData
    ) -> Optional[Malware]:
        """Convert a GTI malware family to STIX format.

        Args:
            malware: GTI malware family data

        Returns:
            STIX malware object

        Raises:
            GTIMalwareConversionError: If there's an error converting the malware family

        """
        try:
            self.logger.debug(f"Converting malware family {malware.id} to STIX format")

            mapper = GTIMalwareFamilyToSTIXMalware(
                malware, self.organization, self.tlp_marking
            )
            stix_malware = mapper.to_stix()

            self.object_id_map[malware.id] = stix_malware.id

            return stix_malware

        except Exception as e:
            # noinspection PyArgumentList
            self.logger.error(  # type: ignore
                f"Error converting malware family {malware.id}: {str(e)}",
                meta={"error": str(e)},
            )
            malware_name = getattr(malware, "name", None)
            raise GTIMalwareConversionError(str(e), malware.id, malware_name) from e

    def _convert_threat_actor(
        self, actor: GTIThreatActorData
    ) -> Optional[IntrusionSet]:
        """Convert a GTI threat actor to STIX format.

        Args:
            actor: GTI threat actor data

        Returns:
            STIX intrusion set object

        Raises:
            GTIActorConversionError: If there's an error converting the threat actor

        """
        try:
            self.logger.debug(f"Converting threat actor {actor.id} to STIX format")

            mapper = GTIThreatActorToSTIXIntrusionSet(
                actor, self.organization, self.tlp_marking
            )
            stix_actor = mapper.to_stix()

            self.object_id_map[actor.id] = stix_actor.id

            return stix_actor

        except Exception as e:
            # noinspection PyArgumentList
            self.logger.error(  # type: ignore
                f"Error converting threat actor {actor.id}: {str(e)}",
                meta={"error": str(e)},
            )
            actor_name = getattr(actor, "name", None)
            raise GTIActorConversionError(str(e), actor.id, actor_name) from e

    def _convert_attack_technique(
        self, technique: GTIAttackTechniqueData
    ) -> Optional[AttackPattern]:
        """Convert a GTI attack technique to STIX format.

        Args:
            technique: GTI attack technique data

        Returns:
            STIX attack pattern object

        Raises:
            GTITechniqueConversionError: If there's an error converting the attack technique

        """
        try:
            self.logger.debug(
                f"Converting attack technique {technique.id} to STIX format"
            )

            mapper = GTIAttackTechniqueToSTIXAttackPattern(
                technique, self.organization, self.tlp_marking
            )
            stix_technique = mapper.to_stix()

            self.object_id_map[technique.id] = stix_technique.id

            return stix_technique

        except Exception as e:
            # noinspection PyArgumentList
            self.logger.error(  # type: ignore
                f"Error converting attack technique {technique.id}: {str(e)}",
                meta={"error": str(e)},
            )
            technique_name = getattr(technique, "name", None)
            mitre_id = getattr(technique, "mitre_attack_id", None)
            raise GTITechniqueConversionError(
                str(e), technique.id, technique_name, mitre_id
            ) from e

    def _convert_vulnerability(
        self, vulnerability: GTIVulnerabilityData
    ) -> Optional[Vulnerability]:
        """Convert a GTI vulnerability to STIX format.

        Args:
            vulnerability: GTI vulnerability data

        Returns:
            STIX vulnerability object

        Raises:
            GTIVulnerabilityConversionError: If there's an error converting the vulnerability

        """
        try:
            self.logger.debug(
                f"Converting vulnerability {vulnerability.id} to STIX format"
            )

            mapper = GTIVulnerabilityToSTIXVulnerability(
                vulnerability, self.organization, self.tlp_marking
            )
            stix_vuln = mapper.to_stix()

            self.object_id_map[vulnerability.id] = stix_vuln.id

            return stix_vuln

        except Exception as e:
            # noinspection PyArgumentList
            self.logger.error(  # type: ignore
                f"Error converting vulnerability {vulnerability.id}: {str(e)}",
                meta={"error": str(e)},
            )
            cve_id = getattr(vulnerability, "cve_id", None)
            raise GTIVulnerabilityConversionError(
                str(e), vulnerability.id, cve_id
            ) from e

    def _add_reference_to_report(
        self, object_id: Union[str, List[str]], report_id: str
    ) -> None:
        """Add reference to one or more objects in a report.

        Args:
            object_id: ID of the object to reference, or a list of object IDs
            report_id: ID of the report

        Raises:
            GTIReferenceError: If there's an error adding the reference

        """
        stix_report_id = self.object_id_map.get(report_id)
        try:
            object_ids = [object_id] if isinstance(object_id, str) else object_id

            if not stix_report_id:
                self.logger.warning(f"Report {report_id} not found in object_id_map")
                raise GTIReferenceError(
                    f"Report {report_id} not found in object_id_map",
                    target_id=report_id,
                )

            latest_report_index: Optional[int] = None
            latest_report: Optional[Report] = None

            for i, obj in enumerate(self.stix_objects):
                if isinstance(obj, Report) and obj.id == stix_report_id:
                    latest_report_index = i
                    latest_report = obj

            if latest_report is None:
                self.logger.warning(
                    f"Report with ID {stix_report_id} not found in STIX objects"
                )
                raise GTIReferenceError(
                    f"Report with ID {stix_report_id} not found in STIX objects",
                    source_id=stix_report_id,
                )

            try:
                updated_report = GTIReportToSTIXReport.add_object_refs(
                    objects_to_add=object_ids, existing_report=latest_report
                )

                if latest_report_index is not None:
                    self.stix_objects[latest_report_index] = updated_report
            except Exception as update_err:
                raise GTIReferenceError(
                    f"Failed to update report references: {str(update_err)}",
                    source_id=stix_report_id,
                    target_id=str(object_ids),
                ) from update_err

        except GTIReferenceError:
            raise
        except Exception as e:
            self.logger.error(f"Error adding reference to report: {str(e)}", meta={"error": str(e)})  # type: ignore
            raise GTIReferenceError(
                str(e),
                source_id=stix_report_id,
                target_id=str(object_id),
            ) from e

    def get_latest_report_date(self) -> Optional[str]:
        """Return the latest report modification date processed.

        Returns:
            ISO format string of the latest report date, or None if no reports were processed

        """
        if self.latest_report_date is None:
            return None

        dt = datetime.fromtimestamp(int(self.latest_report_date), tz=timezone.utc)

        return dt.isoformat()
