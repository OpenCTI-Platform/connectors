# -*- coding: utf-8 -*-
"""Livehunt builder module."""
import datetime
import json
import logging
from typing import Optional

import plyara
import plyara.utils
import stix2
import vt
from pycti import Incident, OpenCTIConnectorHelper, StixCoreRelationship

plyara.logger.setLevel(logging.ERROR)


class LivehuntBuilder:
    """Virustotal Livehunt builder."""

    _SOURCE = "hunting_notification"

    def __init__(
        self,
        client: vt.Client,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        tag: str,
        create_alert: bool,
        max_old_days: int,
        create_file: bool,
        create_ruleset: bool,
        delete_notification: bool,
    ) -> None:
        """Initialize Virustotal builder."""
        self.client = client
        self.helper = helper
        self.author = author
        self.bundle = [self.author]
        self.tag = tag
        self.with_alert = create_alert
        self.max_old_days = max_old_days
        self.with_file = create_file
        self.with_ruleset = create_ruleset
        self.delete_notification = delete_notification

    def process(self, start_date: str):
        url = "/intelligence/hunting_notification_files"
        params = f"date:{start_date}+"
        if self.tag is not None and self.tag != "":
            self.helper.log_debug(f"Setting up filter with tag {self.tag}")
            params += f" tag:{self.tag}"

        self.helper.log_info(f"Url for notifications: {url} / params: {params}")
        files_iterator = self.client.iterator(url, params={"filter": params})

        for vtobj in files_iterator:
            self.helper.log_debug(json.dumps(vtobj.__dict__, indent=2))

            if self.max_old_days is not None:
                time_diff = datetime.datetime.now() - vtobj.first_submission_date
                if time_diff.days >= self.max_old_days:
                    self.helper.log_info(
                        f"First submission date {vtobj.first_submission_date} is too old (more than {self.max_old_days} days"
                    )
                    continue

            # Create external reference to Virustotal report
            external_reference = self.create_external_reference(
                f"https://www.virustotal.com/gui/file/{vtobj.sha256}",
                "Virustotal Analysis",
            )
            incident_id = None
            file_id = None
            if self.with_alert:
                incident_id = self.create_alert(vtobj, external_reference)

            if self.with_file:
                file_id = self.create_file(vtobj, incident_id)

            if self.with_ruleset:
                self.create_ruleset(
                    vtobj._context_attributes["ruleset_id"], incident_id, file_id
                )

            if self.delete_notification:
                self.delete_livehunt_notification(vtobj.id)

    def create_alert(self, vtobj, external_reference) -> str:
        """
        Create the alert from the livehunt notifications.

        Parameters
        ----------
        vtobj
            Virustotal object with the notification and its related file.
        external_reference : stix2.ExternalReference
            External reference to the file on VirusTotal.

        Returns
        -------
        str
            Id of the created incident.
        """
        # Create the alert
        name = f"""Alert from ruleset {vtobj._context_attributes["ruleset_name"]} {f'{vtobj._context_attributes["rule_tags"]}' if vtobj._context_attributes["rule_tags"] else ""}"""
        incident = stix2.Incident(
            id=Incident.generate_id(
                name, vtobj._context_attributes["notification_date"]
            ),
            incident_type="alert",
            name=name,
            description=f'Snippet:\n{vtobj._context_attributes["notification_snippet"]}',
            source=self._SOURCE,
            created_by_ref=self.author["id"],
            confidence=self.helper.connect_confidence_level,
            labels=vtobj._context_attributes["notification_tags"],
            external_references=[external_reference],
            allow_custom=True,
        )
        self.bundle.append(incident)
        return incident["id"]

    def create_external_reference(self, url: str, description: str):
        """
        Create an external reference.

        Used to have a link to the file on VirusTotal.

        Parameters
        ----------
        url : str
            Url for the external reference.
        description : str
            Description fot the external reference.

        Returns
        -------
        stix2.ExternalReference
            The external reference object.
        """
        external_reference = stix2.ExternalReference(
            source_name=self.author["name"],
            url=url,
            description=description,
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return external_reference

    def create_file(self, vtobj, incident_id: Optional[str] = None) -> str:
        """
        Create a file and link it to the created incident, if any.

        Parameters
        ----------
        vtobj
            Virustotal object with the notification and its related file.
        incident_id : str, optional
            Id of the incident to be linked to the file using a `related-to` relationship.

        Returns
        -------
        str
            Id of the created file.
        """
        score = None
        try:
            if hasattr(vtobj, "last_analysis_stats"):
                score = self._compute_score(vtobj.last_analysis_stats)
        except ZeroDivisionError as e:
            self.helper.log_error(f"Unable to compute score of file, err = {e}")

        file = stix2.File(
            type="file",
            name=f'{vtobj.meaningful_name if hasattr(vtobj, "meaningful_name") else "unknown"}',
            hashes={
                "MD5": vtobj.md5,
                "SHA256": vtobj.sha256,
                "SHA1": vtobj.sha1,
            },
            size=vtobj.size,
            custom_properties={
                "x_opencti_score": score,
                "created_by_ref": self.author["id"],
            },
        )
        self.bundle.append(file)
        # Link to the incident if any.
        if incident_id is not None:
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to",
                    incident_id,
                    file["id"],
                ),
                relationship_type="related-to",
                created_by_ref=self.author["id"],
                source_ref=incident_id,
                target_ref=file["id"],
                confidence=self.helper.connect_confidence_level,
                allow_custom=True,
            )
            self.bundle.append(relationship)
        return file["id"]

    def create_ruleset(
        self,
        ruleset_id: str,
        incident_id: Optional[str] = None,
        file_id: Optional[str] = None,
    ):
        """
        Get the ruleset from VirusTotal, parse the yara rules and create them.

        If an incident or a file has been created, the yara rules will be linked to them.

        Parameters
        ----------
        ruleset_id : str
            Ruleset id of the notification to retrieve.
        incident_id : str, optional
            Id of the incident to be linked to the file using a `related-to` relationship.
        file_id : str, optional
            Id of the file to be linked to the file using a `related-to` relationship.
        """
        ruleset = self.client.get_object(f"/intelligence/hunting_rulesets/{ruleset_id}")

        parser = plyara.Plyara()
        rules = parser.parse_string(ruleset.rules)

        for rule in rules:
            indicator = stix2.Indicator(
                created_by_ref=self.author,
                name=rule["rule_name"],
                description=next(
                    (i["date"] for i in rule.get("metadata", {}) if "date" in i),
                    "No description",
                ),
                confidence=self.helper.connect_confidence_level,
                pattern=plyara.utils.rebuild_yara_rule(rule),
                pattern_type="yara",
                valid_from=self.helper.api.stix2.format_date(
                    next(
                        (i["date"] for i in rule.get("metadata", {}) if "date" in i),
                        None,
                    )
                ),
                custom_properties={
                    "x_opencti_main_observable_type": "StixFile",
                },
            )
            self.helper.log_debug(
                f"[VirusTotal Livehunt Notifications] yara indicator created: {indicator}"
            )
            self.bundle.append(indicator)

            if incident_id is not None:
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to",
                        incident_id,
                        indicator["id"],
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.author["id"],
                    source_ref=incident_id,
                    target_ref=indicator["id"],
                    confidence=self.helper.connect_confidence_level,
                    allow_custom=True,
                )
                self.bundle.append(relationship)

            if file_id is not None:
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to",
                        file_id,
                        indicator["id"],
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.author["id"],
                    source_ref=file_id,
                    target_ref=indicator["id"],
                    confidence=self.helper.connect_confidence_level,
                    allow_custom=True,
                )
                self.bundle.append(relationship)

    def delete_livehunt_notification(self, notification_id):
        """
        Delete a Livehunt Notification.

        Parameters
        ----------
        notification_id : str
            Io of the notification to delete.
        """

        url = f"/intelligence/hunting_notifications/{notification_id}"
        return self.client.delete(url)

    @staticmethod
    def _compute_score(stats: dict) -> int:
        """
        Compute the score for the observable.

        score = malicious_count / total_count * 100

        Parameters
        ----------
        stats : dict
            Dictionary with counts of each category (e.g. `harmless`, `malicious`, ...)

        Returns
        -------
        int
            Score, in percent, rounded.
        """
        try:
            vt_score = round(
                (
                    stats["malicious"]
                    / (stats["harmless"] + stats["undetected"] + stats["malicious"])
                )
                * 100
            )
        except ZeroDivisionError as e:
            raise ValueError(
                "Cannot compute score. VirusTotal may have no record of the observable"
            ) from e
        return vt_score

    def send_bundle(self, work_id: str):
        """
        Send the bundle to OpenCTI.

        After being sent, the bundle is reset.

        Parameters
        ----------
        work_id : str
            Work id to use
        """
        bundle = stix2.Bundle(objects=self.bundle, allow_custom=True)
        self.helper.log_debug(f"Sending bundle: {bundle}")
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(serialized_bundle, work_id=work_id)
        # Reset the bundle for the next import.
        self.bundle = []
