# -*- coding: utf-8 -*-
"""Livehunt builder module."""
import datetime
import io
import json
import logging
from typing import Optional

import magic
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
        author_name: str,
        tag: str,
        create_alert: bool,
        max_age_days: int,
        create_file: bool,
        upload_artifact: bool,
        create_yara_rule: bool,
        delete_notification: bool,
        extensions: list[str],
        min_file_size: int,
        max_file_size: int,
        min_positives: int,
    ) -> None:
        """Initialize Virustotal builder."""
        self.client = client
        self.helper = helper
        self.author = author
        self.author_name = author_name
        self.bundle = []
        self.tag = tag
        self.with_alert = create_alert
        self.max_age_days = max_age_days
        self.with_file = create_file
        self.upload_artifact = upload_artifact
        self.with_yara_rule = create_yara_rule
        self.delete_notification = delete_notification
        self.extensions = extensions
        self.min_file_size = min_file_size
        self.max_file_size = max_file_size
        self.min_positives = min_positives

    def process(self, start_date: str, timestamp: int):
        # Work id will only be set and instantiated if there are bundles to send.
        work_id = None
        url = "/intelligence/hunting_notification_files"
        params = f"date:{start_date}+"
        if self.tag is not None and self.tag != "":
            self.helper.log_debug(f"Setting up filter with tag {self.tag}")
            params += f" tag:{self.tag}"

        self.helper.log_info(f"Url for notifications: {url} / params: {params}")
        files_iterator = self.client.iterator(url, params={"filter": params})

        for vtobj in files_iterator:
            self.helper.log_debug(json.dumps(vtobj.__dict__, indent=2))

            if self.delete_notification:
                self.delete_livehunt_notification(vtobj.id)

            if self.upload_artifact:
                if not self.artifact_exists_opencti(vtobj.sha256):
                    self.upload_artifact_opencti(vtobj)

            # If extension filters were set
            if self.extensions:
                # If the extension isn't in the list of extensions
                if (
                    not hasattr(vtobj, "type_extension")
                    or vtobj.type_extension not in self.extensions
                ):
                    self.helper.log_info(
                        f"Extension {vtobj.type_extension} not in filter {self.extensions}."
                    )
                    continue

            # If min positives set and file has fewer detections
            if (
                not hasattr(vtobj, "last_analysis_stats")
                or not self.min_positives
                or vtobj.last_analysis_stats.get("malicious", 0) < self.min_positives
            ):
                self.helper.log_info("Not enough detections")
                continue

            # If min size was set and file is below that size
            if self.min_file_size and self.min_file_size > int(vtobj.size):
                self.helper.log_info(
                    f"File too small ({vtobj.size} < {self.min_file_size}"
                )
                continue

            # If max size was set and file is above that size
            if self.max_file_size and self.max_file_size < int(vtobj.size):
                self.helper.log_info(
                    f"File too big ({vtobj.size} > {self.max_file_size}"
                )
                continue

            if self.max_age_days is not None:
                time_diff = datetime.datetime.now() - vtobj.first_submission_date
                if time_diff.days >= self.max_age_days:
                    self.helper.log_info(
                        f"First submission date {vtobj.first_submission_date} is too old (more than {self.max_age_days} days"
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

            if self.with_yara_rule:
                self.create_rule(
                    vtobj._context_attributes["ruleset_id"],
                    vtobj._context_attributes["rule_name"],
                    incident_id,
                    file_id,
                )

            if len(self.bundle) > 0:
                if work_id is None:
                    work_id = self.initiate_work(timestamp)
                self.send_bundle(work_id)

    def artifact_exists_opencti(self, sha256: str) -> bool:
        """
        Determine whether an Artifact already exists in OpenCTI.

        sha256: a str representing the sha256 of the artifact's file contents
        returns: a bool indicating the aforementioned
        """

        response = self.helper.api.stix_cyber_observable.read(
            filters=[{"key": "hashes_SHA256", "values": [sha256]}]
        )

        if response:
            return True
        return False

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
        name = f"""Alert from ruleset {vtobj._context_attributes["ruleset_name"]} file={vtobj.sha256}"""
        incident_id = Incident.generate_id(
            name, vtobj._context_attributes["notification_date"]
        )
        alert = self.helper.api.incident.read(id=incident_id)
        if alert:
            self.helper.log_info(f"Alert {alert} already exists, skipping")
            return None
        incident = stix2.Incident(
            id=incident_id,
            incident_type="alert",
            name=name,
            description=f'Snippet:\n{vtobj._context_attributes["notification_snippet"]}',
            source=self._SOURCE,
            created_by_ref=self.author["standard_id"],
            confidence=self.helper.connect_confidence_level,
            labels=vtobj._context_attributes["notification_tags"],
            external_references=[external_reference],
            allow_custom=True,
        )
        self.helper.log_debug(f"Adding alert: {incident}")
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
            source_name=self.author_name,
            url=url,
            description=description,
            custom_properties={
                "created_by_ref": self.author["standard_id"],
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

        external_reference = self.create_external_reference(
            f"https://www.virustotal.com/gui/file/{vtobj.sha256}",
            "Virustotal Analysis",
        )

        file = stix2.File(
            type="file",
            name=f'{vtobj.meaningful_name if hasattr(vtobj, "meaningful_name") else "unknown"}',
            hashes={
                "MD5": vtobj.md5,
                "SHA256": vtobj.sha256,
                "SHA1": vtobj.sha1,
            },
            size=vtobj.size,
            external_references=[external_reference],
            custom_properties={
                "x_opencti_score": score,
                "created_by_ref": self.author["standard_id"],
            },
            allow_custom=True,
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
                created_by_ref=self.author["standard_id"],
                source_ref=incident_id,
                target_ref=file["id"],
                confidence=self.helper.connect_confidence_level,
                allow_custom=True,
            )
            self.bundle.append(relationship)
        return file["id"]

    def create_rule(
        self,
        ruleset_id: str,
        rule_name: str,
        incident_id: Optional[str] = None,
        file_id: Optional[str] = None,
    ):
        """
        Get the rule from VirusTotal, parse the yara rules and create the wanted rule.

        A single rule is created, the one having the name matching.
        If an incident or a file has been created, the yara rules will be linked to them.

        Parameters
        ----------
        ruleset_id : str
            Ruleset id of the notification to retrieve.
        rule_name : str
            Name of the rule that matched.
        incident_id : str, optional
            Id of the incident to be linked to the file using a `related-to` relationship.
        file_id : str, optional
            Id of the file to be linked to the file using a `related-to` relationship.
        """
        ruleset = self.client.get_object(f"/intelligence/hunting_rulesets/{ruleset_id}")

        parser = plyara.Plyara()
        rules = parser.parse_string(ruleset.rules)

        for rule in rules:
            if rule["rule_name"] == rule_name:
                self.helper.log_debug(f"Adding rule name {rule_name}")
                # Default valid_from with current date
                valid_from = self.helper.api.stix2.format_date(
                    datetime.datetime.utcnow()
                )
                try:
                    valid_from = self.helper.api.stix2.format_date(
                        next(
                            (
                                i["date"]
                                for i in rule.get("metadata", {})
                                if "date" in i
                            ),
                            None,
                        )
                    )
                except ValueError as e:
                    self.helper.log_error(
                        f"Date not valid, setting to {valid_from}, err: {e}"
                    )

                indicator = stix2.Indicator(
                    created_by_ref=self.author["standard_id"],
                    name=rule["rule_name"],
                    description=next(
                        (i["date"] for i in rule.get("metadata", {}) if "date" in i),
                        "No description",
                    ),
                    confidence=self.helper.connect_confidence_level,
                    pattern=plyara.utils.rebuild_yara_rule(rule),
                    pattern_type="yara",
                    valid_from=valid_from,
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
                        created_by_ref=self.author["standard_id"],
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
                        created_by_ref=self.author["standard_id"],
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

    def initiate_work(self, timestamp: int) -> str:
        now = datetime.datetime.utcfromtimestamp(timestamp)
        friendly_name = "Virustotal Livehunt Notifications run @ " + now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        self.helper.log_info(
            f"[Virustotal Livehunt Notifications] workid {work_id} initiated"
        )
        return work_id

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

    def upload_artifact_opencti(self, vtobj):
        """Upload a file to OpenCTI."""
        file_name = (
            vtobj.meaningful_name if hasattr(vtobj, "meaningful_name") else vtobj.sha256
        )

        # Download the file to a file like object
        file_obj = io.BytesIO()
        self.helper.log_info(f"Downloading {vtobj.sha256}")
        self.client.download_file(vtobj.sha256, file_obj)
        file_obj.seek(0)
        file_contents = file_obj.read()

        mime_type = magic.from_buffer(file_contents, mime=True)

        kwargs = {
            "file_name": file_name,
            "data": file_contents,
            "mime_type": mime_type,
            "x_opencti_description": "Downloaded from Virustotal Livehunt Notifications.",
            "createdBy": self.author["standard_id"],
        }
        return self.helper.api.stix_cyber_observable.upload_artifact(**kwargs)

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
