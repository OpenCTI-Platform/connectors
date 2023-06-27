# -*- coding: utf-8 -*-
"""Livehunt builder module."""

import json

import stix2
import vt
from pycti import Incident, OpenCTIConnectorHelper, StixCoreRelationship


class LivehuntBuilder:
    """Virustotal Livehunt builder."""

    def __init__(
        self,
        client: vt.Client,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        tag: str,
        create_file: bool,
        delete_notification: bool,
    ) -> None:
        """Initialize Virustotal builder."""
        self.client = client
        self.helper = helper
        self.author = author
        self.bundle = [self.author]
        self.tag = tag
        self.with_file = create_file
        self.delete_notification = delete_notification

    def send_bundle(self, work_id: str) -> None:
        bundle = stix2.Bundle(objects=self.bundle, allow_custom=True)
        self.helper.log_debug(f"Sending bundle: {bundle}")
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(serialized_bundle, work_id=work_id)
        # Reset the bundle for the next import.
        self.bundle = []

    def create_alerts(self, start_date: str):
        url = "/intelligence/hunting_notifications"
        params = f"date:{start_date}+"
        if self.tag:
            params += f" tag:{self.tag}"

        self.helper.log_debug(f"Url for notifications: {url} / params: {params}")
        files_iterator = self.client.iterator(url, params={"filter": params})

        for vtobj in files_iterator:
            self.helper.log_debug(json.dumps(vtobj.__dict__, indent=2))

            # Create external reference to Virustotal report
            external_reference = self.create_external_reference(
                f"https://www.virustotal.com/api/v3/intelligence/hunting_notifications/{vtobj.id}",
                f"Rule name: {vtobj.rule_name}",
            )

            # Create the alert
            name = f'Alert from rule {vtobj.rule_name} {f"{vtobj.rule_tags}" if vtobj.rule_tags else ""}'
            incident = stix2.Incident(
                id=Incident.generate_id(name),
                incident_type="alert",
                name=name,
                description=f"Snippet:\n{vtobj.snippet}",
                source=vtobj.type,
                created_by_ref=self.author["id"],
                confidence=self.helper.connect_confidence_level,
                labels=vtobj.tags,
                external_references=[external_reference],
                allow_custom=True,
            )
            self.bundle.append(incident)

            if self.with_file:
                filehash = vtobj.id.split("-")[2]
                self.create_file(filehash, incident["id"])

            if self.delete_notification:
                self.delete_livehunt_notification(vtobj.id)

    def create_external_reference(self, url: str, description: str):
        external_reference = stix2.ExternalReference(
            source_name=self.author["name"],
            url=url,
            description=description,
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return external_reference

    def create_file(self, filehash: str, incident_id: str):
        self.helper.log_debug(f"Retrieving info of file {filehash}")
        vtfile = self.client.get_object(f"/files/{filehash}")
        if vtfile:
            self.helper.log_info(json.dumps(vtfile.__dict__, indent=2))
            score = None
            try:
                if hasattr(vtfile, "last_analysis_stats"):
                    score = self._compute_score(vtfile.last_analysis_stats)
            except ZeroDivisionError as e:
                self.helper.log_error(f"Unable to compute score of file, err = {e}")

            file = stix2.File(
                type="file",
                name=f'{vtfile.meaningful_name if hasattr(vtfile, "meaningful_name") else "unknown"}',
                hashes={
                    "MD5": vtfile.md5,
                    "SHA256": vtfile.sha256,
                    "SHA1": vtfile.sha1,
                },
                size=vtfile.size,
                custom_properties={
                    "x_opencti_score": score,
                    "created_by_ref": self.author["id"],
                },
            )
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
                allow_custom=True,
            )
            self.bundle += [file, relationship]
        else:
            self.helper.log_debug(f"No info on file {filehash}")

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
