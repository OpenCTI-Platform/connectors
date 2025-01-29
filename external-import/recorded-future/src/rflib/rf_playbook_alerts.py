import datetime
import threading

import pycti
import pytz
import stix2
from pycti import StixCoreRelationship

from .constants import TLP_MAP
from .make_markdown_table import make_markdown_table


class RecordedFuturePlaybookAlertConnector(threading.Thread):
    def __init__(
        self,
        helper,
        rf_alerts_api,
        severity_threshold_domain_abuse,
        severity_threshold_identity_novel_exposures,
        severity_threshold_code_repo_leakage,
        debug,
        tlp,
    ):
        threading.Thread.__init__(self)
        self.helper = helper

        self.helper.log_info(
            "Starting Recorded Future Playbook Alert connector module initialization"
        )

        # Additional configuration
        self.work_id = None
        self.author = self._create_author()
        self.tlp = self.tlp = TLP_MAP.get(tlp, None)
        self.threshold_domain_abuse = severity_threshold_domain_abuse
        self.threshold_identity_novel_exposure = (
            severity_threshold_identity_novel_exposures
        )
        self.threshold_code_repo_leakage = severity_threshold_code_repo_leakage
        self.debug_var = debug

        self.playbook_alert_priority_threshold = {
            "identity_novel_exposures": self.threshold_identity_novel_exposure,
            "domain_abuse": self.threshold_domain_abuse,
            "code_repo_leakage": self.threshold_code_repo_leakage,
        }

        self.api_recorded_future = rf_alerts_api

        self.severity_links = {
            "High": "high",
            "Moderate": "medium",
            "Informational": "low",
        }

    @staticmethod
    def _create_author():
        """Creates Recorded Future Author"""
        return stix2.Identity(
            id=pycti.Identity.generate_id("Recorded Future", "organization"),
            name="Recorded Future",
            identity_class="organization",
        )

    def run(self):
        timestamp = datetime.datetime.now(pytz.timezone("UTC"))
        self.work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            "Recorded Future Playbook Alert",
        )
        current_state = self.helper.get_state()
        playbook_types = [
            "domain_abuse",
            "identity_novel_exposures",
            "code_repo_leakage",
        ]
        for playbook_type in playbook_types:
            self.api_recorded_future.playbook_alerts_summaries = []
            if (
                current_state is not None
                and str("last_playbook_alert_run_" + playbook_type) in current_state
            ):
                current_state_datetime = datetime.datetime.strptime(
                    current_state[str("last_playbook_alert_run_" + playbook_type)],
                    "%Y-%m-%dT%H:%M:%S",
                )
                self.api_recorded_future.get_playbook_id(
                    category=playbook_type,
                    trigger_from=current_state_datetime.strftime("%Y-%m-%dT%H:%M:%S"),
                    trigger_to=timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
                    priority_threshold=self.playbook_alert_priority_threshold[
                        playbook_type
                    ],
                )
            else:
                self.api_recorded_future.get_playbook_id(
                    category=playbook_type,
                    trigger_from=(
                        datetime.datetime.today() - datetime.timedelta(days=1)
                    ).strftime("%Y-%m-%dT%H:%M:%S"),
                    trigger_to=timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
                    priority_threshold=self.playbook_alert_priority_threshold[
                        playbook_type
                    ],
                )

            for plb_alert in self.api_recorded_future.playbook_alerts_summaries:
                try:
                    self.helper.log_info(
                        plb_alert.title + " - " + plb_alert.playbook_alert_id
                    )
                    playbook_alert = (
                        self.api_recorded_future.get_complete_playbook_alert(plb_alert)
                    )
                    if playbook_alert["data"]["panel_status"]["status"] != "Dismissed":
                        if plb_alert.category == "identity_novel_exposures":
                            self.create_incident_from_playbook_alert_identity_novel_exposures(
                                playbook_alert
                            )
                        elif plb_alert.category == "domain_abuse":
                            self.create_incident_from_playbook_alert_domain_abuse(
                                playbook_alert
                            )
                        elif plb_alert.category == "code_repo_leakage":
                            self.create_incident_from_playbook_alert_code_repo_leakage(
                                playbook_alert
                            )
                    else:
                        self.debug(
                            str("Dismissed : ")
                            + playbook_alert["data"]["playbook_alert_id"]
                        )
                except Exception as err:
                    self.helper.log_error(err)
                self.update_state(plb_alert.category)

        for playbook_type in playbook_types:
            self.update_state(playbook_type)

        message = (
            f"{self.helper.connect_name} connector successfully run for Playbook Alerts"
        )
        self.helper.api.work.to_processed(self.work_id, message)

    def debug(self, text):
        if self.debug_var:
            self.helper.log_error(text)

    def update_state(self, playbook_type):
        timestamp_checkpoint = datetime.datetime.now(pytz.timezone("UTC"))
        current_state = self.helper.get_state()
        if current_state is not None:
            current_state[str("last_playbook_alert_run_" + playbook_type)] = (
                timestamp_checkpoint.strftime("%Y-%m-%dT%H:%M:%S")
            )
            self.helper.set_state(current_state)
        else:
            current_state_new = {}
            current_state_new[str("last_playbook_alert_run_" + playbook_type)] = (
                timestamp_checkpoint.strftime("%Y-%m-%dT%H:%M:%S")
            )
            self.helper.set_state(current_state_new)

    def create_incident_from_playbook_alert_code_repo_leakage(self, playbook_alert):
        bundle_objects = []
        playbook_alert_description = make_markdown_table(
            [
                ["Panel", "Status"],
                ["Category", playbook_alert["data"]["panel_status"]["case_rule_label"]],
                ["Title", playbook_alert["data"]["panel_status"]["entity_name"]],
                [
                    "Priority",
                    self.severity_links[
                        playbook_alert["data"]["panel_status"]["priority"]
                    ],
                ],
                ["Playbook Alert ID", playbook_alert["data"]["playbook_alert_id"]],
            ]
        )
        playbook_alert_name = str(
            "["
            + playbook_alert["data"]["panel_status"]["case_rule_label"]
            + "] "
            + playbook_alert["data"]["panel_status"]["entity_name"]
        )
        stix_external_ref = stix2.ExternalReference(
            source_name="Recorded Future",
            url=str(playbook_alert["data"]["panel_status"]["entity_name"]),
        )
        stix_incident = stix2.Incident(
            id=pycti.Incident.generate_id(
                playbook_alert_name, playbook_alert["data"]["panel_status"]["created"]
            ),
            name=playbook_alert_name,
            object_marking_refs=self.tlp,
            description=playbook_alert_description,
            created=playbook_alert["data"]["panel_status"]["created"],
            modified=playbook_alert["data"]["panel_status"]["updated"],
            allow_custom=True,
            severity=self.severity_links[
                playbook_alert["data"]["panel_status"]["priority"]
            ],
            incident_type=playbook_alert["data"]["panel_status"]["case_rule_label"],
            labels=[str(playbook_alert["data"]["panel_status"]["case_rule_label"])],
            external_references=[stix_external_ref],
            created_by_ref=self.author,
        )
        bundle_objects.append(stix_incident)

        summary_content = ""
        summary_content = summary_content + "\n" + "## Repository : " + "\n"
        table_markdown = [
            [
                "id",
                playbook_alert["data"]["panel_evidence_summary"]["repository"]["id"],
            ],
            [
                "name",
                playbook_alert["data"]["panel_evidence_summary"]["repository"]["name"],
            ],
            [
                "owner_name",
                playbook_alert["data"]["panel_evidence_summary"]["repository"]["owner"][
                    "name"
                ],
            ],
        ]
        summary_content = summary_content + "\n" + make_markdown_table(table_markdown)

        for i in range(
            len(playbook_alert["data"]["panel_evidence_summary"]["evidence"])
        ):
            summary_content = summary_content + "\n ## Evidence " + str(i + 1)
            for key in playbook_alert["data"]["panel_evidence_summary"]["evidence"][i]:
                summary_content = summary_content + "\n" + "### " + key + "\n"
                if isinstance(
                    playbook_alert["data"]["panel_evidence_summary"]["evidence"][i][
                        key
                    ],
                    str,
                ):
                    summary_content = (
                        summary_content
                        + "\n"
                        + make_markdown_table(
                            [
                                [
                                    key,
                                    playbook_alert["data"]["panel_evidence_summary"][
                                        "evidence"
                                    ][i][key],
                                ]
                            ]
                        )
                    )
                else:
                    table_markdown = []
                    for j in range(
                        len(
                            playbook_alert["data"]["panel_evidence_summary"][
                                "evidence"
                            ][i][key]
                        )
                    ):
                        for subkey in playbook_alert["data"]["panel_evidence_summary"][
                            "evidence"
                        ][i][key][j]:
                            table_markdown.append(
                                [
                                    subkey,
                                    playbook_alert["data"]["panel_evidence_summary"][
                                        "evidence"
                                    ][i][key][j][subkey],
                                ]
                            )
                    if len(table_markdown) > 0:
                        summary_content = (
                            summary_content + "\n" + make_markdown_table(table_markdown)
                        )
        stix_note = stix2.Note(
            id=pycti.Note.generate_id(
                summary_content,
                datetime.datetime.now(pytz.timezone("UTC")).strftime(
                    "%Y-%m-%dT%H:%M:%S"
                ),
            ),
            object_marking_refs=self.tlp,
            abstract="# Evidence summary panel",
            content=summary_content,
            object_refs=[stix_incident.id],
            created_by_ref=self.author,
        )
        bundle_objects.append(stix_note)
        bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
        self.helper.send_stix2_bundle(bundle, update=True, work_id=self.work_id)

    def create_incident_from_playbook_alert_identity_novel_exposures(
        self, playbook_alert
    ):
        bundle_objects = []
        subject = "NOT FOUND"
        if "entity_name" in playbook_alert["data"]["panel_status"]:
            subject = playbook_alert["data"]["panel_status"]["entity_name"]
        elif "subject" in playbook_alert["data"]["panel_evidence_summary"]:
            subject = playbook_alert["data"]["panel_evidence_summary"]["subject"]
        elif "username" in playbook_alert["data"]["panel_evidence_summary"]:
            subject = playbook_alert["data"]["panel_evidence_summary"]["username"]
        playbook_alert_description = make_markdown_table(
            [
                ["Panel", "Status"],
                ["Category", playbook_alert["data"]["panel_status"]["case_rule_label"]],
                ["Title", subject],
                [
                    "Priority",
                    self.severity_links[
                        playbook_alert["data"]["panel_status"]["priority"]
                    ],
                ],
                ["Playbook Alert ID", playbook_alert["data"]["playbook_alert_id"]],
            ]
        )
        playbook_alert_name = str(
            "["
            + playbook_alert["data"]["panel_status"]["case_rule_label"]
            + "] "
            + subject
        )
        stix_incident = stix2.Incident(
            id=pycti.Incident.generate_id(
                playbook_alert_name, playbook_alert["data"]["panel_status"]["created"]
            ),
            name=playbook_alert_name,
            object_marking_refs=self.tlp,
            description=playbook_alert_description,
            created=playbook_alert["data"]["panel_status"]["created"],
            modified=playbook_alert["data"]["panel_status"]["updated"],
            allow_custom=True,
            severity=self.severity_links[
                playbook_alert["data"]["panel_status"]["priority"]
            ],
            incident_type=playbook_alert["data"]["panel_status"]["case_rule_label"],
            labels=["Identity Novel Exposures"],
            created_by_ref=self.author,
        )
        bundle_objects.append(stix_incident)
        summary_content = ""
        summary_content = (
            summary_content
            + "\n"
            + "### Subject : "
            + playbook_alert["data"]["panel_evidence_summary"]["subject"]
            + "\n"
        )

        table_markdown = []
        for supkey in playbook_alert["data"]["panel_evidence_summary"]:
            if supkey == "exposed_secret":
                for key in playbook_alert["data"]["panel_evidence_summary"][
                    "exposed_secret"
                ]:
                    if key == "details":
                        if (
                            "properties"
                            in playbook_alert["data"]["panel_evidence_summary"][
                                "exposed_secret"
                            ]["details"]
                        ):
                            table_markdown.append(
                                [
                                    "properties",
                                    str(
                                        playbook_alert["data"][
                                            "panel_evidence_summary"
                                        ]["exposed_secret"]["details"]["properties"]
                                    ),
                                ]
                            )
                        if (
                            "clear_text_hint"
                            in playbook_alert["data"]["panel_evidence_summary"][
                                "exposed_secret"
                            ]["details"]
                        ):
                            table_markdown.append(
                                [
                                    "clear_text_hint",
                                    playbook_alert["data"]["panel_evidence_summary"][
                                        "exposed_secret"
                                    ]["details"]["clear_text_hint"],
                                ]
                            )
                    elif key == "hashes":
                        for subkey in playbook_alert["data"]["panel_evidence_summary"][
                            "exposed_secret"
                        ]["hashes"]:
                            table_markdown.append([subkey["algorithm"], subkey["hash"]])
                    else:
                        table_markdown.append(
                            [
                                key,
                                str(
                                    playbook_alert["data"]["panel_evidence_summary"][
                                        "exposed_secret"
                                    ][key]
                                ),
                            ]
                        )
            elif supkey == "compromised_host":
                table_markdownsub = [["Comprised", "Host"]]
                for subkey in playbook_alert["data"]["panel_evidence_summary"][
                    "compromised_host"
                ]:
                    table_markdownsub.append(
                        [
                            subkey,
                            playbook_alert["data"]["panel_evidence_summary"][
                                "compromised_host"
                            ][subkey],
                        ]
                    )
                summary_content = (
                    summary_content + "\n" + make_markdown_table(table_markdownsub)
                )
            elif supkey == "malware_family":
                table_markdownsub = [["Malware", "Family"]]
                for subkey in playbook_alert["data"]["panel_evidence_summary"][
                    "malware_family"
                ]:
                    table_markdownsub.append(
                        [
                            subkey,
                            playbook_alert["data"]["panel_evidence_summary"][
                                "malware_family"
                            ][subkey],
                        ]
                    )
                summary_content = (
                    summary_content + "\n" + make_markdown_table(table_markdownsub)
                )
            elif supkey == "infrastructure":
                table_markdownsub = [["Infrastructure", ""]]
                for subkey in playbook_alert["data"]["panel_evidence_summary"][
                    "infrastructure"
                ]:
                    table_markdownsub.append(
                        [
                            subkey,
                            playbook_alert["data"]["panel_evidence_summary"][
                                "infrastructure"
                            ][subkey],
                        ]
                    )
                    if subkey == "ip":
                        stix_ipv4address = stix2.IPv4Address(
                            value=playbook_alert["data"]["panel_evidence_summary"][
                                "infrastructure"
                            ][subkey],
                            object_marking_refs=self.tlp,
                            custom_properties={"x_opencti_created_by_ref": self.author},
                        )
                        stix_relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", stix_incident.id, stix_ipv4address.id
                            ),
                            relationship_type="related-to",
                            source_ref=stix_incident.id,
                            target_ref=stix_ipv4address.id,
                            created_by_ref=self.author,
                            object_marking_refs=self.tlp,
                        )
                        bundle_objects.append(stix_ipv4address)
                        bundle_objects.append(stix_relationship)
                    summary_content = (
                        summary_content + "\n" + make_markdown_table(table_markdownsub)
                    )
            else:
                table_markdown.append(
                    [
                        supkey,
                        str(playbook_alert["data"]["panel_evidence_summary"][supkey]),
                    ]
                )
        summary_content = summary_content + "\n" + make_markdown_table(table_markdown)
        summary_content = (
            summary_content
            + "\n"
            + make_markdown_table(
                [
                    [
                        "dump name",
                        playbook_alert["data"]["panel_evidence_summary"]["dump"][
                            "name"
                        ],
                    ],
                    [
                        "dump description",
                        playbook_alert["data"]["panel_evidence_summary"]["dump"][
                            "description"
                        ],
                    ],
                ]
            )
        )
        stix_note = stix2.Note(
            id=pycti.Note.generate_id(
                summary_content,
                datetime.datetime.now(pytz.timezone("UTC")).strftime(
                    "%Y-%m-%dT%H:%M:%S"
                ),
            ),
            object_marking_refs=self.tlp,
            abstract="# Evidence summary panel",
            content=summary_content,
            object_refs=[stix_incident.id],
            created_by_ref=self.author,
        )
        bundle_objects.append(stix_note)
        bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
        self.helper.send_stix2_bundle(bundle, update=True, work_id=self.work_id)

    def create_incident_from_playbook_alert_domain_abuse(self, playbook_alert):
        bundle_objects = []
        playbook_alert_description = make_markdown_table(
            [
                ["Panel", "Status"],
                ["Category", playbook_alert["data"]["panel_status"]["case_rule_label"]],
                ["Title", playbook_alert["data"]["panel_status"]["entity_name"]],
                [
                    "Priority",
                    self.severity_links[
                        playbook_alert["data"]["panel_status"]["priority"]
                    ],
                ],
                ["Playbook Alert ID", playbook_alert["data"]["playbook_alert_id"]],
            ]
        )
        playbook_alert_name = str(
            "["
            + playbook_alert["data"]["panel_status"]["case_rule_label"]
            + "] "
            + playbook_alert["data"]["panel_status"]["entity_name"]
        )

        stix_incident = stix2.Incident(
            id=pycti.Incident.generate_id(
                playbook_alert_name, playbook_alert["data"]["panel_status"]["created"]
            ),
            name=playbook_alert_name,
            object_marking_refs=self.tlp,
            description=playbook_alert_description,
            created=playbook_alert["data"]["panel_status"]["created"],
            modified=playbook_alert["data"]["panel_status"]["updated"],
            allow_custom=True,
            severity=self.severity_links[
                playbook_alert["data"]["panel_status"]["priority"]
            ],
            incident_type=playbook_alert["data"]["panel_status"]["case_rule_label"],
            labels=["Domain Abuse"],
            created_by_ref=self.author,
        )
        bundle_objects.append(stix_incident)
        stix_url = stix2.DomainName(
            value=playbook_alert["data"]["panel_status"]["entity_name"],
            object_marking_refs=self.tlp,
        )
        stix_relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to", stix_incident.id, stix_url.id
            ),
            relationship_type="related-to",
            source_ref=stix_incident.id,
            target_ref=stix_url.id,
            created_by_ref=self.author,
            object_marking_refs=self.tlp,
        )
        bundle_objects.append(stix_url)
        bundle_objects.append(stix_relationship)
        if len(playbook_alert["data"]["panel_evidence_whois"]["body"]) > 0:
            evidence_whois_content = "### Who is"
            for whois in playbook_alert["data"]["panel_evidence_whois"]["body"]:
                table_markdown = []
                for key in whois:
                    if key != "value":
                        table_markdown.append([key, str(whois[key])])
                for key in whois["value"]:
                    table_markdown.append([key, str(whois["value"][key])])
                evidence_whois_content = (
                    evidence_whois_content + "\n" + make_markdown_table(table_markdown)
                )
            stix_note = stix2.Note(
                id=pycti.Note.generate_id(
                    evidence_whois_content,
                    datetime.datetime.now(pytz.timezone("UTC")).strftime(
                        "%Y-%m-%dT%H:%M:%S"
                    ),
                ),
                object_marking_refs=self.tlp,
                abstract="# Evidence WhoIs panel",
                content=evidence_whois_content,
                object_refs=[stix_incident.id],
                created_by_ref=self.author,
            )
            bundle_objects.append(stix_note)
        if len(playbook_alert["data"]["panel_evidence_dns"]) > 0 and (
            len(playbook_alert["data"]["panel_evidence_dns"]["ip_list"]) > 0
            or len(playbook_alert["data"]["panel_evidence_dns"]["ns_list"]) > 0
            or len(playbook_alert["data"]["panel_evidence_dns"]["mx_list"]) > 0
        ):
            evidence_dns_content = ""
            if len(playbook_alert["data"]["panel_evidence_dns"]["ip_list"]) > 0:
                evidence_dns_content = "\n### IP List"
            for ip in playbook_alert["data"]["panel_evidence_dns"]["ip_list"]:
                table_markdown = []
                for key in ip:
                    table_markdown.append([key, str(ip[key])])
                evidence_dns_content = (
                    evidence_dns_content + "\n" + make_markdown_table(table_markdown)
                )
                stix_ipv4address = stix2.IPv4Address(
                    value=(str(ip["entity"])).replace("ip:", ""),
                    object_marking_refs=self.tlp,
                )
                stix_relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", stix_incident.id, stix_ipv4address.id
                    ),
                    relationship_type="related-to",
                    source_ref=stix_incident.id,
                    target_ref=stix_ipv4address.id,
                    created_by_ref=self.author,
                    object_marking_refs=self.tlp,
                )
                bundle_objects.append(stix_ipv4address)
                bundle_objects.append(stix_relationship)
            if len(playbook_alert["data"]["panel_evidence_dns"]["mx_list"]) > 0:
                evidence_dns_content = evidence_dns_content + "\n### MX List"
            for mx in playbook_alert["data"]["panel_evidence_dns"]["mx_list"]:
                table_markdown = []
                for key in mx:
                    table_markdown.append([key, str(mx[key])])
                evidence_dns_content = (
                    evidence_dns_content + "\n" + make_markdown_table(table_markdown)
                )
            if len(playbook_alert["data"]["panel_evidence_dns"]["ns_list"]) > 0:
                evidence_dns_content = evidence_dns_content + "\n### NS List"
            for ns in playbook_alert["data"]["panel_evidence_dns"]["ns_list"]:
                table_markdown = []
                for key in ns:
                    table_markdown.append([key, str(ns[key])])
                evidence_dns_content = (
                    evidence_dns_content + "\n" + make_markdown_table(table_markdown)
                )
                stix_domain = stix2.DomainName(
                    value=(str(ns["entity"])).replace("idn:", ""),
                    object_marking_refs=self.tlp,
                )
                stix_relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", stix_incident.id, stix_domain.id
                    ),
                    relationship_type="related-to",
                    source_ref=stix_incident.id,
                    target_ref=stix_domain.id,
                    created_by_ref=self.author,
                    object_marking_refs=self.tlp,
                )
                bundle_objects.append(stix_domain)
                bundle_objects.append(stix_relationship)
            stix_note = stix2.Note(
                id=pycti.Note.generate_id(
                    evidence_dns_content,
                    datetime.datetime.now(pytz.timezone("UTC")).strftime(
                        "%Y-%m-%dT%H:%M:%S"
                    ),
                ),
                object_marking_refs=self.tlp,
                abstract="# Evidence DNS panel",
                content=evidence_dns_content,
                object_refs=[stix_incident.id],
                created_by_ref=self.author,
            )
            bundle_objects.append(stix_note)
        evidence_summary_content = ""
        if len(playbook_alert["data"]["panel_evidence_summary"]) > 0 and (
            len(
                playbook_alert["data"]["panel_evidence_summary"]["resolved_record_list"]
            )
            > 0
            or len(playbook_alert["data"]["panel_evidence_summary"]["screenshots"]) > 0
        ):
            evidence_summary_content = "### Resolved records"
            for record in playbook_alert["data"]["panel_evidence_summary"][
                "resolved_record_list"
            ]:
                evidence_summary_content = (
                    evidence_summary_content
                    + "\n"
                    + make_markdown_table(
                        [
                            ["Key", "Value"],
                            ["entity", str(record["entity"])],
                            ["risk_score", str(record["risk_score"])],
                            ["criticality", str(record["criticality"])],
                            ["record_type", str(record["record_type"])],
                            ["context_list", str(record["context_list"])],
                        ]
                    )
                )
        bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
        self.helper.send_stix2_bundle(bundle, update=True, work_id=self.work_id)
