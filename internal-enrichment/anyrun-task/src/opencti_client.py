import stix2
from anyrun_sandbox import AnyRunSandbox
from config import config
from pycti import (
    Identity,
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)

ANYRUN_INDICATOR_TO_MAIN_OBSERVABLE = {
    "domain": "Domain-Name",
    "url": "Url",
    "ip": "IPv4-Addr",
    "sha256": "File",
}

# Patterns used to build STIX indicators from ANY.RUN IoC entries.
# File hashes have to follow the canonical ``file:hashes.'<ALGO>'`` syntax so
# OpenCTI's pattern parser can normalise them; the other observable types use
# the simple ``<type>:value`` pattern.
ANYRUN_INDICATOR_PATTERNS = {
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "ip": "[ipv4-addr:value = '{value}']",
    "sha256": "[file:hashes.'SHA-256' = '{value}']",
}


class OpenCTI:
    def __init__(self, helper: OpenCTIConnectorHelper, anyrun: AnyRunSandbox):
        self._helper = helper
        self._anyrun = anyrun

        self._opencti_entity: dict | None = None

        self._identity = stix2.Identity(
            id=Identity.generate_id("ANY.RUN", "organization"),
            name="ANY.RUN",
            identity_class="organization",
            description="Empowers SOC teams with a Sandbox for real-time malware analysis, Threat Intelligence Lookup, "
            "and high-quality feeds to enhance detection and threat coverage.",
            contact_information="techsupport@any.run",
        )

        self._helper.send_stix2_bundle(
            self._helper.stix2_create_bundle([self._identity]),
        )

    def _process_message(self, data):
        self._load_opencti_entity(data)

        self._anyrun.load_analysis_object(self._opencti_entity)
        self._helper.log_info("Preparing for the analysis.")

        if self._opencti_entity.get(
            "entity_type"
        ) == "StixFile" and not self._opencti_entity.get("hashes"):
            raise ValueError(
                "StixFile entity must have at least one of the following hashes: SHA-256, SHA-1, MD5"
            )

        analysis_summary = self._anyrun.process_analysis()["data"]

        self._helper.log_info("Analysis successful")
        task_uuid = analysis_summary.get("analysis").get("uuid")

        self._update_main_observable(analysis_summary, task_uuid)
        self._attach_report(task_uuid)

        if self._anyrun.get_verdict(
            task_uuid
        ) != "No threats detected" and get_config_variable(
            "ANYRUN_ENABLE_IOC", ["anyrun", "enable_ioc"], config, default=True
        ):
            self._add_malicious_iocs(task_uuid)

    def _load_opencti_entity(self, data) -> None:
        """
        Loads OpenCTI entity object using message data

        :param data: Message data
        """
        opencti_entity = self._helper.api.stix_cyber_observable.read(
            id=data.get("entity_id"), withFiles=True
        )

        if opencti_entity is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, "
                "check the group of the connector user)"
            )

        self._opencti_entity = opencti_entity

    def _update_main_observable(self, analysis_summary: dict, task_uuid: str) -> None:
        """
        Updates main observable using ANY.RUN Sandbox analysis results

        :param analysis_summary: ANY.RUN Sandbox JSON summary
        :param task_uuid:  ANY.RUN Sandbox analysis uuid
        """
        labels = [tag.get("tag") for tag in analysis_summary["analysis"]["tags"]]

        if self._opencti_entity.get("entity_type") == "Url":
            observable = stix2.URL(
                value=self._opencti_entity.get("value"),
                custom_properties={
                    "x_opencti_labels": labels,
                    "x_opencti_score": self._get_score(
                        analysis_summary["analysis"]["scores"]["verdict"]["score"]
                    ),
                    "x_opencti_description": "Detected by ANY.RUN Sandbox",
                    "x_opencti_created_by_ref": self._identity.get("id"),
                    "x_opencti_external_references": self._get_external_reference(
                        task_uuid
                    ),
                },
            )
        else:
            observable = stix2.File(
                hashes={
                    "MD5": analysis_summary["analysis"]["content"]["mainObject"][
                        "hashes"
                    ]["md5"],
                    "SHA-256": analysis_summary["analysis"]["content"]["mainObject"][
                        "hashes"
                    ]["sha256"],
                    "SHA-1": analysis_summary["analysis"]["content"]["mainObject"][
                        "hashes"
                    ]["sha1"],
                },
                custom_properties={
                    "x_opencti_labels": labels,
                    "x_opencti_score": self._get_score(
                        analysis_summary["analysis"]["scores"]["verdict"]["score"]
                    ),
                    "x_opencti_description": "Detected by ANY.RUN Sandbox",
                    "x_opencti_created_by_ref": self._identity.get("id"),
                    "x_opencti_external_references": self._get_external_reference(
                        task_uuid
                    ),
                },
            )

        self._helper.send_stix2_bundle(
            self._helper.stix2_create_bundle([observable]), update=True
        )

    def _get_score(self, anyrun_score: int) -> int:
        """
        Adds score to the OpenCTI entity

        :param anyrun_score: ANY.RUN task score
        """
        if not (opencti_score := self._opencti_entity.get("x_opencti_score", 0)):
            return anyrun_score

        if anyrun_score > opencti_score:
            return anyrun_score

        return opencti_score

    def _add_malicious_iocs(self, task_uuid: str) -> None:
        """
        Process ANY.RUN task indicators. If indicator's threat level is 'No threads detected' crates related observable
            else creates a new stix indicator

        :param task_uuid: ANY.RUN task uuid
        """
        if iocs := self._anyrun.get_iocs(task_uuid):
            objects = list()

            for ioc in iocs:
                if ioc.get("reputation") == 0:
                    observable_type = ANYRUN_INDICATOR_TO_MAIN_OBSERVABLE.get(
                        ioc.get("type")
                    )
                    observable_value = ioc.get("ioc")

                    if observable_type == "File":
                        observable = stix2.File(
                            hashes={"SHA-256": observable_value},
                            custom_properties={
                                "x_opencti_description": "Detected by ANY.RUN Sandbox",
                                "x_opencti_created_by_ref": self._identity.get("id"),
                                "x_opencti_external_references": self._get_external_reference(
                                    task_uuid
                                ),
                            },
                        )
                    elif observable_type == "Domain-Name":
                        observable = stix2.DomainName(
                            value=observable_value,
                            custom_properties={
                                "x_opencti_description": "Detected by ANY.RUN Sandbox",
                                "x_opencti_created_by_ref": self._identity.get("id"),
                                "x_opencti_external_references": self._get_external_reference(
                                    task_uuid
                                ),
                            },
                        )
                    elif observable_type == "Url":
                        observable = stix2.URL(
                            value=observable_value,
                            custom_properties={
                                "x_opencti_description": "Detected by ANY.RUN Sandbox",
                                "x_opencti_created_by_ref": self._identity.get("id"),
                                "x_opencti_external_references": self._get_external_reference(
                                    task_uuid
                                ),
                            },
                        )
                    elif observable_type == "IPv4-Addr":
                        observable = stix2.IPv4Address(
                            value=observable_value,
                            custom_properties={
                                "x_opencti_description": "Detected by ANY.RUN Sandbox",
                                "x_opencti_created_by_ref": self._identity.get("id"),
                                "x_opencti_external_references": self._get_external_reference(
                                    task_uuid
                                ),
                            },
                        )

                    if observable.id == self._opencti_entity.get("standard_id"):
                        continue

                    relationship = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to",
                            observable.id,
                            self._opencti_entity.get("standard_id"),
                        ),
                        confidence=100,
                        description="Detected by ANY.RUN Sandbox",
                        relationship_type="related-to",
                        created_by_ref=self._identity.get("id"),
                        source_ref=observable.id,
                        target_ref=self._opencti_entity.get("standard_id"),
                        custom_properties={
                            "x_opencti_external_references": self._get_external_reference(
                                task_uuid
                            )
                        },
                    )

                    objects.append(observable)
                    objects.append(relationship)

                elif ioc.get("reputation") in (1, 2):
                    pattern_template = ANYRUN_INDICATOR_PATTERNS.get(ioc.get("type"))
                    if not pattern_template:
                        continue
                    pattern = pattern_template.format(value=ioc.get("ioc"))

                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        created_by_ref=self._identity.get("id"),
                        name=ioc.get("ioc"),
                        pattern_type="stix",
                        pattern=pattern,
                        custom_properties={
                            "x_opencti_score": {1: 50, 2: 100}.get(
                                ioc.get("reputation")
                            ),
                            "x_opencti_created_by_ref": self._identity.get("id"),
                            "x_opencti_external_references": self._get_external_reference(
                                task_uuid
                            ),
                            "x_opencti_main_observable_type": ANYRUN_INDICATOR_TO_MAIN_OBSERVABLE.get(
                                ioc.get("type")
                            ),
                        },
                    )

                    relationship = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "based-on",
                            indicator.id,
                            self._opencti_entity.get("standard_id"),
                        ),
                        confidence=100,
                        description="Detected by ANY.RUN Sandbox",
                        relationship_type="based-on",
                        created_by_ref=self._identity.get("id"),
                        source_ref=indicator.id,
                        target_ref=self._opencti_entity.get("standard_id"),
                        custom_properties={
                            "x_opencti_external_references": self._get_external_reference(
                                task_uuid
                            )
                        },
                    )

                    objects.append(indicator)
                    objects.append(relationship)

            self._helper.send_stix2_bundle(self._helper.stix2_create_bundle(objects))

    def _attach_report(self, task_uuid: str) -> None:
        """
        Attaches ANY.RUN task html report to the OpenCTI entity

        :param task_uuid: ANY.RUN task uuid
        """
        self._helper.api.stix_cyber_observable.add_file(
            id=self._opencti_entity.get("id"),
            file_name="anyrun_sandbox_report.html",
            data=self._anyrun.get_report(task_uuid),
            mime_type="text/html",
        )

    @staticmethod
    def _get_external_reference(task_uuid: str) -> list:
        """
        Creates external reference and attaches it to the OpenCTI entity

        :param task_uuid: ANY.RUN task uuid
        :return: External reference ID
        """
        return [
            stix2.ExternalReference(
                source_name=f"ANY.RUN analysis {task_uuid}",
                url=f"https://app.any.run/tasks/{task_uuid}",
                description="ANY.RUN related analysis URL",
            )
        ]

    # Start the main loop
    def mainloop(self):
        self._helper.listen(self._process_message)


if __name__ == "__main__":
    opencti_helper = OpenCTIConnectorHelper(config)
    anyrun_connector = AnyRunSandbox(opencti_helper)
    opencti = OpenCTI(opencti_helper, anyrun_connector)

    opencti.mainloop()
