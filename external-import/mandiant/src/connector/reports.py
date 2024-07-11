import base64
import itertools
import re

import stix2
from pycti import Note

from . import utils
from .common import create_stix_relationship


def process(connector, report):
    report_id = report.get("report_id", report.get("reportId", None))
    try:
        report_type = report.get("report_type", report.get("reportType", None))
        report_title = report.get("title", report.get("reportTitle", None))
        if report_type not in connector.mandiant_report_types:
            connector.helper.connector_logger.debug(
                "Ignoring report",
                {
                    "report_id": report_id,
                    "report_type": report_type,
                    "report_title": report_title,
                },
            )
            return
        connector.helper.connector_logger.info(
            "Processing report",
            {
                "report_id": report_id,
                "report_type": report_type,
                "report_title": report_title,
            },
        )
        report_details = connector.api.report(report_id, "json")
        report_bundle = connector.api.report(report_id, mode="stix")
        report_pdf = connector.api.report(report_id, mode="pdf")
        bundle_objects = report_bundle["objects"]
        report_bundle["objects"] = list(
            filter(lambda item: not item["id"].startswith("x-"), bundle_objects)
        )
        report = Report(
            bundle=report_bundle,
            details=report_details,
            pdf=report_pdf,
            connector=connector,
            report_type=report_type,
            report_link=report["report_link"],
        )
        bundle = report.generate()
    except Exception:
        connector.helper.connector_logger.error(
            "Could not process Report", {"report_id": report_id}
        )
        return None
    return bundle


class Report:
    def __init__(
        self,
        bundle,
        details,
        pdf,
        connector,
        report_type,
        report_link,
    ):
        self.bundle = bundle
        self.connector = connector
        self.details = details
        self.pdf = pdf
        self.confidence = connector.helper.connect_confidence_level
        self.identity = connector.identity
        self.report_id = details.get("report_id", details.get("reportId", None))
        self.report_type = connector.mandiant_report_types[report_type]
        self.report_link = report_link
        self.create_notes = connector.mandiant_create_notes

    def generate(self):
        self.save_files()
        self.convert_threat_actor_to_intrusion_set()
        self.update_identities()
        self.update_country()
        self.update_report()
        self.update_vulnerability()
        self.create_relationships()
        if self.create_notes:
            self.create_note()
        return stix2.parse(self.bundle, allow_custom=True)

    def save_files(self):
        report = utils.retrieve(self.bundle, "type", "report")
        report["x_opencti_files"] = list()

        # FIXME: did not manage to import with .json extension
        # bundle = json.dumps(self.bundle, indent=4)
        # report["x_opencti_files"].append(
        #     {
        #         "name": f"{self.report_id}.stix.original.txt",
        #         "data": base64.b64encode(bundle.encode("utf-8")).decode("utf-8"),
        #         "mime_type": "text/plain",
        #     }
        # )

        # FIXME: did not manage to import with .json extension
        # details = json.dumps(self.details, indent=4)
        # report["x_opencti_files"].append(
        #     {
        #         "name": f"{self.report_id}.details.original.txt",
        #         "data": base64.b64encode(details.encode("utf-8")).decode("utf-8"),
        #         "mime_type": "text/plain",
        #     }
        # )

        if self.pdf:
            report["x_opencti_files"].append(
                {
                    "name": f"{self.report_id}.pdf",
                    "data": base64.b64encode(self.pdf).decode("utf-8"),
                    "mime_type": "application/pdf",
                    "no_trigger_import": True,
                }
            )

        # HTML Files from specific report details fields
        # FIXME: create a condition
        # if "executive_summary" in self.details:
        #     report["x_opencti_files"].append(
        #         {
        #             "name": f"{self.report_id}.summary.html",
        #             "data": base64.b64encode(self.details["executive_summary"].encode("utf-8")).decode("utf-8"),
        #             "mime_type": "text/html",
        #         }
        #     )
        # if "threat_detail" in self.details:
        #     report["x_opencti_files"].append(
        #         {
        #             "name": f"{self.report_id}.threat-detail.html",
        #             "data": base64.b64encode(self.details["threat_detail"].encode("utf-8")).decode("utf-8"),
        #             "mime_type": "text/html",
        #         }
        #     )

    def update_vulnerability(self):
        report = utils.retrieve(self.bundle, "type", "report")

        risk_rating = None
        if (
            "x_mandiant_com_medata" in report
            and "risk_rating" in report["x_mandiant_com_medata"]
        ):
            risk_rating = report["x_mandiant_com_medata"]["risk_rating"]

        for vulnerability in utils.retrieve_all(self.bundle, "type", "vulnerability"):
            for score_item in vulnerability["x_mandiant_com_vulnerability_score"]:
                if "cvss_version" in score_item.keys():
                    base_score = score_item["base_metrics"]["base_score"]
                    vulnerability["x_opencti_base_score"] = (
                        int(base_score) if base_score is not None else base_score
                    )
            if risk_rating:
                vulnerability["x_opencti_base_severity"] = risk_rating

    @staticmethod
    def _parse_description(description):
        media = description
        return re.sub("<[^<]+?>", "", media)

    def update_report(self):
        report = utils.retrieve(self.bundle, "type", "report")
        report["confidence"] = self.confidence
        report["created_by_ref"] = self.identity["standard_id"]
        report["report_types"] = [self.report_type]
        report["object_refs"] = list(
            filter(lambda ref: not ref.startswith("x-"), report["object_refs"])
        )

        if "fromMedia" in self.details and self.details["fromMedia"] is not None:
            report["description"] = self._parse_description(self.details["fromMedia"])

        # Retrieve the story link and add it into external reference
        story_link_ref = None
        if (
            "storyLink" in self.details
            and "outlet" in self.details
            and self.details["storyLink"] is not None
            and self.details["outlet"] is not None
        ):
            story_link_ref = {
                "source_name": self.details["outlet"],
                "url": self.details["storyLink"],
            }

        mandiant_refs = [{"source_name": "Mandiant", "url": self.report_link}]
        if story_link_ref is not None:
            mandiant_refs.append(story_link_ref)

        if (
            "external_references" in report
            and report["external_references"] is not None
        ):
            report["external_references"] = (
                report["external_references"] + mandiant_refs
            )
        else:
            report["external_references"] = mandiant_refs

    def create_note(self):
        # Report Analysis Note
        report = utils.retrieve(self.bundle, "type", "report")

        if "x_mandiant_com_tracking_info" in report:
            del report["x_mandiant_com_tracking_info"]
        if (
            "x_mandiant_com_metadata" in report
            and "report_type" in report["x_mandiant_com_metadata"]
        ):
            del report["x_mandiant_com_metadata"]["report_type"]
        if (
            "x_mandiant_com_metadata" in report
            and "subscriptions" in report["x_mandiant_com_metadata"]
        ):
            del report["x_mandiant_com_metadata"]["subscriptions"]
        if (
            "x_mandiant_com_additional_description_sections" in report
            and "analysis" in report["x_mandiant_com_additional_description_sections"]
        ):
            del report["x_mandiant_com_additional_description_sections"]["analysis"]

        data = {}

        # Collect custom mandiant section data
        for section in report.keys():
            if not section.startswith("x_mandiant"):
                continue

            if isinstance(report[section], str):
                title = " ".join(
                    section.replace("x_mandiant_com_", "").split("_")
                ).title()
                data[title] = [report[section]]
                continue

            for key, values in report[section].items():
                title = " ".join(key.split("_")).title()
                if isinstance(values, str):
                    data[title] = [values]
                else:
                    data[title] = values

        # Collect tags data too and merge them in previous sections collection
        for key, values in self.details.get("tags", {}).items():
            name = " ".join(key.split("_")).title()
            if isinstance(values[0], dict):
                continue

            if name in data:
                data[name] += values
            else:
                data[name] = values

        # Mandiant typo "infomations"
        if "Targeted Infomations" in data and "Targeted Informations" in data:
            del data["Targeted Infomations"]

        # Mandiant typo "it"
        if "Affected Systems" in data and "Affected It Systems" in data:
            del data["Affected It Systems"]

        text = f"Report ID: {self.report_id}\n"
        for key, values in data.items():
            text += f"\n\n### {key}\n"
            text += "* " + "\n* ".join(set(values))

        if (
            "isightComment" in self.details
            and self.details["isightComment"] is not None
        ):
            content = utils.cleanhtml(self.details["isightComment"])
            text += f"\n**Analyst Comment** \n{content}"

        if text == "":
            return

        note = utils.generate_note(
            {
                "id": Note.generate_id(report["created"], text),
                "abstract": "Analysis",
                "content": text,
                "confidence": self.confidence,
                "created_by_ref": self.identity["standard_id"],
                "object_refs": [report.get("id")],
                "object_marking_refs": report["object_marking_refs"],
                "note_types": ["analysis", "external"],
            }
        )

        self.bundle["objects"].append(note)

    # TODO: dont know about this, it come from original code
    def update_identities(self):
        for identity in utils.retrieve_all(self.bundle, "type", "identity"):
            if identity.get("identity_class") != "organization":
                identity.update({"identity_class": "class"})

    def update_country(self):
        for location in utils.retrieve_all(self.bundle, "type", "location"):
            location.update({"x_opencti_location_type": "Country"})
            if "country" not in location and "name" in location:
                location.update({"country": location["name"]})
            else:
                location.update({"country": "Unknown"})

    def convert_threat_actor_to_intrusion_set(self):
        for item in utils.retrieve_all(self.bundle, "type", "threat-actor"):
            item["type"] = "intrusion-set"
            item["id"] = item.get("id").replace("threat-actor", "intrusion-set")

        for rel in utils.retrieve_all(self.bundle, "type", "relationship"):
            rel["source_ref"] = rel.get("source_ref").replace(
                "threat-actor", "intrusion-set"
            )
            rel["target_ref"] = rel.get("target_ref").replace(
                "threat-actor", "intrusion-set"
            )

            if (
                rel["relationship_type"] == "located-at"
                and rel["source_ref"].startswith("intrusion-set")
                and rel["target_ref"].startswith("location")
            ):
                rel["relationship_type"] = "originates-from"

        report = utils.retrieve(self.bundle, "type", "report")
        report["object_refs"] = [
            reference.replace("threat-actor", "intrusion-set")
            for reference in report.get("object_refs", [])
        ]

    def _get_objects_from_tags(self, section):
        tags = self.details.get("tags", {}).get(section, [])
        for tag in tags:
            for item in self.bundle.get("objects"):
                if tag == item.get("name"):
                    yield item

    def create_relationships(self):
        # Get related objects
        identities = list(utils.retrieve_all(self.bundle, "type", "identity"))
        malwares = list(utils.retrieve_all(self.bundle, "type", "malware"))
        intrusion_sets = list(utils.retrieve_all(self.bundle, "type", "intrusion-set"))
        vulnerabilities = list(utils.retrieve_all(self.bundle, "type", "vulnerability"))
        softwares = list(utils.retrieve_all(self.bundle, "type", "software"))
        course_actions = list(
            utils.retrieve_all(self.bundle, "type", "course-of-action")
        )
        attack_patterns = list(
            utils.retrieve_all(self.bundle, "type", "attack-pattern")
        )
        indicators = list(utils.retrieve_all(self.bundle, "type", "indicator"))
        ipv4_addresses = list(utils.retrieve_all(self.bundle, "type", "ipv4-addr"))
        ipv6_addresses = list(utils.retrieve_all(self.bundle, "type", "ipv6-addr"))
        domain_names = list(utils.retrieve_all(self.bundle, "type", "domain-name"))
        urls = list(utils.retrieve_all(self.bundle, "type", "url"))
        files = list(utils.retrieve_all(self.bundle, "type", "file"))

        scos = ipv4_addresses + ipv6_addresses + domain_names + urls + files

        sectors = [
            identity for identity in identities if identity["identity_class"] == "class"
        ]

        # Get objects from tags
        source_geographies = list(self._get_objects_from_tags("source_geographies"))
        target_geographies = list(self._get_objects_from_tags("target_geographies"))
        affected_industries = list(self._get_objects_from_tags("affected_industries"))
        affected_systems = list(self._get_objects_from_tags("affected_systems"))
        # NOT NEEEDED malware_families = list(self._get_objects_from_tags("malware_families"))
        # NOT NEEEDED actors = list(self._get_objects_from_tags("actors"))
        # motivations = list(self._get_objects_from_tags("motivations"))
        # ? ttps = list(self._get_objects_from_tags("ttps"))
        # ? targeted_informations = list(self._get_objects_from_tags("targeted_informations"))
        # ? intended_effects = list(self._get_objects_from_tags("intended_effects"))

        definitions = []

        if len(intrusion_sets) > 0:
            definitions += [
                {
                    "type": "originates-from",
                    "sources": intrusion_sets,
                    "destinations": source_geographies,
                },
                {
                    "type": "targets",
                    "sources": intrusion_sets,
                    "destinations": target_geographies + affected_industries,
                },
                {
                    "type": "targets",
                    "sources": intrusion_sets,
                    "destinations": sectors,
                },
                {
                    "type": "compromises",
                    "sources": intrusion_sets,
                    "destinations": affected_systems,
                },
                {
                    "type": "uses",
                    "sources": intrusion_sets,
                    "destinations": malwares,
                },
                {
                    "type": "targets",
                    "sources": intrusion_sets,
                    "destinations": vulnerabilities,
                },
                {
                    "type": "indicates",
                    "sources": indicators,
                    "destinations": intrusion_sets,
                },
                {
                    "type": "related-to",
                    "sources": scos,
                    "destinations": intrusion_sets,
                },
            ]

        if len(malwares) > 0:
            definitions += [
                {
                    "type": "originates-from",
                    "sources": malwares,
                    "destinations": source_geographies,
                },
                {
                    "type": "targets",
                    "sources": malwares,
                    "destinations": target_geographies + affected_industries,
                },
                {
                    "type": "targets",
                    "sources": malwares,
                    "destinations": affected_systems,
                },
                {
                    "type": "communicates-with",
                    "sources": malwares,
                    "destinations": ipv4_addresses
                    + ipv6_addresses
                    + domain_names
                    + urls,
                },
                {
                    "type": "drops",
                    "sources": malwares,
                    "destinations": files,
                },
                {
                    "type": "indicates",
                    "sources": indicators,
                    "destinations": malwares,
                },
            ]

        if len(vulnerabilities) > 0:
            definitions += [
                {
                    "type": "has",
                    "sources": softwares,
                    "destinations": vulnerabilities,
                },
                {
                    "type": "mitigates",
                    "sources": course_actions,
                    "destinations": vulnerabilities,
                },
                {
                    "type": "targets",
                    "sources": attack_patterns,
                    "destinations": vulnerabilities,
                },
            ]

        # Create relationships
        relationships = []
        relationships_ids = []

        for definition in definitions:
            sources = definition["sources"]
            destinations = definition["destinations"]

            for item in itertools.product(sources, destinations):
                relationship = create_stix_relationship(
                    self.connector,
                    definition["type"],
                    item[0]["id"],
                    item[1]["id"],
                    "",
                )

                relationships.append(relationship)
                relationships_ids.append(relationship.id)

        report = utils.retrieve(self.bundle, "type", "report")
        report["object_refs"] += relationships_ids
        self.bundle["objects"] += relationships
