import itertools
import base64
import json
import stix2

from . import utils


def process(connector, report):
    report_id = report.get("report_id", report.get("reportId", None))
    report_type = report.get("report_type", report.get("reportType", None))
    report_title = report.get("title", report.get("reportTitle", None))

    if report_type not in connector.mandiant_report_types:
        connector.helper.log_debug(f"Ignoring report based on type [{report_id}][{report_type}] {report_title} ...")
        return

    connector.helper.log_info(f"Processing report [{report_id}][{report_type}] {report_title} ...")

    report_details = connector.api.report(report_id, "json")
    report_bundle = connector.api.report(report_id, mode="stix")
    report_pdf = connector.api.report(report_id, mode="pdf")

    report_bundle["objects"] = list(
        filter(
            lambda item: not item["id"].startswith("x-"), report_bundle["objects"]
        )
    )

    report = Report(
        bundle=report_bundle,
        details=report_details,
        pdf=report_pdf,
        confidence=connector.helper.connect_confidence_level,
        identity=connector.identity,
    )

    bundle = report.generate()

    if bundle is None:
        connector.helper.log_error(f"Could not process report {report_id}. Skipping ...")

    return bundle


class Report:
    def __init__(self, bundle, details, pdf, confidence, identity):
        self.bundle = bundle
        self.details = details
        self.pdf = pdf
        self.confidence = confidence
        self.identity = identity
        self.report_id = details.get("report_id", details.get("reportId", None))

    def generate(self):
        self.save_files()
        self.convert_threat_actor_to_intrusion_set()
        self.update_identities()
        self.update_country()
        self.update_report()
        self.update_intrusionset()
        self.update_vulnerability()
        self.create_note()
        self.create_relationships()
        return stix2.parse(self.bundle, allow_custom=True)

    def save_files(self):
        report = utils.retrieve(self.bundle, "type", "report")
        report["x_opencti_files"] = list()

        # Original Report Files
        bundle = json.dumps(self.bundle, indent=4)
        report["x_opencti_files"].append(
            {
                "name": f"{self.report_id}.stix.original.txt",  # FIXME: did not manage to import with .json extension
                "data": base64.b64encode(bundle.encode("utf-8")).decode("utf-8"),
                "mime_type": "text/plain",
            }
        )

        details = json.dumps(self.details, indent=4)
        report["x_opencti_files"].append(
            {
                "name": f"{self.report_id}.details.original.txt",  # FIXME: did not manage to import with .json extension
                "data": base64.b64encode(details.encode("utf-8")).decode("utf-8"),
                "mime_type": "text/plain",
            }
        )

        if self.pdf:
            report["x_opencti_files"].append(
                {
                    "name": f"{self.report_id}.pdf",
                    "data": base64.b64encode(self.pdf).decode("utf-8"),
                    "mime_type": "application/pdf",
                }
            )

        # HTML Files from specific report details fields
        # FIXME: create a condition
        if "executive_summary" in self.details:
            report["x_opencti_files"].append(
                {
                    "name": f"{self.report_id}.summary.html",
                    "data": base64.b64encode(self.details["executive_summary"].encode("utf-8")).decode("utf-8"),
                    "mime_type": "text/html",
                }
            )

        if "threat_detail" in self.details:
            report["x_opencti_files"].append(
                {
                    "name": f"{self.report_id}.threat-detail.html",
                    "data": base64.b64encode(self.details["threat_detail"].encode("utf-8")).decode("utf-8"),
                    "mime_type": "text/html",
                }
            )

    def update_intrusionset(self):
        report = utils.retrieve(self.bundle, "type", "report")
        for intrusion_set in utils.retrieve_all(self.bundle, "type", "intrusion-set"):
            # Goals
            # FIXME: the goals are being inserted in double (tags?)
            intrusion_set["goals"] = report["x_mandiant_com_metadata"].get("intended_effects", [])

            # Motivations
            # FIXME: requires a mapping
            motivations = report["x_mandiant_com_metadata"].get("motivations", [])
            num_items = len(motivations)

            if num_items > 0:
                intrusion_set["primary_motivation"] = motivations[0]

            if num_items > 1:
                intrusion_set["secondary_motivations"] = motivations[1:]

    def update_vulnerability(self):
        report = utils.retrieve(self.bundle, "type", "report")

        risk_rating = None
        if "x_mandiant_com_medata" in report and "risk_rating" in report["x_mandiant_com_medata"]:
            risk_rating = report["x_mandiant_com_medata"]["risk_rating"]

        for vulnerability in utils.retrieve_all(self.bundle, "type", "vulnerability"):
            for score_item in vulnerability["x_mandiant_com_vulnerability_score"]:
                if "cvss_version" in score_item.keys():
                    vulnerability["x_opencti_base_score"] = score_item["base_metrics"]["base_score"]
            if risk_rating:
                vulnerability["x_opencti_base_severity"] = risk_rating

    def update_report(self):
        report = utils.retrieve(self.bundle, "type", "report")
        report["confidence"] = self.confidence
        report["created_by_ref"] = self.identity["standard_id"]

    def create_note(self):
        # Report Analysis Note
        report = utils.retrieve(self.bundle, "type", "report")

        del report["x_mandiant_com_tracking_info"]
        del report["x_mandiant_com_metadata"]["report_type"]
        del report["x_mandiant_com_metadata"]["subscriptions"]
        del report["x_mandiant_com_additional_description_sections"]["analysis"]

        data = {}

        # Collect custom mandiant section data
        for section in report.keys():
            if not section.startswith("x_mandiant"):
                continue

            if type(report[section]) == str:
                title = " ".join(section.replace("x_mandiant_com_", "").split("_")).title()
                data[title] = [report[section]]
                continue

            for key, values in report[section].items():
                title = " ".join(key.split("_")).title()
                if type(values) == str:
                    data[title] = [values]
                else:
                    data[title] = values

        # Collect tags data too and merge them in previous sections collection
        for key, values in self.details.get("tags", {}).items():
            name = " ".join(key.split("_")).title()
            if type(values[0]) == dict:
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

        text = ""
        for key, values in data.items():
            text += f"\n\n### {key}\n"
            text += "* " + "\n* ".join(set(values))

        if text == "":
            return

        note = utils.generate_note(
            {
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

    def convert_threat_actor_to_intrusion_set(self):
        for item in utils.retrieve_all(self.bundle, "type", "threat-actor"):
            item["type"] = "intrusion-set"
            item["id"] = item.get("id").replace("threat-actor", "intrusion-set")

        for rel in utils.retrieve_all(self.bundle, "type", "relationship"):
            rel["source_ref"] = rel.get("source_ref").replace("threat-actor", "intrusion-set")
            rel["target_ref"] = rel.get("target_ref").replace("threat-actor", "intrusion-set")

            if (
                rel["relationship_type"] == "located-at"
                and rel["source_ref"].startswith("intrusion-set")
                and rel["target_ref"].startswith("location")
            ):
                rel["relationship_type"] = "originates-from"

        report = utils.retrieve(self.bundle, "type", "report")
        report["object_refs"] = [
            reference.replace("threat-actor", "intrusion-set") for reference in report.get("object_refs", [])
        ]

    def _get_objects_from_tags(self, section):
        tags = self.details["tags"].get(section, [])

        for tag in tags:
            for item in self.bundle.get("objects"):
                if tag == item.get("name"):
                    yield item

    def create_relationships(self):
        # Get related objects
        identities = list(utils.retrieve_all(self.bundle, "type", "identity"))
        malwares = list(utils.retrieve_all(self.bundle, "type", "malware"))
        intrusion_sets = list(utils.retrieve_all(self.bundle, "type", "intrusion-set"))
        vulnerabilities = list(utils.retrieve_all(self.bundle, "type", "vulnerabilities"))
        softwares = list(utils.retrieve_all(self.bundle, "type", "softwares"))
        course_actions = list(utils.retrieve_all(self.bundle, "type", "course-of-action"))
        attack_patterns = list(utils.retrieve_all(self.bundle, "type", "attack-pattern"))
        indicators = list(utils.retrieve_all(self.bundle, "type", "indicator"))
        ipv4_addresses = list(utils.retrieve_all(self.bundle, "type", "ipv4"))
        ipv6_addresses = list(utils.retrieve_all(self.bundle, "type", "ipv6"))
        domain_names = list(utils.retrieve_all(self.bundle, "type", "domain-name"))
        urls = list(utils.retrieve_all(self.bundle, "type", "url"))
        files = list(utils.retrieve_all(self.bundle, "type", "file"))

        sectors = [identity for identity in identities if identity["identity_class"] == "class"]

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

        definitions = [
            {"type": "originates-from", "sources": malwares + intrusion_sets, "destinations": source_geographies},
            {"type": "targets", "sources": malwares + intrusion_sets, "destinations": target_geographies + affected_industries},
            {"type": "targets", "sources": malwares, "destinations": affected_systems},
            {"type": "targets", "sources": intrusion_sets, "destinations": sectors},
            {"type": "compromises", "sources": intrusion_sets, "destinations": affected_systems},
            {"type": "uses", "sources": intrusion_sets, "destinations": malwares},
            {"type": "related-to", "sources": vulnerabilities, "destinations": softwares},
            {"type": "mitigates", "sources": course_actions, "destinations": vulnerabilities},
            {"type": "targets", "sources": attack_patterns, "destinations": vulnerabilities},
            {
                "type": "communicates-with",
                "sources": malwares,
                "destinations": ipv4_addresses + ipv6_addresses + domain_names + urls},
            {"type": "drops", "sources": malwares, "destinations": files},
            {"type": "indicates", "sources": indicators, "destinations": malwares},
            {"type": "targets", "sources": intrusion_sets, "destinations": sectors},
        ]

        # Create relationships
        relationships = []

        for definition in definitions:

            sources = definition["sources"]
            destinations = definition["destinations"]

            for item in itertools.product(sources, destinations):

                relationship = stix2.Relationship(
                    source_ref=item[0]["id"],
                    target_ref=item[1]["id"],
                    relationship_type=definition["type"],
                )

                relationships.append(relationship)

        # Remove me
        if len(relationships) == 0:
            self.bundle["objects"] = []
            return
        # end

        self.bundle["objects"] += relationships


# class NewsAnalysisReport(Report):
#     pass

#     def _process(self, item):
#         note = create_isight_note(report_details, identity, confidence)
#         if note:
#             item["object_refs"].append(note.id)

#         if "description" not in item:
#             item["description"] = parse_description(report_details)

#         if "external_references" not in item:
#             item["external_references"] = list()

#         outlet = report_details.get("outlet")
#         storyLink = report_details.get("storyLink")

#         if outlet and storyLink:
#             item["external_references"].append({
#                 "source_name": outlet,
#                 "url": storyLink,
#             })

#     def create_isight_note(report_details, identity, confidence):
#         content = utils.cleanhtml(report_details.get("isightComment"))

#         if not content:
#             return None

#         return stix2.Note(
#             id=Note.generate_id(),
#             abstract="Analysis",
#             created_by_ref=identity,
#             content=content,
#             note_types=["analysis"],
#             confidence=confidence,
#             object_refs=[item.get("id")],
#             object_marking_refs=item["object_marking_refs"],
#         )

#     def parse_description(report_details):
#         media = report_details.get("fromMedia", "")
#         return re.sub("<[^<]+?>", "", media)
