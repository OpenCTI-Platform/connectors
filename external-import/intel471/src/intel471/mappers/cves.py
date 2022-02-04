from stix2 import Bundle, Vulnerability, ExternalReference

from .common import BaseMapper, StixMapper, generate_id, author_identity


@StixMapper.register("cves", lambda x: "cveReportsTotalCount" in x)
@StixMapper.register("cve", lambda x: "cve_report" in x.get("data", {}))
class CveMapper(BaseMapper):

    def map(self, source: dict) -> Bundle:
        container = {}
        items = source.get("cveReports") or [] if "cveReportsTotalCount" in source else [source]
        for item in items:
            uid = item["uid"]
            name = item["data"]["cve_report"]["name"]
            summary = "{}\n{}".format(item["data"]["cve_report"]["summary"],
                                      item["data"]["cve_report"]["underground_activity_summary"])
            cvss3_score = (item["data"]["cve_report"].get("cvss_score") or {}).get("v3")
            external_references = []
            for link_type, key in (("Titan URL", "titan_links"), ("PoC", "poc_links"), ("Patch", "patch_links")):
                for link in item["data"]["cve_report"].get(key) or []:
                    external_reference = ExternalReference(
                        source_name=f"[{link_type}] {link['title']}",
                        url=link['url']
                    )
                    external_references.append(external_reference)

            custom_properties = {"x_intel471_com_uid": uid}
            if cvss3_score:
                custom_properties["x_opencti_base_score"] = cvss3_score
            vulnerability = Vulnerability(id=generate_id(Vulnerability, name=name.strip().lower()),
                                          name=name,
                                          description=summary,
                                          created_by_ref=author_identity,
                                          external_references=external_references,
                                          custom_properties=custom_properties)
            container[vulnerability.id] = vulnerability
            container[author_identity.id] = author_identity
        if container:
            bundle = Bundle(*container.values(), allow_custom=True)
            return bundle
