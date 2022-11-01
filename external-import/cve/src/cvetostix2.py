# coding: utf-8

import datetime
# Importing the JSON module
import json
import sys

# Umporting the STIX module
import stix2
from pycti import Identity, Vulnerability


def convert(filename, output="output.json"):
    # Create the default author
    author = stix2.Identity(
        id=Identity.generate_id("The MITRE Corporation", "organization"),
        name="The MITRE Corporation",
        identity_class="organization",
    )
    count = 0
    with open(filename) as json_file:
        vulnerabilities_bundle = [author]
        data = json.load(json_file)
        for cves in data["CVE_Items"]:
            count += 1
            # Get the name
            name = cves["cve"]["CVE_data_meta"]["ID"]

            # Create external references
            external_reference = stix2.ExternalReference(
                source_name="NIST NVD", url="https://nvd.nist.gov/vuln/detail/" + name
            )
            external_references = [external_reference]
            if (
                "references" in cves["cve"]
                and "reference_data" in cves["cve"]["references"]
            ):
                for reference in cves["cve"]["references"]["reference_data"]:
                    external_reference = stix2.ExternalReference(
                        source_name=reference["refsource"], url=reference["url"]
                    )
                    external_references.append(external_reference)

            # Getting the different fields
            description = cves["cve"]["description"]["description_data"][0]["value"]
            base_score = (
                cves["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                if "baseMetricV3" in cves["impact"]
                else None
            )
            base_severity = (
                cves["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                if "baseMetricV3" in cves["impact"]
                else None
            )
            attack_vector = (
                cves["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]
                if "baseMetricV3" in cves["impact"]
                else None
            )
            integrity_impact = (
                cves["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"]
                if "baseMetricV3" in cves["impact"]
                else None
            )
            availability_impact = (
                cves["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"]
                if "baseMetricV3" in cves["impact"]
                else None
            )
            confidentiality_impact = (
                cves["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"]
                if "baseMetricV3" in cves["impact"]
                else None
            )
            cdate = datetime.datetime.strptime(cves["publishedDate"], "%Y-%m-%dT%H:%MZ")
            mdate = datetime.datetime.strptime(
                cves["lastModifiedDate"], "%Y-%m-%dT%H:%MZ"
            )

            # Creating the vulnerability with the extracted fields
            vuln = stix2.Vulnerability(
                id=Vulnerability.generate_id(name),
                name=name,
                created=cdate,
                modified=mdate,
                description=description,
                created_by_ref=author,
                external_references=external_references,
                custom_properties={
                    "x_opencti_base_score": base_score,
                    "x_opencti_base_severity": base_severity,
                    "x_opencti_attack_vector": attack_vector,
                    "x_opencti_integrity_impact": integrity_impact,
                    "x_opencti_availability_impact": availability_impact,
                    "x_opencti_confidentiality_impact": confidentiality_impact,
                },
            )
            # Adding the vulnerability to the list of vulnerabilities
            vulnerabilities_bundle.append(vuln)
    # Creating the bundle from the list of vulnerabilities
    bundle = stix2.Bundle(vulnerabilities_bundle, allow_custom=True)
    bundle_json = bundle.serialize()

    # Write to file
    with open(output, "w") as f:
        f.write(bundle_json)


if __name__ == "__main__":
    convert(sys.argv[1], sys.argv[2])
