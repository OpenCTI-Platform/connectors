import sys
# Importing the JSON module
import json
# Importing the different stix2 modules
from stix2 import MemoryStore
from stix2 import Vulnerability
from stix2 import Bundle
from stix2 import Identity
from stix2 import ExternalReference


def convert(filename, output='output.json'):
    # Create the default author
    author = Identity(name='The MITRE Corporation', identity_class='organization')
    count = 0
    with open(filename) as json_file:
        vulnerabilities_bundle = [author]
        data = json.load(json_file)
        for cves in data['CVE_Items']:
            count += 1
            # Get the name
            name = cves['cve']['CVE_data_meta']['ID']

            # Create external references
            external_reference = ExternalReference(
                source_name='NIST NVD',
                url='https://nvd.nist.gov/vuln/detail/' + name
            )
            external_references = [external_reference]
            for reference in cves['cve']['references']['reference_data']:
                external_reference = ExternalReference(
                    source_name=reference['refsource'],
                    url=reference['url']
                )
                external_references.append(external_reference)

            # Getting the different fields
            description = cves['cve']['description']['description_data'][0]["value"]
            base_score = cves['impact']['baseMetricV3']['cvssV3']["baseScore"] if "baseMetricV3" in cves['impact'] else None
            base_severity = cves['impact']['baseMetricV3']['cvssV3']["baseSeverity"] if "baseMetricV3" in cves['impact'] else None
            attack_vector = cves['impact']['baseMetricV3']['cvssV3']["attackVector"] if "baseMetricV3" in cves['impact'] else None
            integrity_impact = cves['impact']['baseMetricV3']['cvssV3']["integrityImpact"] if "baseMetricV3" in cves['impact'] else None
            availability_impact = cves['impact']['baseMetricV3']['cvssV3']["availabilityImpact"] if "baseMetricV3" in cves['impact'] else None
            cdate = cves['publishedDate']
            mdate = cves['lastModifiedDate']

            # Creating the vulnerability with the extracted fields
            vuln = Vulnerability(
                name=name,
                created=cdate,
                modified=mdate,
                description=description,
                created_by_ref=author,
                external_references=external_references,
                custom_properties={
                    'x_opencti_base_score': base_score,
                    'x_opencti_base_severity': base_severity,
                    'x_opencti_attack_vector': attack_vector,
                    'x_opencti_integrity_impact': integrity_impact,
                    'x_opencti_availability_impact': availability_impact
                }
            )
            # Adding the vulnerability to the list of vulnerabilities
            vulnerabilities_bundle.append(vuln)
    # Creating the bundle from the list of vulnerabilities
    bundle = Bundle(vulnerabilities_bundle)
    # Creating a MemoryStore object from the bundle
    memorystore = MemoryStore(bundle)
    # Dumping this object to a file
    memorystore.save_to_file(output)

if __name__ == '__main__':
    convert(sys.argv[1], sys.argv[2])
