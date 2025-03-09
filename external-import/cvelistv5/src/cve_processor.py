# Transform CVE_RECORD (v5.1) into STIX (v2.x) format

#from stix2 import Vulnerability, Software, Relationship
import os
import json
import stix2
from pycti import (
    Identity,
    Infrastructure,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Vulnerability,
    Note,
    get_config_variable,
)

class CVEProcessor:
    def __init__(self, helper: OpenCTIConnectorHelper, api):
        self.helper = helper
        self.api = api
        self.author = self._create_author()


    def process_cve_file(self, file_path):
        with open(file_path, 'r') as file:
            cve_data = json.load(file)

        # Convert CVE to STIX
        stix_objects = self.cve_record_to_stix(cve_data)

        # Import STIX objects to OpenCTI
        bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(bundle)

        self.helper.log_info(f"Processed CVE: {cve_data['cveMetadata']['cveId']}")


    def cve_record_to_stix(self, cve_data):
        stix_objects = [self.author]
        
        # Extract basic CVE information
        cve_id = cve_data['cveMetadata']['cveId']
        published_date = cve_data['cveMetadata']['datePublished']
        modified_date = cve_data['cveMetadata']['dateUpdated']
        cna = cve_data['containers']['cna']     # CVE Numbering Authority (CNA)
        description = cna['descriptions'][0]['value']
        metric = cna['metrics'][0]
        CVSS_metric = metric.get('cvssV4_0') if 'cvssV4_0' in  metric else metric.get('cvssV3_1')
        
        external_references = []
        for reference in cna["references"]:
            if 'name' in reference:
                source_name = reference['name']
            elif 'tags' in reference:
                source_name = reference['tags'][0]
            else:
                source_name = reference['url']
            external_references.append(
                stix2.ExternalReference(
                    source_name=source_name, 
                    url=reference["url"]
                )
            )
            
        # Create Vulnerability object
        vulnerability = stix2.Vulnerability(
            id=Vulnerability.generate_id(cve_id),
            name=cve_id,
            description=description,
            created=published_date,
            modified=modified_date,
            external_references=external_references,
            created_by_ref=self.author,
            custom_properties={
                    "x_opencti_cvss_base_score": CVSS_metric['baseScore'],
                    "x_opencti_cvss_base_severity": CVSS_metric['baseSeverity'],
                    "x_opencti_cvss_attack_vector" : CVSS_metric['attackVector'],
                    "x_opencti_cvss_integrity_impact" : CVSS_metric['integrityImpact'],
                    "x_opencti_cvss_availability_impact" : CVSS_metric['availabilityImpact'],
                    "x_opencti_cvss_confidentiality_impact" : CVSS_metric['confidentialityImpact']
                }
        )
        stix_objects.append(vulnerability)
        
        
        # Loop through each product and version and see if it's affected, (1) add a software, (2) add a relationship
        for product in cna['affected']:
            product_name = product['product']
            vendor = product['vendor']
            
            # Software vendor
            software_vendor = stix2.Identity(
                id=Identity.generate_id(vendor, "organization"),
                name=f"{vendor}",
                identity_class="organization",
                description="Software Vendor",
                created_by_ref=self.author,
                custom_properties={
                    "x_opencti_organization_type": "vendor",
                },
            )
            stix_objects.append(software_vendor)
            
            if 'cpes' in product:   # Handle cpe entries
                for cpe in product['cpes']:
                    version_value = f"{cpe.split(':')[5]}-{cpe.split(':')[6]}" if cpe.split(':')[6] not in ["-", "*"] else cpe.split(':')[5]
                    stix_objects += self.create_affected_software(product_name, version_value, software_vendor, vulnerability)     
            
            else:                   # Handle version entries
                for version in product['versions']:  
                    if version['status'] == "affected":
                        version_value = f"<{version.get('lessThan')}" if 'lessThan' in version else version['version']
                        stix_objects += self.create_affected_software(product_name, version_value, software_vendor, vulnerability)
        
        # process workarounds,Solutions,exploits,configuration into related notes
        if "workarounds" in cna:
            stix_objects += self.create_notes(vulnerability, 'workaround', cna['workarounds'])
        if "solutions" in cna:
            stix_objects += self.create_notes(vulnerability, 'solution', cna['solutions'])
        if "exploits" in cna:
            stix_objects += self.create_notes(vulnerability, 'exploit', cna['exploits'])
        if "configurations" in cna:
            stix_objects += self.create_notes(vulnerability, 'configuration', cna['configurations'])
                          
        return stix_objects
    
    
    def create_affected_software(self, name: str, version: str, vendor: stix2.Identity, vulnerability: stix2.Vulnerability):
        stix_objects = []
        
        software = stix2.Software(
            name=f"{name} {version}",
            version=version,
            vendor=vendor.name,
            created_by_ref=self.author,
        )
        stix_objects.append(software)
        
        vulnerability_relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "affectes", vulnerability.id, software.id
            ),
            relationship_type='affects',
            source_ref=vulnerability.id,
            target_ref=software.id,
            created_by_ref=self.author,
        )
        stix_objects.append(vulnerability_relationship)
        
        software_vendor_relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to", software.id, vendor.id
            ),
            relationship_type="related-to",
            description="This software is maintained by",
            source_ref=f"{software.id}",
            target_ref=f"{vendor.id}",
            created_by_ref=self.author,
        )
        stix_objects.append(software_vendor_relationship)
        
        return stix_objects

    def create_related_notes(self, section_name, entries,vulnerability: stix2.Vulnerability):
        stix_objects = []
        for entry in entries:
            note = stix2.Note(
                id=Note.generate_id(content=entry['value']),
                abstract=f"{vulnerability.name} - {section_name}",
                content=entry['value'],
                object_refs=[vulnerability.id],
                labels=[section_name],
                created_by_ref=self.author,
            )
            stix_objects.append(note)
            
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(f"has-{section_name}", vulnerability.id, note.id),
                relationship_type=f"has-{section_name}",
                source_ref=vulnerability.id,
                target_ref=note.id,
                created_by_ref=self.author,
            )
            stix_objects.append(relationship)
        return stix_objects
    
    @staticmethod
    def _create_author():
        """
        :return: CVEs' default author
        """
        return stix2.Identity(
            id=Identity.generate_id("The CVE Program", "organization"),
            name="The CVE Program",
            identity_class="organization",
        )