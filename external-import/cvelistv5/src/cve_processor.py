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


    def process_cve_file(self, file_path, work_id):
        with open(file_path, 'r') as file:
            cve_data = json.load(file)
        self.helper.log_debug(f"File content {json.dumps(cve_data)}")
        
        # Check if CVE is rejected
        state = cve_data['cveMetadata']['state']
        if state == "REJECTED":
            return
        
        # Convert CVE to STIX
        stix_objects = self.cve_record_to_stix(cve_data)
        self.helper.log_debug(f"CVE converted to STIX objects")

        # Import STIX objects to OpenCTI
        bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(bundle, work_id=work_id)

        self.helper.log_info(f"Processed CVE: {cve_data['cveMetadata']['cveId']}")


    def cve_record_to_stix(self, cve_data):
        stix_objects = [self.author]
        
        # Extract basic CVE information
        cve_id = cve_data['cveMetadata']['cveId']
        published_date = cve_data['cveMetadata']['datePublished'] if cve_data['cveMetadata']['datePublished'][-1] == "Z" else f"{cve_data['cveMetadata']['datePublished']}Z"
        modified_date = cve_data['cveMetadata']['dateUpdated']
        cna = cve_data['containers']['cna']     # CVE Numbering Authority (CNA)
        description = cna['descriptions'][0]['value']
        metric=''
        if 'metrics' in cna:
            for element in cna['metrics']:
                if ('cvssV4_0' in element or 'cvssV3_1' in element):
                    metric = element
        if not bool(metric) and 'adp' in cve_data['containers']:
            if 'metrics' in cve_data['containers']['adp'][0]:
                for element in cve_data['containers']['adp'][0]['metrics']:
                    if ('cvssV4_0' in element or 'cvssV3_1' in element):
                        metric = element
        if bool(metric):
            self.helper.log_debug(f"CVSS metric raw content {metric}")
            CVSS_metric = metric.get('cvssV4_0') if 'cvssV4_0' in  metric else metric.get('cvssV3_1')
            x_opencti_cvss = {
                    "x_opencti_cvss_base_score": CVSS_metric.get('baseScore', ''),
                    "x_opencti_cvss_base_severity": CVSS_metric.get('baseSeverity', ''),
                    "x_opencti_cvss_attack_vector" : CVSS_metric.get('attackVector', ''),
                    "x_opencti_cvss_integrity_impact" : CVSS_metric.get('integrityImpact', ''),
                    "x_opencti_cvss_availability_impact" : CVSS_metric.get('availabilityImpact', ''),
                    "x_opencti_cvss_confidentiality_impact" : CVSS_metric.get('confidentialityImpact', '')
                }
        else: x_opencti_cvss = {}
        
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
            custom_properties=x_opencti_cvss
        )
        stix_objects.append(vulnerability)
        
        
        # Loop through each product and version and see if it's affected, (1) add a software, (2) add a relationship
        for product in cna['affected']:
            product_name = product.get('product') if 'product' in  product else product.get('packageName')
            vendor = product.get('vendor', 'UNKNOWN')
            
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
                    self.helper.log_debug(f"CPE: {cpe}")
                    if len(cpe.split(':')) == 5:
                        version_value = f"{cpe.split(':')[4]}"
                    elif len(cpe.split(':')) > 5:
                        version_value = f"{cpe.split(':')[5]}-{cpe.split(':')[6]}" if cpe.split(':')[6] not in ["-", "*", ""] else cpe.split(':')[5]
                    else: version_value = ''
                    stix_objects += self.create_affected_software(product_name, version_value, software_vendor, vulnerability, cpe)     
            
            else:                   # Handle version entries
                for version in product['versions']:  
                    if version['status'] == "affected":
                        version_value = f"<{version.get('lessThan')}" if 'lessThan' in version else f"<={version.get('lessThanOrEqual')}" if 'lessThanOrEqual' in version else version['version']
                        stix_objects += self.create_affected_software(f"{product_name} {version['version']}", version_value, software_vendor, vulnerability)
        
        # process workarounds,Solutions,exploits,configuration into related notes
        if "workarounds" in cna:
            stix_objects += self.create_related_notes('workaround', cna['workarounds'], vulnerability)
        if "solutions" in cna:
            stix_objects += self.create_related_notes('solution', cna['solutions'], vulnerability)
        if "exploits" in cna:
            stix_objects += self.create_related_notes('exploit', cna['exploits'], vulnerability)
        if "configurations" in cna:
            stix_objects += self.create_related_notes('configuration', cna['configurations'], vulnerability)
                          
        return stix_objects
    
    
    def create_affected_software(self, name: str, version: str, vendor: stix2.Identity, vulnerability: stix2.Vulnerability, cpe = ''):
        stix_objects = []
        
        software = stix2.Software(
            name=name,
            version=version,
            vendor=vendor.name,
            cpe=cpe,
            custom_properties = {
                "x_opencti_created_by_ref": self.author.id
            }
        )
        stix_objects.append(software)
        
        vulnerability_relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "has", software.id, vulnerability.id
            ),
            relationship_type='has',
            source_ref=software.id,
            target_ref=vulnerability.id,
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

    def create_related_notes(self, section_name:str, entries:list, vulnerability: stix2.Vulnerability):
        stix_objects = []
        self.helper.log_debug(f"Related note content: {json.dumps(entries)}")
        for entry in entries:
            note = stix2.Note(
                id=Note.generate_id(created=None, content=entry['value']),
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