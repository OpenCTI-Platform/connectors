import logging
from datetime import datetime
from stix2 import MarkingDefinition, Identity
from pycti import OpenCTIConnectorHelper, Identity as pycti_identity
import magic
from .utils import datetime_to_string, string_to_datetime, note_timestamp_to_datetime, dict_to_markdown, check_ip_address, from_list_to_csv, get_stix_id_precedence

LOGGER = logging.getLogger(__name__)

class ShadowServerStixTransformation:
    def __init__(self, marking_refs: MarkingDefinition, report_list: list, report: dict, api_helper: OpenCTIConnectorHelper, labels: list = ['ShadowServer']):
        self.helper = api_helper
        self.validate_inputs(marking_refs, report_list, report)
        self.type = report.get("type", None)
        self.url = report.get("url", None)
        self.report = report
        self.report_list = report_list
        self.labels = labels
        self.stix_objects = []
        self.object_refs = []
        self.published = self.get_published_date(report_list)
        self.marking_refs = [marking_refs] if isinstance(marking_refs, MarkingDefinition) else []
        self.create_stix_objects()

    def create_stix_objects(self):
        """Creates STIX objects in OpenCTI."""
        self.default_labels_id = self.create_labels(self.labels)
        self.create_author()
        self.create_external_reference()
        # self.create_report()

    def handle_stix_object_creation(self, key:str, create_method, element:dict, labels:list = []):
        value = element.get(key)
        if value:
            self.helper.log_debug(f"Creating {key} STIX object: {value}")
            stix_object = create_method(value)
        else:
            stix_object = None
        if stix_object and isinstance(stix_object, dict):
            self.object_refs.append(stix_object.get('id'))
            return stix_object.get('id')
        else:
            LOGGER.debug(f"{key} is empty, {type(stix_object)}")

    def validate_inputs(self, marking_refs, report_list, report):
        self.helper.log_debug("Validating inputs.")
        if not isinstance(marking_refs, MarkingDefinition):
            raise ValueError(f"Invalid marking references: {marking_refs}")
        if not isinstance(report_list, list) or not report_list:
            raise ValueError("Report list must be a non-empty list")
        if not isinstance(report, dict):
            raise ValueError("Report must be a dictionary")

    def get_published_date(self, report_list):
        self.helper.log_debug(f"Getting published date.")
        try:
            if report_list and isinstance(report_list[0], dict) and report_list[0].get("timestamp"):
                return datetime_to_string(string_to_datetime(report_list[0].get("timestamp")))
        except Exception as e:
            LOGGER.error(f"Error parsing published date: {e}")
        return datetime_to_string(datetime.now())
        
    def get_stix_objects(self):
        return self.stix_objects
    
    def create_external_reference(self):
        self.helper.log_debug(f"Creating external reference: {self.url}")
        kwargs = {
            "source_name": "source",
            "description": "ShadowServer Report",
            "url": f"{self.url}",
        }
        external_ref = self.helper.api.external_reference.create(**kwargs)
        self.external_ref_id = external_ref.get('id')
    
    def create_opencti_case(self):
        self.helper.log_debug(f"Creating OpenCTI case: {self.report.get('id')}")
        description = str()
        for key, value in self.report.items():
            description += f"{key}: {value}\n"
        kwargs = {
            "name": f"ShadowServer Report {self.type}: {self.report.get('id')}",
            "description": description,
            "externalReferences": self.external_ref_id,
            "objectLabel": self.labels,
        }
        if isinstance(self.marking_refs, list) and len(self.marking_refs) > 0 and self.marking_refs[0].get('id'):
            kwargs.update(objectMarking=self.marking_refs[0].get('id'))
        if self.object_refs:
            kwargs.update(externalReferences=self.object_refs)
        opencti_obj = self.helper.api.case_incident.create(**kwargs)
        self.case_id = opencti_obj.get('id')
        self.object_refs.append(self.case_id)

    def create_report(self):
        self.helper.log_debug(f"Creating report: {self.report.get('id')}")
        description = []
        self.upload_opencti_artifact(self.report_list)
        for element in self.report_list:
            description.append(dict_to_markdown(element))
            self.map_to_stix(element)
        self.create_opencti_case()
        
        # TODO: Create Report? 
        # self.stix_report = Report(
        #     id=pycti_report.generate_id(name=self.report.get("id"), published=self.published),
        #     report_types=['tool'],
        #     name=f"ShadowServer Report: {self.type}",
        #     published=self.published,
        #     object_refs = self.object_refs,
        #     external_references=[self.external_ref],
        #     description='\n---\n'.join(description),
        #     created_by_ref=self.author_id.id,
        #     object_marking_refs=self.marking_refs,
        #     labels = self.labels,
        # )
        # self.stix_objects.append(
        #     self.stix_report
        # )
    
    def add_default_labels(self, stix_obj: dict):
        """Adds default labels to the specified STIX object."""
        self.helper.log_debug(f"Adding default labels: {self.default_labels_id}")
        for label_id in self.default_labels_id:
            if isinstance(label_id, str) and stix_obj.get('id'):
                if 'Stix-Domain-Object' in stix_obj.get('parent_types'):
                    self.helper.api.stix_domain_object.add_label(
                        id=stix_obj.get('id'), label_id=label_id
                    )
                elif 'Stix-Cyber-Observable' in stix_obj.get('parent_types'):
                    self.helper.api.stix_cyber_observable.add_label(
                        id=stix_obj.get('id'), label_id=label_id
                    )
                else:
                    LOGGER.error(f"Invalid STIX object type: {stix_obj.get('parent_types')}")
            else:
                LOGGER.error(f"Invalid label: {label_id}")
    
    def add_marking_definition(self, stix_obj: dict):
        """Adds marking definition to the specified STIX object."""
        self.helper.log_debug(f"Adding marking definition: {self.marking_refs}")
        for marking_def in self.marking_refs:
            if isinstance(marking_def, MarkingDefinition) and marking_def.get('id') and stix_obj.get('id'):
                if 'Stix-Domain-Object' in stix_obj.get('parent_types'):
                    self.helper.api.stix_domain_object.add_marking_definition(
                        id=stix_obj.get('id'), marking_definition_id=marking_def.get('id')
                    )
                elif 'Stix-Cyber-Observable' in stix_obj.get('parent_types'):
                    self.helper.api.stix_cyber_observable.add_marking_definition(
                        id=stix_obj.get('id'), marking_definition_id=marking_def.get('id')
                    )
                else:
                    LOGGER.error(f"Invalid STIX object type: {stix_obj.get('parent_types')}")
            else:
                LOGGER.error(f"Invalid marking definition: {marking_def}")

    def create_labels(self, labels:list):
        """Creates labels in OpenCTI."""
        self.helper.log_debug(f"Creating labels: {labels}")
        label_ids = []
        for label_str in labels:
            label = self.helper.api.label.create(value=label_str)
            if label and label.get('id'):
                self.helper.log_debug(f"Created label: {label.get('id')}")
                label_ids.append(label.get('id'))
        return label_ids

    def create_author(self):
        """Creates the author of the report."""
        self.helper.log_debug(f"Creating author: ShadowServer Connector")
        """Creates ShadowServer Author"""
        kwargs = {
            "name": "ShadowServer Connector",
            "type": "Organization",
            "description": "ShadowServer Connector",
        }
        # Create the author in OpenCTI
        opencti_obj = self.helper.api.identity.create(**kwargs)
        self.helper.log_debug(f"Created author: {opencti_obj.get('id')}")
        # Add marking definition
        self.add_marking_definition(opencti_obj)
        # Add default labels
        self.add_default_labels(opencti_obj)
        # Set the author ID
        self.author_id = opencti_obj.get('id')

    def upload_opencti_artifact(self, report_list:list):
        self.helper.log_debug(f"Uploading ShadowServer report as artifact.")
        csv_str_enc = from_list_to_csv(report_list).encode()
        mime_type = magic.from_buffer(csv_str_enc, mime=True)
        kwargs = {
            "file_name": self.report.get('file', 'default_file_name.csv'),
            "data": csv_str_enc,
            "mime_type": mime_type,
            "x_opencti_description": f"ShadowServer Report Type ({self.type}) Report ID ({self.report.get('id')})",
        }
        stix_artifact = self.helper.api.stix_cyber_observable.upload_artifact(**kwargs)

        if stix_artifact and stix_artifact.get('id'):
            self.object_refs.append(stix_artifact.get('id'))

        # Add marking definition
        self.add_marking_definition(stix_artifact)
        # Add default labels
        self.add_default_labels(stix_artifact)

    def map_to_stix(self, element):
        # Define a mapping of object types to their creation functions
        object_types = {
            'asn': self.create_asn,
            'ip': self.create_ip,
            'hostname': self.create_hostname,
            'mac_address': self.create_mac_address,
        }
        self.helper.log_debug(f"Mapping ShadowServer report to STIX.")
        observed_data_list = list()
        labels_list = list()
        labels_list.extend(self.labels)
        if element.get('tag'):
            labels_list.extend(element.get('tag').split(';'))
            for labels in labels_list:
                if isinstance(labels, str) and labels.upper().startswith('CVE'):
                    LOGGER.debug(f"Label is CVE: {labels}")
                    self.create_vulnerability(labels)
        stix_labels_list = self.create_labels(labels_list)
        self.helper.log_debug(f"Labels: {stix_labels_list}")
        # Iterate over the mapping and create STIX objects
        for object_type, create_function in object_types.items():
            stix_object_str = self.handle_stix_object_creation(object_type, create_function, element, stix_labels_list)
            if isinstance(stix_object_str, str):
                self.helper.log_debug(f"Created {object_type} STIX object: {stix_object_str}")
                observed_data_list.append(stix_object_str)
        if element.get('port') and element.get('protocol'):
            dst_ref = get_stix_id_precedence(observed_data_list)
            stix_object = self.create_network_traffic(port=element.get('port'), protocol=element.get('protocol'), dst_ref=dst_ref)
            if stix_object and isinstance(stix_object, dict):
                self.object_refs.append(stix_object.get('id'))
                observed_data_list.append(stix_object)
        if element.get('cert_serial_number'):
            stix_object = self.create_x509_certificate(element)
            if stix_object and isinstance(stix_object, dict):
                self.object_refs.append(stix_object.get('id'))
                observed_data_list.append(stix_object)
        if observed_data_list:
            first_observed=note_timestamp_to_datetime(element.get('timestamp'))
            self.create_observed_data(observables_list=observed_data_list, element=element, labels_list=stix_labels_list,first_observed=first_observed)
        else:
            self.helper.log_error(f"Unable to create observed data for element: {element}")
    def create_vulnerability(self, name: str):
        self.helper.log_debug(f"Creating vulnerability STIX object: {name}")
        opencti_obj = self.helper.api.vulnerability.create(name=name.upper())
        if opencti_obj.get('id'):
            self.object_refs.append(opencti_obj.get('id'))
            # Add marking definition
            self.add_marking_definition(opencti_obj)

    def create_asn(self, asn: int):
        self.helper.log_debug(f"Creating ASN STIX object: {asn}")
        observed_data = {
            "type": "Autonomous-System",
            "number": asn,
        }
        return self.helper.api.stix_cyber_observable.create(
            ObservedData = observed_data
        )

    def create_ip(self, ip: str):
        self.helper.log_debug(f"Creating IP STIX object: {ip}")
        if check_ip_address(ip).startswith('IPv4'):
            observable_data = {
                "type": "IPv4-Addr",
                "value": ip,
            }
        elif check_ip_address(ip).startswith('IPv6'):
            observable_data = {
                "type": "IPv6-Addr",
                "value": ip,
            }
        else:
            self.helper.log_error(f"Invalid IP address: {ip}")
            return None
        return self.helper.api.stix_cyber_observable.create(
            observableData=observable_data
        )
    
    def create_hostname(self, hostname: str):
        self.helper.log_debug(f"Creating hostname STIX object: {hostname}")
        observed_data = {
            "type": "Domain-Name",
            "value": hostname,
        }

        return self.helper.api.stix_cyber_observable.create(
            ObservedData = observed_data
        )
    
    def create_mac_address(self, mac_address: str):
        self.helper.log_debug(f"Creating MAC address STIX object: {mac_address}")
        observed_data = {
            "type": "MAC-Addr",
            "value": mac_address,
        }
        return self.helper.api.stix_cyber_observable.create(    
            ObservedData = observed_data
        )
        
    def create_network_traffic(self, port: int, protocol: str, dst_ref:str = None):
        self.helper.log_debug(f"Creating network traffic STIX object. Port: {port}, Protocol: {protocol}.")
        observed_data = {
            "type": "Network-Traffic",
            "dst_port": port,
            "protocols": [protocol],
            'dst_ref': dst_ref,
        }
        return self.helper.api.stix_cyber_observable.create(    
            ObservedData = observed_data
        )

    def create_x509_certificate(self, data: dict):
        self.helper.log_debug(f"Creating X509 certificate STIX object: {data}")
        kwargs = dict()
        # Remove unwanted characters from hashes
        hashes = {
                'SHA-1': data.get('sha1_fingerprint', None),
                'SHA-256': data.get('sha256_fingerprint', None),
                'SHA-512': data.get('sha512_fingerprint', None),
                'MD5': data.get('md5_fingerprint', None),
                # Include other hash types if available
            }
        cleaned_hashes = {k: v.replace(":", "") for k, v in hashes.items() if v is not None}
        kwargs.update(hashes=cleaned_hashes)

        # Convert timestamps to datetime
        if data.get('cert_issue_date'):
            validity_not_before = note_timestamp_to_datetime(data.get('cert_issue_date') + 'Z')
            kwargs.update(validity_not_before=validity_not_before)
        if data.get('cert_expiration_date'):
            validity_not_after = note_timestamp_to_datetime(data.get('cert_expiration_date') + 'Z')
            kwargs.update(validity_not_after=validity_not_after)

        if data.get('cert_serial_number'):
            kwargs.update(serial_number=data.get('cert_serial_number'))
        if data.get('signature_algorithm'):
            kwargs.update(signature_algorithm=data.get('signature_algorithm'))
        if data.get('issuer_common_name'):
            kwargs.update(issuer=data.get('issuer_common_name'))
        if data.get('subject_common_name'):
            kwargs.update(subject=data.get('subject_common_name'))

        observed_data = {
            "type": "X509-Certificate",
            **kwargs
        }
        
        return self.helper.api.stix_cyber_observable.create(
            ObservedData = observed_data
        )
    
    def create_observed_data(self, observables_list: list, element: dict, labels_list: list, first_observed: datetime = None, last_observed: datetime = None):
        self.helper.log_debug(f"Creating observed data STIX object: {observables_list}")
        try:
            observables = [obs for obs in observables_list if obs is not None]
            if not observables:
                return None
            
            for stix_obj_id in observables:
                # Add marking definition
                self.add_marking_definition(stix_obj_id)
                # Add labels
                for label_id in labels_list:
                    if isinstance(label_id, str) and stix_obj_id:
                        self.helper.api.stix_cyber_observable.add_label(
                            id=stix_obj_id, label_id=label_id
                        )
                    else:
                        LOGGER.error(f"Invalid label: {label_id}")

            first_observed = first_observed or datetime.utcnow()
            last_observed = last_observed or first_observed

            # Create observed data
            observed_data = {
                "objects": observables,  # Reference to the created observable
                "first_observed": first_observed.isoformat(timespec='milliseconds') + 'Z',
                "last_observed": last_observed.isoformat(timespec='milliseconds') + 'Z',
                "number_observed": len(observables),
            }

            # Create the observed data in OpenCTI
            self.helper.api.observed_data.create(**observed_data)
            
        except Exception as e:
            LOGGER.error(f"Error creating observed data: {e}")
            return None




    # def create_stix_note_from_data(self):
    #     for element in self.report_list:
    #         content = dict_to_markdown(element)
    #         abstract = f'ShadowServer {self.type} Report {element.get("timestamp")}'
    #         stix_object = Note(
    #             id = pycti_note.generate_id(abstract, content),
    #             abstract=abstract,
    #             content=content,
    #             created=note_timestamp_to_datetime(element.get("timestamp")),
    #             created_by_ref=self.author_id.id,
    #             object_refs=[self.report_id],
    #             object_marking_refs=self.marking_refs,
    #             labels=self.labels,
    #             external_references=[self.external_ref],
    #         )
    #         self.stix_objects.append(stix_object)
    #         self.object_refs.append(stix_object.id)