import base64
import ipaddress

import stix2
import validators
from pycti import (
    Channel,
    CustomObjectChannel,
    Identity,
    Incident,
    MarkingDefinition,
    StixCoreRelationship,
)


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, tlp):
        self.helper = helper
        self.author = self.create_author()
        self.tlp_marking = self._create_tlp_marking(level=tlp.lower())

    @staticmethod
    def create_author() -> stix2.Identity:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(
                name="Google Threat Intelligence", identity_class="organization"
            ),
            name="Google Threat Intelligence",
            identity_class="organization",
        )
        return author

    @staticmethod
    def _create_tlp_marking(level):
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[level]

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv6
        :param value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv4
        :param value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_domain(value: str) -> bool:
        """
        Valid domain name regex including internationalized domain name
        :param value: Value in string
        :return: A boolean
        """
        is_valid_domain = validators.domain(value)

        if is_valid_domain:
            return True
        else:
            return False

    def create_channel(self, dtm_channel: dict) -> CustomObjectChannel:
        """
        :param dtm_channel:
        :return:
        """
        channel_type = dtm_channel.get("messenger").get("name")
        channel_name = dtm_channel.get("name")
        channel_description = dtm_channel.get("channel_info").get("description")
        channel_url = dtm_channel.get("channel_url")

        formatted_channel_name = "[" + channel_type + "] - " + channel_name
        external_refs = []
        if channel_url:
            external_ref = stix2.ExternalReference(
                source_name=channel_type + " - " + channel_name, url=channel_url
            )
            external_refs.append(external_ref)
        channel = CustomObjectChannel(
            id=Channel.generate_id(name=formatted_channel_name),
            name=formatted_channel_name,
            description=channel_description,
            channel_types=[channel_type],
            external_references=external_refs,
            object_marking_refs=[self.tlp_marking.get("id")],
        )
        return channel

    @staticmethod
    def generate_incident_description(dtm_alert: dict) -> str:
        """
        :param dtm_alert:
        :return:
        """
        markdown_description = f"""
**Alert Id**: {dtm_alert.get("id")}\n

**Alert Summary**: {dtm_alert.get("alert_summary")}\n
        
**Summary from Gemini**: {dtm_alert.get("ai_doc_summary")}
        """
        return markdown_description

    @staticmethod
    def get_common_content_metadata_part(dtm_alert: dict) -> str:
        """
        :param dtm_alert:
        :return:
        """
        markdown_content = f"""
### Metadata
- **Alert Id**: {dtm_alert.get("id")}
- **Monitor Id**: {dtm_alert.get("monitor_id")}
- **Created**: {dtm_alert.get("created_at")}
- **Type**: {dtm_alert.get("alert_type")}
- **Severity**: {dtm_alert.get("severity")}

### Summary from Gemini
{dtm_alert.get("ai_doc_summary", "N/A")}
"""
        return markdown_content

    def convert_document_analysis_alert_to_markdown_content(
        self, dtm_alert: dict
    ) -> str:
        """
        :param dtm_alert:
        :return:
        """
        metadata_part = self.get_common_content_metadata_part(dtm_alert)
        markdown_content = f"""
{metadata_part}
### Source Information
- **Author**: {dtm_alert.get("doc").get("source_url")}
- **Collected**: {dtm_alert.get("doc").get("ingested")}
- **Published**: {dtm_alert.get("doc").get("timestamp")}
- **Source File**: {dtm_alert.get("doc").get("filename")}
- **MD5**: {dtm_alert.get("doc").get("file_hashes").get("md5")}
- **SHA1**: {dtm_alert.get("doc").get("file_hashes").get("sha1")}
- **SHA256**: {dtm_alert.get("doc").get("file_hashes").get("sha256")}
- **Source**: {dtm_alert.get("doc").get("source")}
- **Source URL**: {dtm_alert.get("doc").get("source_url")}

### Content
```
{dtm_alert.get("doc").get("raw_text")}
```
"""
        return markdown_content

    def convert_paste_alert_to_markdown_content(self, dtm_alert: dict) -> str:
        """
        :param dtm_alert:
        :return:
        """
        metadata_part = self.get_common_content_metadata_part(dtm_alert)
        markdown_content = f"""
{metadata_part}
### Source Information
- **Created**: {dtm_alert.get("doc").get("timestamp")}
- **Paste Id**: {dtm_alert.get("doc").get("paste_id")}
- **URL**: {dtm_alert.get("doc").get("source_location", {}).get("url", "")}
- **Author**: {dtm_alert.get("doc").get("author", {}).get("identity", {}).get("name", "")}
- **Title**: {dtm_alert.get("doc").get("title", "")}

### Content
```
{dtm_alert.get("doc").get("body")}
```
"""
        return markdown_content

    def convert_account_discovery_alert_to_markdown_content(
        self, dtm_alert: dict
    ) -> str:
        """
        :param dtm_alert:
        :return:
        """
        metadata_part = self.get_common_content_metadata_part(dtm_alert)
        markdown_content = f"""
{metadata_part}
### Source Information
- **Source URL**: {dtm_alert.get("doc").get("source_url")}
- **Collected**: {dtm_alert.get("doc").get("ingested")}
- **Published**: {dtm_alert.get("doc").get("timestamp")}
- **Source File**: {dtm_alert.get("doc").get("source_file").get("filename")}
- **MD5**: {dtm_alert.get("doc").get("source_file").get("hashes").get("md5")}
- **SHA1**: {dtm_alert.get("doc").get("source_file").get("hashes").get("sha1")}
- **SHA256**: {dtm_alert.get("doc").get("source_file").get("hashes").get("sha256")}
### Content
- **Service URL**: {dtm_alert.get("doc").get("service_account").get("service").get("inet_location").get("domain")}
- **Service Domain**: {dtm_alert.get("doc").get("service_account").get("service").get("inet_location").get("url")}
- **Email Domain**: {dtm_alert.get("doc").get("service_account").get("email_domain")}
- **Login**: {dtm_alert.get("doc").get("service_account").get("login")}
- **Password**: {dtm_alert.get("doc").get("service_account").get("password").get("plain_text")}
"""
        return markdown_content

    def convert_message_type_alert_to_markdown_content(self, dtm_alert: dict) -> str:
        """
        :param dtm_alert:
        :return:
        """
        metadata_part = self.get_common_content_metadata_part(dtm_alert)
        markdown_content = f"""
{metadata_part}
### Source Information
- **Created**: {dtm_alert.get("doc").get("ingested")}
- **Channel**: {dtm_alert.get("doc").get("channel").get("name")}
- **Channel URL**: {dtm_alert.get("doc").get("channel").get("channel_url")}
- **Channel Description**: {dtm_alert.get("doc").get("channel").get("channel_info").get("description")}
- **Messenger**: {dtm_alert.get("doc").get("channel").get("messenger").get("name")}
- **Author**: {dtm_alert.get("doc").get("sender").get("identity").get("name")}
- **Message Id**: {dtm_alert.get("doc").get("message_id")}

### Content
```
{dtm_alert.get("doc").get("body")}
```
"""
        return markdown_content

    def convert_web_content_alert_to_markdown_content(self, dtm_alert: dict) -> str:
        """
        :param dtm_alert:
        :return:
        """
        metadata_part = self.get_common_content_metadata_part(dtm_alert)
        markdown_content = f"""
{metadata_part}
### Source Information
- **Created**: {dtm_alert.get("doc").get("timestamp")}
- **Title**: {dtm_alert.get("doc").get("title")}
- **URL**: {dtm_alert.get("doc").get("inet_location", {}).get("url", "")}

### Content
```
{dtm_alert.get("doc").get("text") if "text" in dtm_alert.get("doc") else dtm_alert.get("doc").get("raw_text")}
```
"""
        return markdown_content

    def convert_domain_discovery_alert_to_markdown_content(
        self, dtm_alert: dict
    ) -> str:
        """
        :param dtm_alert:
        :return:
        """
        metadata_part = self.get_common_content_metadata_part(dtm_alert)
        markdown_content = f"""
{metadata_part}
### Source Information
- **Created**: {dtm_alert.get("doc").get("timestamp")}
- **Domain**: {dtm_alert.get("doc").get("domain")}
- **Source**: {dtm_alert.get("doc").get("source")}
"""
        return markdown_content

    def convert_shop_list_alert_to_markdown_content(self, dtm_alert: dict) -> str:
        """
        :param dtm_alert:
        :return:
        """
        metadata_part = self.get_common_content_metadata_part(dtm_alert)
        markdown_content = f"""
{metadata_part}
### Source Information
- **Created**: {dtm_alert.get("doc").get("ingested")}
- **URL**: {dtm_alert.get("doc").get("listing_url", {}).get("url")}
- **Shop Name**: {dtm_alert.get("doc").get("shop", {}).get("name")}
- **Price**: {str(dtm_alert.get("doc").get("price", ""))+dtm_alert.get("doc").get("currency", "")}
- **Quantity**: {dtm_alert.get("doc").get("item_qty", "")}
- **Seller**: {dtm_alert.get("doc").get("seller", {}).get("identity", {}).get("name")}
- **Listing ID**: {dtm_alert.get("doc").get("listing_id", "")}
- **Listing URL**: {dtm_alert.get("doc").get("listing_url", {}).get("url", "")}
- **Item Type**: {dtm_alert.get("doc").get("item_type")}
"""
        return markdown_content

    def convert_alert_to_markdown_content(self, dtm_alert: dict) -> str:
        """
        :param dtm_alert:
        :return:
        """
        metadata_part = self.get_common_content_metadata_part(dtm_alert)
        markdown_content = f"""
{metadata_part}
### Post
```
{dtm_alert.get("doc").get("raw_text")}
```
"""
        return markdown_content

    def create_incident(self, dtm_alert: dict) -> list:
        """
        convert a dtm_alert into an OCTI incident with related entities
        :param dtm_alert:
        :return:
        """
        stix_objects = []

        # incident name
        incident_name = dtm_alert.get("title")

        # incident description
        incident_description = self.generate_incident_description(dtm_alert)

        # incident date
        incident_created = dtm_alert.get("created_at")
        incident_updated = dtm_alert.get("updated_at")

        incident_severity = dtm_alert.get("severity")
        incident_type = dtm_alert.get("alert_type")

        # generate a content based on alert useful information
        files = []
        try:
            if dtm_alert.get("doc").get("__type") == "message":
                markdown_content = self.convert_message_type_alert_to_markdown_content(
                    dtm_alert
                )
            elif dtm_alert.get("doc").get("__type") == "web_content_publish":
                markdown_content = self.convert_web_content_alert_to_markdown_content(
                    dtm_alert
                )
            elif dtm_alert.get("doc").get("__type") == "account_discovery":
                markdown_content = (
                    self.convert_account_discovery_alert_to_markdown_content(dtm_alert)
                )
            elif dtm_alert.get("doc").get("__type") == "document_analysis":
                markdown_content = (
                    self.convert_document_analysis_alert_to_markdown_content(dtm_alert)
                )
            elif dtm_alert.get("doc").get("__type") == "paste":
                markdown_content = self.convert_paste_alert_to_markdown_content(
                    dtm_alert
                )
            elif dtm_alert.get("doc").get("__type") == "shop_listing":
                markdown_content = self.convert_shop_list_alert_to_markdown_content(
                    dtm_alert
                )
            elif dtm_alert.get("doc").get("__type") == "domain_discovery":
                markdown_content = (
                    self.convert_domain_discovery_alert_to_markdown_content(dtm_alert)
                )
            else:
                markdown_content = self.convert_alert_to_markdown_content(dtm_alert)

            # add the alert formatted content into a file attached to the incident
            markdown_content_bytes = markdown_content.encode("utf-8")
            base64_bytes = base64.b64encode(markdown_content_bytes)
            files.append(
                {
                    "name": "alert.md",
                    "data": base64_bytes,
                    "mime_type": "text/markdown",
                    "no_trigger_import": False,
                }
            )
        except Exception as ex:
            self.helper.connector_logger.error(
                f"An error occurred while generating alert content for alert.id: {dtm_alert.get('id')}, exception: {str(ex)}"
            )

        # generate external_reference
        stix_external_ref = stix2.ExternalReference(
            source_name="Google DTM",
            url="https://advantage.mandiant.com/dtm/alerts/" + dtm_alert.get("id"),
        )

        # create the incident
        stix_incident = stix2.Incident(
            id=Incident.generate_id(name=incident_name, created=incident_created),
            name=incident_name,
            created=incident_created,
            first_seen=incident_created,
            last_seen=incident_updated,
            description=incident_description,
            created_by_ref=self.author,
            allow_custom=True,
            incident_type=incident_type,
            labels=dtm_alert.get("tags", []),
            severity=incident_severity,
            object_marking_refs=[self.tlp_marking.get("id")],
            source="Google DTM",
            external_references=[stix_external_ref],
            custom_properties={"x_opencti_files": files},
        )
        stix_objects.append(stix_incident)

        if "channel" in dtm_alert.get("doc"):
            stix_channel = self.create_channel(dtm_alert.get("doc").get("channel"))
            stix_objects.append(stix_channel)

            # create relation between incident and channel
            relationship_uses = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "uses",
                    stix_incident.id,
                    stix_channel.id,
                ),
                relationship_type="uses",
                created_by_ref=self.author.id,
                source_ref=stix_incident.id,
                target_ref=stix_channel.id,
                object_marking_refs=[self.tlp_marking.get("id")],
                allow_custom=True,
            )
            stix_objects.append(relationship_uses)

        related_stix_entities = []
        # process 'account_discovery' related entities
        if dtm_alert.get("doc").get("__type") == "account_discovery":
            related_stix_entities = self.generate_account_discovery_related_entities(
                dtm_alert
            )

        # process 'domain_discovery' related entities
        if dtm_alert.get("doc").get("__type") == "domain_discovery":
            related_stix_entities = self.generate_domain_discovery_related_entities(
                dtm_alert
            )

        # attach alert related entities to incident
        if related_stix_entities:
            for entity in related_stix_entities:
                # create relation between incident and email
                relationship_uses = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to",
                        entity.id,
                        stix_incident.id,
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.author.id,
                    source_ref=entity.id,
                    target_ref=stix_incident.id,
                    object_marking_refs=[self.tlp_marking.get("id")],
                    allow_custom=True,
                )
                stix_objects.append(entity)
                stix_objects.append(relationship_uses)

        return stix_objects

    def generate_account_discovery_related_entities(self, dtm_alert: dict) -> list:
        """
        :param dtm_alert:
        :return:
        """
        stix_related_entities = []
        if "login" in dtm_alert.get("doc").get("service_account", {}):
            password = None
            if (
                "plain_text"
                in dtm_alert.get("doc").get("service_account", {}).get("password", {})
                and dtm_alert.get("doc")
                .get("service_account", {})
                .get("password", {})
                .get("plain_text")
                != "********"
            ):
                password = (
                    dtm_alert.get("doc")
                    .get("service_account", {})
                    .get("password", {})
                    .get("plain_text")
                )
            stix_account = stix2.UserAccount(
                account_login=dtm_alert.get("doc").get("service_account").get("login"),
                credential=password,
                object_marking_refs=[self.tlp_marking.get("id")],
                custom_properties={
                    "created_by_ref": self.author.id,
                },
            )
            stix_related_entities.append(stix_account)
        if "email" in dtm_alert.get("doc").get("service_account", {}).get(
            "profile", {}
        ).get("contact", {}):
            stix_email = stix2.EmailAddress(
                value=dtm_alert.get("doc")
                .get("service_account", {})
                .get("profile", {})
                .get("contact", {})
                .get("email"),
                object_marking_refs=[self.tlp_marking.get("id")],
                custom_properties={
                    "created_by_ref": self.author.id,
                },
            )
            stix_related_entities.append(stix_email)
        if "url" in dtm_alert.get("doc").get("service_account", {}).get(
            "service", {}
        ).get("inet_location", {}):
            stix_url = stix2.URL(
                value=dtm_alert.get("doc")
                .get("service_account", {})
                .get("service", {})
                .get("inet_location", {})
                .get("url"),
                object_marking_refs=[self.tlp_marking.get("id")],
                custom_properties={
                    "created_by_ref": self.author.id,
                },
            )
            stix_related_entities.append(stix_url)
        if "domain" in dtm_alert.get("doc").get("service_account", {}).get(
            "service", {}
        ).get("inet_location", {}):
            stix_domain = stix2.DomainName(
                value=dtm_alert.get("doc")
                .get("service_account", {})
                .get("service", {})
                .get("inet_location", {})
                .get("domain"),
                object_marking_refs=[self.tlp_marking.get("id")],
                custom_properties={
                    "created_by_ref": self.author.id,
                },
            )
            stix_related_entities.append(stix_domain)
        if "filename" in dtm_alert.get("doc").get("source_file", {}):
            stix_file = stix2.File(
                hashes={
                    "SHA-256": dtm_alert.get("doc")
                    .get("source_file", {})
                    .get("hashes", {})
                    .get("sha256"),
                    "SHA-1": dtm_alert.get("doc")
                    .get("source_file", {})
                    .get("hashes", {})
                    .get("sha1"),
                    "MD5": dtm_alert.get("doc")
                    .get("source_file", {})
                    .get("hashes", {})
                    .get("md5"),
                },
                name=dtm_alert.get("doc").get("source_file", {}).get("name"),
                object_marking_refs=[self.tlp_marking.get("id")],
                custom_properties={
                    "created_by_ref": self.author.id,
                },
            )
            stix_related_entities.append(stix_file)
        return stix_related_entities

    def generate_domain_discovery_related_entities(self, dtm_alert: dict) -> list:
        """
        :param dtm_alert:
        :return:
        """
        stix_related_entities = []
        if "domain" in dtm_alert.get("doc") and dtm_alert.get("doc").get("domain"):
            stix_account = stix2.DomainName(
                value=dtm_alert.get("doc").get("domain"),
                object_marking_refs=[self.tlp_marking.get("id")],
                custom_properties={
                    "created_by_ref": self.author.id,
                },
            )
            stix_related_entities.append(stix_account)
        return stix_related_entities
