from typing import Literal

import pycti
import stix2
from dateutil.parser import parse
from pycti import (
    Identity,
    Incident,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
        - `generate_id()` methods from `pycti` library MUST be used to generate the `id` of each entity (except observables),
        e.g. `pycti.Identity.generate_id(name="Source Name", identity_class="organization")` for a STIX Identity.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
    ):
        """
        Initialize the converter with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `tlp_level`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            tlp_level (str): The TLP level to add to the created STIX entities.
        """
        self.helper = helper
        self.author = self.create_author()
        self.tlp_marking = self._create_tlp_marking(level=tlp_level.lower())

    @staticmethod
    def create_author() -> stix2.Identity:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="CrowdStrike", identity_class="organization"),
            name="CrowdStrike",
            identity_class="organization",
        )
        return author

    @staticmethod
    def _create_tlp_marking(level):
        mapping = {
            "white": stix2.TLP_WHITE,
            # OpenCTI treats TLP:CLEAR as a distinct marking (not an alias of
            # TLP:WHITE), matching connectors_sdk.models.tlp_marking.
            "clear": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:CLEAR",
                },
            ),
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
    def generate_common_description(notification: dict) -> str:
        """
        :param notification:
        :return:
        """
        markdown_description = (
            "### Alert Metadata\n"
            f"- **Notification Id**: {notification.get('id')}\n"
            f"- **Created Date**: {notification.get('created_date')}\n"
            f"- **Updated Date**: {notification.get('updated_date')}\n"
            f"- **Rule Name**: {notification.get('rule_name')}\n"
            f"- **Rule Topic**: {notification.get('rule_topic')}\n"
            f"- **Rule Priority**: {notification.get('rule_priority')}\n"
            f"- **Item Type**: {notification.get('item_type')}\n"
            f"- **Item Date**: {notification.get('item_date')}\n"
        )
        return markdown_description

    @staticmethod
    def _format_breach_files(files: list[dict]) -> str:
        """
        Format a list of breach file entries into a Markdown section.

        :param files: List of file dicts with keys name, size, complete_data_set, download_urls.
        :return: Markdown string for the files section.
        """
        if not files:
            return ""

        lines = ["### Files\n"]
        for index, file in enumerate(files, start=1):
            name = file.get("name") or "--"
            size = file.get("size")
            size_display = f"{size:,} bytes" if size is not None else "--"
            complete = file.get("complete_data_set")
            complete_display = (
                "Yes" if complete else ("No" if complete is False else "--")
            )
            download_urls = file.get("download_urls") or []

            lines.append(f"**File {index}**\n")
            lines.append(f"- **Name**: {name}\n")
            lines.append(f"- **Size**: {size_display}\n")
            lines.append(f"- **Complete Data Set**: {complete_display}\n")
            if download_urls:
                urls_display = ", ".join(download_urls)
                lines.append(f"- **Download URLs**: {urls_display}\n")
            lines.append("\n")

        return "".join(lines)

    @staticmethod
    def _format_breach_details(items: list[dict]) -> str:
        """
        Format a list of breach detail items into a Markdown section.

        :param items: List of credential/item dicts from breach_details.items.
        :return: Markdown string for the breach details section.
        """
        if not items:
            return ""

        fields = [
            ("Email", "email"),
            ("Login ID", "login_id"),
            ("Credentials URL", "credentials_url"),
        ]

        lines = ["### Breach Details\n"]
        for index, item in enumerate(items, start=1):
            lines.append(f"**Item {index}**\n")
            for label, key in fields:
                value = item.get(key) or "--"
                lines.append(f"- **{label}**: {value}\n")
            lines.append("\n")

        return "".join(lines)

    def generate_exposed_data_content(self, notification_detail: dict) -> str:
        """
        Generate a Markdown description for exposed data notifications.
        """
        notification = notification_detail.get("notification") or {}
        breach_details = notification_detail.get("breach_details") or {}
        breach = notification.get("breach_summary") or {}
        breach_files = breach.get("files", [])
        markdown_content = (
            f"{self.generate_common_description(notification)}\n"
            "### Breach Summary\n"
            f"- **Name**: {breach.get('name') or '--'}\n"
            f"- **Description**: {breach.get('description') or '--'}\n"
            f"- **Exposure Date**: {breach.get('exposure_date') or '--'}\n"
            f"- **Confidence**: {breach.get('confidence_level') or '--'}\n"
            f"- **Credentials Domains**: {breach.get('credentials_domains') or '--'}\n"
            f"- **Event Date**: {breach.get('event_date') or '--'}\n"
            f"- **Credential Statuses**: {breach.get('credential_statuses') or '--'}\n"
        )
        # append markdown with breach files information
        if breach_files:
            markdown_content += "\n" + self._format_breach_files(breach_files)

        # append markdown with breach details
        breach_items = breach_details.get("items", [])
        if breach_items:
            markdown_content += "\n" + self._format_breach_details(breach_items)

        return markdown_content

    def generate_typosquatting_content(self, notification: dict) -> str:
        """
        Generate a Markdown description for typosquatting notifications.
        """
        typosquatting = notification.get("typosquatting", {})
        whois = typosquatting.get("whois", {})
        markdown_content = (
            f"{self.generate_common_description(notification)}\n"
            "### Typosquatting Summary\n"
            f"- **Unicode Format**: {typosquatting.get('unicode_format') or '--'}\n"
            f"- **Punycode Format**: {typosquatting.get('punycode_format') or '--'}\n"
            "\n"
            "#### WHOIS Information\n"
            f"- **Date Created**: {whois.get('date_created') or '--'}\n"
            f"- **Date Updated**: {whois.get('date_updated') or '--'}\n"
            f"- **Date Expires**: {whois.get('date_expires') or '--'}\n"
            f"- **Name Servers**: {whois.get('name_servers') or '--'}\n"
            f"- **Registrant Name**: {whois.get('registrant', {}).get('name') or '--'}\n"
            f"- **Registrar Name**: {whois.get('registrar', {}).get('name') or '--'}\n"
        )
        return markdown_content

    def generate_post_content(self, notification_detail: dict) -> str:
        """
        Generate a Markdown description for post type notifications.
        """
        notification = notification_detail.get("notification") or {}
        post_details = notification_detail.get("details") or {}
        markdown_content = (
            f"{self.generate_common_description(notification)}\n"
            "### Post Summary\n"
            f"- **Created Date**: {post_details.get('created_date') or '--'}\n"
            f"- **Updated Date**: {post_details.get('updated_date') or '--'}\n"
            f"- **Site**: {post_details.get('site') or '--'}\n"
            f"- **URL**: {post_details.get('url') or '--'}\n"
            f"- **Author**: {post_details.get('author') or '--'}\n"
            f"- **Language**: {post_details.get('language') or '--'}\n"
            f"- **Category**: {post_details.get('category') or '--'}\n"
            f"- **Title**: {post_details.get('title') or '--'}\n"
            "### Post Content\n"
            "```\n"
            f"{post_details.get('content')}\n"
            "```\n"
        )
        return markdown_content

    def generate_reply_content(self, notification_detail: dict) -> str:
        """
        Generate a Markdown description for reply type notifications.
        """
        notification = notification_detail.get("notification") or {}
        reply_details = notification_detail.get("details") or {}
        markdown_content = (
            f"{self.generate_common_description(notification)}\n"
            "### Reply Summary\n"
            f"- **Created Date**: {reply_details.get('created_date') or '--'}\n"
            f"- **Updated Date**: {reply_details.get('updated_date') or '--'}\n"
            f"- **Site**: {reply_details.get('site') or '--'}\n"
            f"- **URL**: {reply_details.get('url') or '--'}\n"
            f"- **Author**: {reply_details.get('author') or '--'}\n"
            f"- **Language**: {reply_details.get('language') or '--'}\n"
            f"- **Category**: {reply_details.get('category') or '--'}\n"
            f"- **Title**: {reply_details.get('title') or '--'}\n"
            "### Reply Content\n"
            "```\n"
            f"{reply_details.get('content')}\n"
            "```\n"
        )
        return markdown_content

    def generate_file_content(self, notification_detail: dict) -> str:
        """
        Generate a Markdown description for file leak notifications.

        File notifications share the dark-web ``details`` structure with posts,
        so the post formatter is reused here. A dedicated method is kept so the
        intent is explicit and a file-specific layout can be added later without
        touching ``create_incident``.
        """
        return self.generate_post_content(notification_detail)

    @staticmethod
    def _extract_highlight_title(notification: dict) -> str:
        """
        Build a short incident title from a notification's ``highlights``.

        ``highlights`` may be missing, ``None`` or an empty list, so guard
        before indexing to avoid ``TypeError`` / ``IndexError``.
        """
        highlights = notification.get("highlights") or []
        raw_title = highlights[0] if highlights else ""
        if len(raw_title) > 50:
            return raw_title[:50] + "..."
        return raw_title

    def create_incident(self, notification_detail: dict) -> list:
        """
        :param notification_detail:
        :return:
        """
        notification = notification_detail.get("notification") or {}
        item_type = notification.get("item_type")
        created_date = notification.get("created_date")
        if not created_date:
            self.helper.connector_logger.error(
                "Notification is missing created_date, skipping alert",
                meta={
                    "item_type": item_type,
                    "notification_id": notification.get("id"),
                },
            )
            return []

        try:
            incident_date = parse(created_date)
        except (ValueError, OverflowError, TypeError):
            self.helper.connector_logger.warning(
                "Notification has an unparseable created_date, skipping alert",
                meta={
                    "item_type": item_type,
                    "created_date": created_date,
                    "notification_id": notification.get("id"),
                },
            )
            return []

        stix_objects = []
        # incident_type is derived from the CrowdStrike notification item_type
        incident_type = item_type or "alert"
        incident_labels = []
        inc_sco_sdo_refs = []
        attachment_files = []

        if item_type == "typosquatting_domain":
            typosquatting = notification.get("typosquatting") or {}
            title = typosquatting.get("unicode_format")
            alert_detail = self.generate_typosquatting_content(notification)
            for domain_value in (
                typosquatting.get("unicode_format"),
                typosquatting.get("punycode_format"),
            ):
                if not domain_value:
                    continue
                domain_name = stix2.DomainName(
                    value=domain_value,
                    allow_custom=True,
                    object_marking_refs=[self.tlp_marking.id],
                    custom_properties={
                        "x_opencti_created_by_ref": self.author.id,
                    },
                )
                stix_objects.append(domain_name)
                inc_sco_sdo_refs.append(domain_name.id)

        elif item_type == "exposed_data":
            title = (notification.get("breach_summary") or {}).get("name")
            alert_detail = self.generate_exposed_data_content(notification_detail)
            for item in (notification_detail.get("breach_details") or {}).get(
                "items", []
            ):
                if (
                    item.get("malware_family")
                    and item.get("malware_family") != "unknown"
                ):
                    malware = stix2.Malware(
                        id=pycti.Malware.generate_id(item.get("malware_family")),
                        name=item.get("malware_family"),
                        is_family=True,
                        created_by_ref=self.author.id,
                        object_marking_refs=[self.tlp_marking.id],
                    )
                    inc_sco_sdo_refs.append(malware.id)
                    stix_objects.append(malware)
                if item.get("email"):
                    email_address = stix2.EmailAddress(
                        value=item.get("email"),
                        allow_custom=True,
                        object_marking_refs=[self.tlp_marking.id],
                        custom_properties={
                            "x_opencti_created_by_ref": self.author.id,
                        },
                    )
                    inc_sco_sdo_refs.append(email_address.id)
                    stix_objects.append(email_address)
                if item.get("login_id"):
                    user_account = stix2.UserAccount(
                        account_login=item.get("login_id"),
                        allow_custom=True,
                        object_marking_refs=[self.tlp_marking.id],
                        custom_properties={
                            "x_opencti_created_by_ref": self.author.id,
                        },
                    )
                    inc_sco_sdo_refs.append(user_account.id)
                    stix_objects.append(user_account)

                if item.get("credentials_url"):
                    url = stix2.URL(
                        value=item.get("credentials_url"),
                        allow_custom=True,
                        object_marking_refs=[self.tlp_marking.id],
                        custom_properties={
                            "x_opencti_created_by_ref": self.author.id,
                        },
                    )
                    inc_sco_sdo_refs.append(url.id)
                    stix_objects.append(url)

                if item.get("credentials_domain"):
                    domain_name = stix2.DomainName(
                        value=item.get("credentials_domain"),
                        allow_custom=True,
                        object_marking_refs=[self.tlp_marking.id],
                        custom_properties={
                            "x_opencti_created_by_ref": self.author.id,
                        },
                    )
                    inc_sco_sdo_refs.append(domain_name.id)
                    stix_objects.append(domain_name)

        elif item_type == "reply":
            title = self._extract_highlight_title(notification)
            alert_detail = self.generate_reply_content(notification_detail)

        elif item_type == "post":
            title = self._extract_highlight_title(notification)
            alert_detail = self.generate_post_content(notification_detail)

        elif item_type == "file":
            title = self._extract_highlight_title(notification)
            alert_detail = self.generate_file_content(notification_detail)
        else:
            # Unsupported types are expected and skipped, so log at warning level
            # (matches the README) rather than error to avoid noise.
            self.helper.connector_logger.warning(
                "Unsupported notification type, skipping alert",
                meta={
                    "item_type": item_type,
                    "notification_id": notification.get("id"),
                },
            )
            return []

        # Create the incident
        rule_name = notification.get("rule_name") or "CrowdStrike Recon"
        incident_name = f"{rule_name} : {title or '--'}"

        stix_incident = stix2.Incident(
            id=Incident.generate_id(incident_name, incident_date),
            name=incident_name,
            description=alert_detail,
            created=incident_date,
            first_seen=incident_date,
            object_marking_refs=[self.tlp_marking.id],
            labels=incident_labels,
            created_by_ref=self.author.id,
            allow_custom=True,
            custom_properties={
                "severity": notification.get("rule_priority"),
                "incident_type": incident_type,
                "x_opencti_files": attachment_files,
            },
        )
        stix_objects.append(stix_incident)

        for inc_sco_sdo_ref in inc_sco_sdo_refs:
            relation_with_incident = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", stix_incident.id, inc_sco_sdo_ref
                ),
                relationship_type="related-to",
                source_ref=stix_incident.id,
                target_ref=inc_sco_sdo_ref,
                created_by_ref=self.author.id,
                object_marking_refs=[self.tlp_marking.id],
            )
            stix_objects.append(relation_with_incident)

        return stix_objects
