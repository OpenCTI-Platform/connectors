import logging

from markdownify import markdownify
from pycti import CaseIncident, CustomObjectCaseIncident, CustomObjectTask
from pycti import Note as pyctiNote
from pycti import Task
from stix2 import URL, DomainName, IPv4Address, IPv6Address, Note, UserAccount
from validators import domain as validators_domain
from validators import email as validators_email
from validators import ipv4, ipv6
from validators import url as validators_url

from .constants import EXTERNAL_REFERENCE_URL, INTELFINDER_SEVERITY_MAP, TLP_MAPPINGS
from .utils import (
    create_markdown_table,
    format_datetime,
    format_labels,
    get_cursor_id,
    truncate_content,
)

LOGGER = logging.getLogger(__name__)


class TransformIntelFinder2Stix:
    """Transforms Intelfinder data into STIX objects"""

    def __init__(
        self, intelfinder, author, labels=None, object_marking_refs="TLP:WHITE"
    ):
        self.intelfinder = intelfinder
        self.author = author
        self.id = get_cursor_id(intelfinder)
        self.name = f'Intelfinder - {self.intelfinder.get("title")} - {self.id}'
        LOGGER.debug(f"Transforming: {self.name}")

        if labels:
            self.labels = format_labels(labels)
        else:
            self.labels = None

        self.object_marking_refs = TLP_MAPPINGS.get(object_marking_refs)
        self.external_references = [
            {
                "source_name": "IntelFinder",
                "url": EXTERNAL_REFERENCE_URL.format(self.id),
            }
        ]
        self.custom_properties = {
            "x_opencti_labels": self.labels,
            # "x_opencti_external_references": self.external_references,
        }

        self.stix_objects = []
        self.case_id = None
        self.created = None

    def _transform(self):
        """Transforms Intelfinder data into STIX objects"""
        self._transform_elements()
        self._transform_case_incident()
        self._transform_note()
        self._transform_task()

    def _transform_case_incident(self):
        """Transforms Intelfinder data into STIX Case Incident object"""
        severity = INTELFINDER_SEVERITY_MAP.get(self.intelfinder.get("priority"), "low")
        description = markdownify(self.intelfinder.get("description"))
        if "last_update" in self.intelfinder:
            self.created = format_datetime(self.intelfinder.get("last_update"))
        elif "added_on" in self.intelfinder:
            self.created = format_datetime(self.intelfinder.get("added_on"))
        else:
            raise ValueError("No valid timestamp found in Intelfinder alert")
        # Get all id attributes from STIX objects
        object_refs = [stix_object.get("id") for stix_object in self.stix_objects]

        stix_object = CustomObjectCaseIncident(
            id=CaseIncident.generate_id(
                name=self.name,
                created=self.created,
            ),
            name=self.name,
            description=description,
            severity=severity,
            created=self.created,
            object_marking_refs=self.object_marking_refs,
            labels=self.labels,
            object_refs=object_refs if object_refs is not None else [],
            external_references=self.external_references,
        )

        self.stix_objects.append(stix_object)
        self.case_id = stix_object.get("id")

    def _transform_task(self):
        """Transforms Intelfinder data into STIX Task object"""
        if hasattr(self.intelfinder, "get") and self.intelfinder.get("recommendation"):
            recommendation = markdownify(self.intelfinder.get("recommendation"))

            stix_object = CustomObjectTask(
                id=Task.generate_id(self.name, self.created),
                name=f"Recommendation: {self.name}",
                description=recommendation,
                created=self.created,
                object_refs=[self.case_id],
                object_marking_refs=self.object_marking_refs,
                labels=self.labels,
                external_references=self.external_references,
            )
            self.stix_objects.append(stix_object)
        else:
            LOGGER.warning(f"Invalid recommendation Value for element: {self.name}.")

    def _transform_note(self):
        """Transforms Intelfinder data into STIX Note object"""
        if hasattr(self.intelfinder, "get") and self.intelfinder.get("details"):
            content = markdownify(self.intelfinder.get("details"))
            if hasattr(self.intelfinder, "get") and self.intelfinder.get("elements"):
                markdown_table = create_markdown_table(
                    name=self.name, data=self.intelfinder.get("elements")
                )
                content = content.replace("%elements%", markdown_table)
            note_content = (
                f"{self.name}\n\n{truncate_content(content=content, name=self.name)}"
            )
            stix_object = Note(
                id=pyctiNote.generate_id(content=self.name, created=self.created),
                abstract=self.name,
                content=note_content,
                created=self.created,
                created_by_ref=self.author.id,
                object_refs=[self.case_id],
                object_marking_refs=self.object_marking_refs,
                labels=self.labels,
                external_references=self.external_references,
            )
            self.stix_objects.append(stix_object)
        else:
            LOGGER.warning(f"Invalid details Value for element: {self.name}.")

    def _transform_elements(self):
        """Transforms Intelfinder data into STIX objects"""
        if hasattr(self.intelfinder, "get") and self.intelfinder.get("elements"):
            for element in self.intelfinder.get("elements"):
                if not isinstance(element.get("label"), str):
                    LOGGER.warning(f"Invalid label Value for element: {self.name}.")
                    continue
                if (
                    element.get("label").startswith(
                        ("Similar to Domain", "Name Server", "Mail Server")
                    )
                    or element.get("label") == "Domain"
                ):
                    # Transform Domain Object
                    for domain in element.get("value").split("\n"):
                        if validators_domain(domain):
                            self._create_domain(
                                domain=domain, label=element.get("label")
                            )
                        elif ipv4(domain) or ipv6(domain):
                            self._create_ip(ip=domain, label=element.get("label"))
                        else:
                            LOGGER.warning(
                                f"Invalid domain Value for element: {element.get('label')}, value: {domain}, name: {self.name}"
                            )
                elif element.get("label").startswith(("IP Address")):
                    # Transform IP Address Object
                    for ip in element.get("value").split("\n"):
                        if len(ip) > 0:
                            self._create_ip(ip=ip, label=element.get("label"))
                elif element.get("label").startswith("URL"):
                    # Transform url Address Object
                    for url in element.get("value").split("\n"):
                        # Check url
                        self._create_url(url=url, label=element.get("label"))
                elif element.get("label").startswith("Record"):
                    # Check record
                    self._create_record(
                        records=element.get("value"), label=element.get("label")
                    )
        else:
            LOGGER.warning(f"Invalid elements Value for element: {self.name}.")

    def _create_user_account(
        self,
        label,
        user_id=None,
        account_login=None,
        credential=None,
        silent_warning=False,
    ):
        """Transforms Intelfinder User Accounts into STIX objects"""
        try:
            if user_id is None and account_login is None and credential is None:
                if not silent_warning:
                    LOGGER.warning(
                        f"Invalid User Account Value for element: {label}, {self.name}"
                    )
            else:
                self.stix_objects.append(
                    UserAccount(
                        type="user-account",
                        user_id=user_id,
                        account_login=account_login,
                        credential=credential,
                        object_marking_refs=self.object_marking_refs,
                        custom_properties=self.custom_properties,
                    )
                )
        except Exception as e:
            LOGGER.warning(
                f"Invalid User Account Value for element: {label}, value: {user_id}, name: {self.name}, {e}"
            )

    def _create_record(self, records, label):
        """Transforms Intelfinder Records into STIX objects"""
        # Initialize variables
        user_id = None
        account_login = None
        password = None
        hashed_password = None
        silent_warning = False

        # Transform record into STIX objects
        for record in records.split("\n"):
            try:
                record_breaker = ": "
                if record_breaker in record:
                    key, value = record.split(record_breaker)
                    if key.lower() == "url":
                        self._create_url(url=value, label=label)
                    if key.lower() in ["emails", "e-mails"]:
                        for email in value.split(", "):
                            if validators_email(email):
                                silent_warning = True
                                self._create_user_account(
                                    user_id=email, account_login=email, label=label
                                )
                            else:
                                LOGGER.warning(
                                    f"Invalid email Value for element: {label}, value: {email}, name: {self.name}"
                                )
                    if key.lower() in ["email", "e-mail"]:
                        if validators_email(value):
                            user_id = value
                    if key.lower() in ["username", "name", "user"]:
                        account_login = value
                    if key.lower() == "password":
                        password = value
                    if key.lower() == "Hashed Password":
                        hashed_password = value
                else:
                    LOGGER.debug(
                        f"Invalid record Value for element: {label}, value: {record}, name: {self.name}"
                    )
            except Exception as e:
                if not str(e).startswith("too many values to unpack"):
                    LOGGER.warning(
                        f"Invalid record Value for element: {label}, value: {record}, name: {self.name}, Error: {e}"
                    )
        # Create User Account
        user_id = user_id or account_login or None
        account_login = account_login or user_id or None
        credential = password or hashed_password or None
        self._create_user_account(
            label=label,
            user_id=user_id,
            account_login=account_login,
            credential=credential,
            silent_warning=silent_warning,
        )

    def _create_url(self, url, label):
        """Transforms Intelfinder URLs into STIX objects"""
        if validators_url(url):
            self.stix_objects.append(
                URL(
                    value=url,
                    object_marking_refs=self.object_marking_refs,
                    custom_properties=self.custom_properties,
                )
            )
        else:
            LOGGER.warning(
                f"Invalid domain Value for element: {label}, value: {url}, name: {self.name}"
            )

    def _create_ip(self, ip, label):
        """Transforms Intelfinder IP Addresses into STIX objects"""
        # Check IPv6
        if ipv6(ip):
            self.stix_objects.append(
                IPv6Address(
                    value=ip,
                    object_marking_refs=self.object_marking_refs,
                    custom_properties=self.custom_properties,
                )
            )
        # Check IPv4
        elif ipv4(ip):
            self.stix_objects.append(
                IPv4Address(
                    value=ip,
                    object_marking_refs=self.object_marking_refs,
                    custom_properties=self.custom_properties,
                )
            )
        else:
            LOGGER.warning(
                f"Invalid IP Value for element: {label}, value: {ip}, name: {self.name}"
            )

    def _create_domain(self, domain, label):
        """Transforms Intelfinder Domains into STIX objects"""
        if validators_domain(domain):
            self.stix_objects.append(
                DomainName(
                    value=domain,
                    object_marking_refs=self.object_marking_refs,
                    custom_properties=self.custom_properties,
                )
            )
        else:
            LOGGER.warning(
                f"Invalid domain Value for element: {label}, value: {domain}, name: {self.name}"
            )

    def get_stix_objects(self):
        """Returns STIX objects"""
        self._transform()
        return self.stix_objects
