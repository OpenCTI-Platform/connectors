import ipaddress
from pathlib import Path
from typing import Callable

from pycti import OpenCTIConnectorHelper
from pydantic import ValidationError

from spycloud_connector.models import opencti, spycloud
from spycloud_connector.utils.helpers import dict_to_markdown_table
from spycloud_connector.services import ConfigLoader
from spycloud_connector.utils.types import OCTITLPLevelType

SEVERITY_LEVELS_BY_CODE = {2: "low", 5: "medium", 20: "high", 25: "critical"}


def handle_validation_error(decorated_function: Callable):
    """
    Handle Pydantic's ValidationErrors during models instanciation.
    :param decorated_function: An instance method instanciating a Pydantic model.
    :return: Decorator
    """

    def decorator(self: "ConverterToStix", *args, **kwargs):
        try:
            return decorated_function(self, *args, **kwargs)
        except ValidationError as e:
            self.helper.connector_logger.error(str(e))
            return None

    return decorator


class ConverterToStix:
    """
    Provides methods to convert SpyCloud objects into OCTI objects following STIX 2.1 specification.
    """

    def __init__(self, helper: OpenCTIConnectorHelper, config: ConfigLoader):
        """
        Initialize ConverterToStix with necessary injections.
        :param helper: OpenCTIConnectorHelper instance
        :param config: ConfigLoader instance
        """
        self.helper = helper
        self.config = config
        self.author = ConverterToStix._create_author(
            name=self.helper.connect_name,
            identity_class="organization",
            description="SpyCloud external import connector",
        )
        self.tlp_marking = ConverterToStix._create_tlp_marking(
            level=self.config.spycloud.tlp_level
        )

    @handle_validation_error
    def create_incident(
        self,
        breach_record: spycloud.BreachRecord,
        breach_catalog: spycloud.BreachCatalog = None,
    ) -> opencti.Incident:
        """
        Create an Incident from given breach record and its catalog.
        :param breach_record: SpyCloud breach record
        :param breach_catalog: SpyCloud breach record's catalog
        :return: OpenCTI Incident
        """
        incident_source = breach_catalog.title or "Unknown"
        incident_severity = SEVERITY_LEVELS_BY_CODE.get(breach_record.severity)
        incident_name = (
            f"Spycloud {incident_severity} alert on "
            f"{breach_record.email or breach_record.username or breach_record.ip_addresses[0] or breach_record.document_id}"
        )
        incident_description = dict_to_markdown_table(
            breach_record.model_dump(
                exclude=[
                    "source_id",
                    "severity",
                    "spycloud_publish_date",
                ]
            )
        )

        incident = opencti.Incident(
            name=incident_name,
            description=incident_description,
            source=incident_source,
            severity=incident_severity,
            incident_type="data-breach",
            author=self.author,
            created_at=breach_record.spycloud_publish_date,
            updated_at=breach_record.spycloud_publish_date,
            markings=[self.tlp_marking],
        )
        return incident

    def create_observables(
        self, breach_record: spycloud.BreachRecord
    ) -> list[opencti.ObservableBaseModel]:
        """
        Create all found observables from given breach record.
        :param breach_record: SpyCloud breach record
        :return: OpenCTI observables
        """
        observables = []

        breach_record_fields = breach_record.model_extra

        user_account_login = breach_record_fields.get("user_hostname")
        user_account_type = breach_record_fields.get("user_os")
        user_account = self._create_user_account(
            account_login=user_account_login, account_type=user_account_type
        )
        if user_account:
            observables.append(user_account)

        user_account_login = breach_record_fields.get("username")
        user_account = self._create_user_account(account_login=user_account_login)
        if user_account:
            observables.append(user_account)

        email_value = breach_record_fields.get("email")
        email_display_name = breach_record_fields.get("full_name")
        email_address = self._create_email_address(
            value=email_value,
            display_name=email_display_name,
            belongs_to_ref=user_account.id if user_account else None,
        )
        if email_address:
            observables.append(email_address)

        url_value = breach_record_fields.get("target_url")
        url = self._create_url(url_value)
        if url:
            observables.append(url)

        domain_name_value = breach_record_fields.get("target_domain")
        domain_name = self._create_domain_name(domain_name_value)
        if domain_name:
            observables.append(domain_name)

        subdomain_name_value = breach_record_fields.get("target_subdomain")
        domain_name = self._create_domain_name(subdomain_name_value)
        if domain_name:
            observables.append(domain_name)

        mac_address_value = breach_record_fields.get("mac_address")
        mac_address = self._create_mac_address(mac_address_value)
        if mac_address:
            observables.append(mac_address)

        for ip_address_value in breach_record_fields.get("ip_addresses", []):
            ip_address = self._create_ip_address(ip_address_value)
            if ip_address:
                observables.append(ip_address)

        file_path = breach_record_fields.get("infected_path")
        if file_path:
            file_path = Path(file_path)

            file = self._create_file(str(file_path))
            if file:
                observables.append(file)

            directory = self._create_directory(str(file_path.parent))
            if directory:
                observables.append(directory)

        user_agent_value = breach_record_fields.get("user_agent")
        user_agent = self._create_user_agent(user_agent_value)
        if user_agent:
            observables.append(user_agent)

        return observables

    @staticmethod
    def _create_author(
        name: str, identity_class: str, description: str = None
    ) -> opencti.Author:
        """Create an OpenCTI Author."""
        return opencti.Author(
            name=name,
            identity_class=identity_class,
            description=description,
        )

    @staticmethod
    def _create_tlp_marking(level: OCTITLPLevelType) -> opencti.TLPMarking:
        """Create an OpenCTI TLP Marking."""
        return opencti.TLPMarking(level=level)

    @handle_validation_error
    def _create_directory(self, path: str) -> opencti.Directory:
        """Create an OpenCTI Directory observable."""
        if path:
            return opencti.Directory(
                path=path,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_validation_error
    def _create_domain_name(self, value: str) -> opencti.DomainName:
        """Create an OpenCTI DomainName observable."""
        if value:
            return opencti.DomainName(
                value=value,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_validation_error
    def _create_email_address(
        self, value: str, display_name: str = None, belongs_to_ref: str = None
    ) -> opencti.EmailAddress:
        """Create an OpenCTI EmailAddress observable."""
        if value:
            return opencti.EmailAddress(
                value=value,
                display_name=display_name,
                belongs_to_ref=belongs_to_ref,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_validation_error
    def _create_file(self, name: str) -> opencti.File:
        """Create an OpenCTI File observable."""
        if name:
            return opencti.File(
                name=name,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_validation_error
    def _create_ip_address(
        self, value: str
    ) -> opencti.IPv4Address | opencti.IPv6Address:
        """Create an OpenCTI IPv4Address or IPv6Address observable."""
        ip_address_version = None
        try:
            ip_address_version = ipaddress.ip_address(value).version
        except ValueError as e:
            self.helper.connector_logger.error(str(e))
            return None

        if ip_address_version == 4:
            return opencti.IPv4Address(
                value=value,
                author=self.author,
                markings=[self.tlp_marking],
            )
        if ip_address_version == 6:
            return opencti.IPv6Address(
                value=value,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_validation_error
    def _create_mac_address(self, value: str) -> opencti.MACAddress:
        """Create an OpenCTI MACAddress observable."""
        if value:
            return opencti.MACAddress(
                value=value,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_validation_error
    def _create_url(self, value: str) -> opencti.URL:
        """Create en OpenCTI URL observable."""
        if value:
            return opencti.URL(
                value=value,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_validation_error
    def _create_user_account(
        self, account_login: str = None, account_type: str = None
    ) -> opencti.UserAccount:
        """Create an OpenCTI UserAccount observable."""
        if account_login:
            return opencti.UserAccount(
                account_login=account_login,
                account_type=account_type,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_validation_error
    def _create_user_agent(self, value: str) -> opencti.UserAgent:
        """Create an OpenCTI UserAgent observable."""
        if value:
            return opencti.UserAgent(
                value=value,
                author=self.author,
                markings=[self.tlp_marking],
            )
