import ipaddress

from pycti import OpenCTIConnectorHelper

from ..models import opencti, spycloud
from ..utils.helpers import dict_to_markdown_table
from .config_loader import ConfigLoader

SEVERITY_LEVELS_BY_CODE = {2: "low", 5: "medium", 20: "high", 25: "critical"}


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

    def create_incident(
        self,
        breach_record: spycloud.BreachRecord,
        breach_catalog: spycloud.BreachCatalog = None,
    ) -> opencti.domain.Incident:
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
            f"{breach_record.email or breach_record.username or breach_record.ip[0] or breach_record.document_id}"
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

        incident = opencti.domain.Incident(
            name=incident_name,
            description=incident_description,
            source=incident_source,
            severity=incident_severity,
            incident_type="data-breach",
            author=self.author,
            created_at=breach_record.spycloud_publish_date,
            updated_at=breach_record.spycloud_publish_date,
            object_marking_refs=[],
        )
        return incident

    def create_observables(
        self,
        breach_record: spycloud.BreachRecord,
    ) -> list[opencti.observables.ObservableBaseModel]:
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

        domain_name_value = breach_record_fields.get("target_domain")
        domain_name = self._create_domain_name(domain_name_value)
        if domain_name:
            observables.append(domain_name)

        subdomain_name_value = breach_record_fields.get("target_subdomain")
        domain_name = self._create_domain_name(subdomain_name_value)
        if domain_name:
            observables.append(domain_name)

        ip_address_value = breach_record_fields.get("ip_addresses", [])[0]
        ip_address = self._create_ip_address(ip_address_value)
        if ip_address:
            observables.append(ip_address)

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

        mac_address_value = breach_record_fields.get("mac_address")
        mac_address = self._create_mac_address(mac_address_value)
        if mac_address:
            observables.append(mac_address)

        file_name = breach_record_fields.get("infected_path")
        file = self._create_file(file_name)
        if file:
            observables.append(file)

        user_agent_value = breach_record_fields.get("user_agent")
        user_agent = self._create_user_agent(user_agent_value)
        if user_agent:
            observables.append(user_agent)

        return observables

    @staticmethod
    def _create_author(
        name: str,
        identity_class: str,
        description: str = None,
    ) -> opencti.common.Author:
        """Create an OpenCTI Author."""
        return opencti.common.Author(
            name=name,
            identity_class=identity_class,
            description=description,
        )

    def _create_domain_name(self, value: str) -> opencti.observables.DomainName:
        """Create an OpenCTI DomainName observable."""
        if value:
            return opencti.observables.DomainName(value=value, author=self.author)

    def _create_email_address(
        self,
        value: str,
        display_name: str = None,
        belongs_to_ref: str = None,
    ) -> opencti.observables.EmailAddress:
        """Create an OpenCTI EmailAddress observable."""
        if value:
            return opencti.observables.EmailAddress(
                value=value,
                display_name=display_name,
                belongs_to_ref=belongs_to_ref,
                author=self.author,
            )

    def _create_file(self, name: str) -> opencti.observables.File:
        """Create an OpenCTI File observable."""
        if name:
            return opencti.observables.File(name=name, author=self.author)

    def _create_ip_address(
        self, value: str
    ) -> opencti.observables.IPV4Address | opencti.observables.IPV6Address:
        """Create an OpenCTI IPv4Address or IPv6Address observable."""
        try:
            ip_address_version = ipaddress.ip_address(value).version
            if ip_address_version == 4:
                ip_address = opencti.observables.IPV4Address(
                    value=value, author=self.author
                )
                return ip_address
            if ip_address_version == 6:
                ip_address = opencti.observables.IPV6Address(
                    value=value, author=self.author
                )
                return ip_address
        except ValueError:
            return None

    def _create_mac_address(self, value: str) -> opencti.observables.MACAddress:
        """Create an OpenCTI MACAddress observable."""
        if value:
            return opencti.observables.MACAddress(value=value, author=self.author)

    def _create_url(self, value: str) -> opencti.observables.Url:
        """Create en OpenCTI Url observable."""
        if value:
            return opencti.observables.Url(value=value, author=self.author)

    def _create_user_account(
        self,
        account_login: str = None,
        account_type: str = None,
    ) -> opencti.observables.UserAccount:
        """Create an OpenCTI UserAccount observable."""
        if account_login:
            return opencti.observables.UserAccount(
                account_login=account_login,
                account_type=account_type,
                author=self.author,
            )

    def _create_user_agent(self, value: str) -> opencti.observables.UserAgent:
        """Create an OpenCTI UserAgent observable."""
        if value:
            return opencti.observables.UserAgent(value=value, author=self.author)
