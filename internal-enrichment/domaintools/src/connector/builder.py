# -*- coding: utf-8 -*-
"""Builder for DomainTools."""

from datetime import datetime
from typing import Optional, Union

import validators
from pycti import OpenCTIConnectorHelper, StixCoreRelationship
from stix2 import (
    TLP_AMBER,
    AutonomousSystem,
    Bundle,
    DomainName,
    EmailAddress,
    Identity,
    IPv4Address,
    Relationship,
)

from .constants import EntityType


class DtBuilder:
    """
    DomainTools builder.
    Create the STIX objects and relationships.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: Identity,
    ):
        """Initialize DtBuilder."""
        self.helper = helper
        self.author = author

        # Use custom properties to set the author and the confidence level of the object.
        self.custom_props = {
            "x_opencti_created_by_ref": author["id"],
        }

        self.bundle: list[
            Union[AutonomousSystem, DomainName, EmailAddress, IPv4Address, Relationship]
        ] = []

    def reset_score(self):
        """Reset the score used."""
        if "x_opencti_score" in self.custom_props:
            self.custom_props.pop("x_opencti_score")

    def set_score(self, score: int):
        """
        Set the score for the observable.

        Parameters
        ----------
        score : int
            Score to use as `x_opencti_score`
        """
        self.custom_props["x_opencti_score"] = score

    def create_autonomous_system(self, number: int) -> Optional[str]:
        """
        Create an autonomous_system object with the author and custom properties.

        Parameters
        ----------
        number : int
            Number of the autonomous system to create.

        Returns
        -------
        str
            Id of the inserted autonomous system or None.
        """
        auto_system = AutonomousSystem(
            type="autonomous-system",
            number=number,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        self.bundle.append(auto_system)
        return auto_system.id

    def create_belongs_to(
        self,
        source_id: str,
        target_id: str,
        start_date: datetime,
        end_date: datetime,
        description: Optional[str] = None,
    ) -> Relationship:
        """
        Create the `belongs-to` relationship between the source and the target.
        The relation is added to the bundle.

        Parameters
        ----------
        source_id : str
            Id of the source, must be the id of a `domain-name`.
        target_id : str
            Id of the target, must be the id of a `domain-name` or an `ipv4-addr`.
        start_date : datetime
            Starting date for the relationship.
        end_date : datetime
            Ending date for the relationship.
        description : str, optional
            Description of the relationship (e.g. the type (name-server, redirect, etc.).

        Returns
        -------
        Relationship
            Created relationship.
        """
        rel = self.create_relationship(
            "belongs-to", source_id, target_id, start_date, end_date, description
        )

        self.bundle.append(rel)
        return rel

    def create_domain(self, domain: str) -> Optional[str]:
        """
        Create a domain object with the author and custom properties.

        Parameters
        ----------
        domain : str
            Domain to create.

        Returns
        -------
        str
            Id of the inserted domain or None if the domain is invalid.
        """
        if not validators.domain(domain):
            self.helper.log_warning(
                f"[DomainTools] domain {domain} is not correctly "
                "formatted. Skipping."
            )
            return None
        domain_obj = DomainName(
            type="domain-name",
            value=domain,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        self.bundle.append(domain_obj)
        return domain_obj.id

    def create_email(self, email: str) -> Optional[str]:
        """
        Create an email object with the author and custom properties.

        Parameters
        ----------
        email : str
            Email to create.

        Returns
        -------
        str
            Id of the inserted email or None if the domain is invalid.
        """
        if not validators.email(email):
            self.helper.log_warning(
                f"[DomainTools] email {email} is " "not correctly formatted. Skipping."
            )
            return None
        email_obj = EmailAddress(
            type="email-addr",
            value=email,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        self.bundle.append(email_obj)
        return email_obj.id

    def create_ipv4(self, ip: str) -> Optional[str]:
        """
        Create an ip object with the author and custom properties.

        Parameters
        ----------
        ip : str
            Ip to create.

        Returns
        -------
        str
            Id of the inserted ip or None if the ip is invalid.
        """
        if not validators.ipv4(ip):
            self.helper.log_warning(
                f"[DomainTools] ip {ip} is not correctly " "formatted. Skipping."
            )
            return None
        ip_obj = IPv4Address(
            type="ipv4-addr",
            value=ip,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        self.bundle.append(ip_obj)
        return ip_obj.id

    def create_related_to(
        self,
        source_id: str,
        target_id: str,
        start_date: datetime,
        end_date: datetime,
        description: Optional[str] = None,
    ) -> Relationship:
        """
        Create the `related-to` relationship between the source and the target.
        The relation is added to the bundle.

        Parameters
        ----------
        source_id : str
            Id of the source.
        target_id : str
            Id of the target.
        start_date : datetime
            Starting date for the relationship.
        end_date : datetime
            Ending date for the relationship.
        description : str
            Description of the relationship.

        Returns
        -------
        Relationship
            Created relationship.
        """
        rel = self.create_relationship(
            "related-to", source_id, target_id, start_date, end_date, description
        )

        self.bundle.append(rel)
        return rel

    def create_relationship(
        self,
        relationship_type: str,
        source_id: str,
        target_id: str,
        start_date: datetime,
        end_date: datetime,
        description: Optional[str] = None,
    ) -> Relationship:
        """
        Create a relationship between the source and the target.

        Author and confidence level is added from class value.

        Parameters
        ----------
        relationship_type : str
            Type of the relationship (e.g. `related-to`, `belongs-to`, `resolves-to`).
        source_id : str
            Id of the source.
        target_id : str
            Id of the target.
        start_date : datetime
            Starting date for the relationship.
        end_date : datetime
            Ending date for the relationship.
        description : str, optional
            Description of the relationship (e.g. the type (name-server, redirect, etc.).

        Returns
        -------
        Relationship
            Created relationship.
        """
        kwargs = {
            "created_by_ref": self.author,
            "confidence": self.helper.connect_confidence_level,
        }
        if description is not None:
            kwargs["description"] = description
        if start_date != "" and end_date != "":
            kwargs |= {"start_time": start_date, "stop_time": end_date}
        return Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id, start_date, end_date
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            **kwargs,
        )

    def create_resolves_to(
        self,
        source_id: str,
        target_id: str,
        start_date: datetime,
        end_date: datetime,
        description: Optional[str] = None,
    ) -> Relationship:
        """
        Create the `resolves-to` relationship between the source and the target.
        The relation is added to the bundle.

        Parameters
        ----------
        source_id : str
            Id of the source, must be the id of a `domain-name`.
        target_id : str
            Id of the target, must be the id of a `domain-name` or an `ipv4-addr`.
        start_date : datetime
            Starting date for the relationship.
        end_date : datetime
            Ending date for the relationship.
        description : str, optional
            Description of the relationship (e.g. the type (name-server, redirect, etc.).

        Returns
        -------
        Relationship
            Created relationship.
        """
        rel = self.create_relationship(
            "resolves-to", source_id, target_id, start_date, end_date, description
        )

        self.bundle.append(rel)
        return rel

    def link_domain_related_to_email(
        self,
        source: str,
        target: str,
        start_date: datetime,
        end_date: datetime,
        description: str,
    ):
        """
        Create the `related-to` relationship between the `domain-name` and the `email-addr`.
        The created objects are saved into the `bundle` object of the class.

        Parameters
        ----------
        source : str
            Value of the source (domain-name) of the relationship.
        target : str
            Value of the target (email-addr) of the relationship.
        start_date : datetime
            Starting date for the relationship.
        end_date : datetime
            Ending date for the relationship.
        description : str
            Description of the relationship.
        """
        email_id = self.create_email(target)
        if email_id is not None:
            self.create_related_to(source, email_id, start_date, end_date, description)

    def link_domain_resolves_to(
        self,
        source_id: str,
        target: str,
        target_type: EntityType,
        start_date: datetime,
        end_date: datetime,
        description: Optional[str] = None,
    ) -> Optional[str]:
        """
        Create the `resolves-to` relationship between the `domain-name` and the target.
        The target can either be a `domain-name` or an `ipv4-addr`
        The created objects are saved into the `bundle` object of the class.

        Parameters
        ----------
        source_id : str
            Id of the source (`domain-name` object)
        target : str
            Value of the target of the relationship.
        target_type : str
            Type of the target. The type of the target is created based on this field.
        start_date : datetime
            Starting date for the relationship.
        end_date : datetime
            Ending date for the relationship.
        description : str, optional
            Description of the relationship (e.g. the type (name-server, redirect, etc).

        Returns
        -------
        str, optional
            Target id inserted. This will allow re-using it for other insertions.
        """
        target_obj = (
            self.create_domain(target)
            if target_type == EntityType.DOMAIN_NAME
            else self.create_ipv4(target)
        )
        if target_obj is not None:
            self.create_resolves_to(
                source_id, target_obj, start_date, end_date, description
            )
            return target_obj
        return None

    def link_ip_belongs_to_asn(
        self, source: str, target: int, start_date: datetime, end_date: datetime
    ):
        """
        Create the `belongs-to` relationship between the `ipv4-addr` and the `autonomous-system`.
        The created objects are saved into the `bundle` object of the class.

        Parameters
        ----------
        source : str
            Value of the source (ip) of the relationship.
        target : int
            Value of the target (autonomous-system) of the relationship.
        start_date : datetime
            Starting date for the relationship.
        end_date : datetime
            Ending date for the relationship.
        """
        auto_system = self.create_autonomous_system(target)

        if auto_system is not None:
            self.create_belongs_to(source, auto_system, start_date, end_date)

    def send_bundle(self) -> None:
        """
        Create and send the bundle containing the author and the enrichment entities.

        Note: `allow_custom` must be set to True in order to specify the author of an object.
        """
        self.helper.send_stix2_bundle(
            Bundle(objects=[self.author] + self.bundle, allow_custom=True).serialize(),
            allow_custom=True,
            update=True,
        )
