from datetime import datetime

import stix2
from pycti import CustomObservableHostname, Identity, Indicator, StixCoreRelationship

from .config_variables import UrlscanConfig
from .constants import UrlscanConstants
from .utils import UrlscanUtils


class UrlscanConverter:
    """
    Convert data from Urlscan to STIX 2 object
    """

    def __init__(self, helper):
        self.helper = helper
        self.config = UrlscanConfig()
        self.identity = self.generate_urlscan_stix_identity()
        self.constants = UrlscanConstants
        self.utils = UrlscanUtils

    def generate_urlscan_stix_identity(self) -> dict:
        """
        This method create the "Identity (organization)" of UrlScan in Stix2 format.

        :return: dict
        """

        # Generate "URLScan" Identity
        return stix2.Identity(
            id=Identity.generate_id(self.helper.connect_name, "organization"),
            name=self.helper.connect_name,
            description=f"Connector Enrichment {self.helper.connect_name}",
            identity_class="organization",
        )

    def generate_stix_relationship(
        self,
        source_ref: str,
        stix_core_relationship_type: str,
        target_ref: str,
        start_time: str | None = None,
        stop_time: str | None = None,
    ) -> dict:
        """
        This method allows you to create a relationship in Stix2 format.

        :param source_ref: This parameter is the "from" of the relationship.
        :param stix_core_relationship_type: This parameter defines the type of relationship between the two entities.
        :param target_ref: This parameter is the "to" of the relationship.
        :param start_time: This parameter is the start of the relationship. Value not required, None by default.
        :param stop_time: This parameter is the stop of the relationship. Value not required, None by default.
        :return:  dict
        """

        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                stix_core_relationship_type, source_ref, target_ref
            ),
            relationship_type=stix_core_relationship_type,
            source_ref=source_ref,
            start_time=start_time,
            stop_time=stop_time,
            target_ref=target_ref,
            created_by_ref=self.identity["id"],
        )

    def generate_stix_external_reference(
        self, data: dict, stix_entity: dict, is_entity_submission: bool
    ) -> list:
        """
        This method allows you to create an external reference in Stix2 format.
        The is_entity_submission parameter is false, so we create an external reference
        that contains the URLScan link of the search.

        :param data: This parameter contains all the information about the observable enriched by URLScan.
        :param stix_entity: This parameter contains all the information about the observable enriched by OpenCTI.
        :param is_entity_submission: This parameter allows us to know if we are in submissive or search mode. (bool)
        :return: list -> ExternalReference (Stix2 format)
        """

        if is_entity_submission is True:
            description = (
                f"This {stix_entity['type']} has been identified by URLScan, "
                "this link allows you to see the result of this analysis."
            )
            urlscan_uuid = data["task"]["uuid"]
            urlscan_url = data["task"]["reportURL"]
        else:
            entity_type = stix_entity["type"]
            entity_value = stix_entity["value"]
            description = (
                f"This {entity_type} has been identified by URLScan, "
                f"this link allows you to see all results related to it."
            )
            urlscan_uuid = None
            if entity_type in self.constants.ENTITY_TYPE_MAP_SEARCH_API:
                search_entity_type = self.constants.ENTITY_TYPE_MAP_SEARCH_API.get(
                    entity_type
                )

                urlscan_url = (
                    "https://urlscan.io/search#"
                    + search_entity_type
                    + entity_value
                    + " AND date:"
                    + self.config.search_filtered_by_date
                )
            else:
                return []

        # Generate ExternalReference
        external_reference = stix2.ExternalReference(
            source_name=self.helper.connect_name,
            url=urlscan_url,
            external_id=urlscan_uuid,
            description=description,
        )
        return [external_reference]

    def upsert_stix_observable(
        self,
        stix_entity: dict,
        external_reference: list,
        labels: list = None,
        prepared_file_png: dict = None,
    ):
        """
        This method allows you to upsert the information collected by URLScan (Submission / Search)
        to the enriched observable.

        :param stix_entity: This parameter contains all the information about the observable enriched by OpenCTI.
        :param external_reference: This parameter contains the list of all external references.
        :param labels: This parameter contains the list of all labels.
        :param prepared_file_png: This parameter contains the screen prepare file.
        :return:  dict
        """

        data_submission = {
            "type": stix_entity["type"],
            "id": stix_entity["id"],
            "value": stix_entity["value"],
            "custom_properties": {
                "x_opencti_external_references": external_reference,
                "x_opencti_labels": labels,
                "x_opencti_files": (
                    [prepared_file_png] if prepared_file_png is not None else []
                ),
            },
        }
        data_search = {
            "type": stix_entity["type"],
            "id": stix_entity["id"],
            "value": stix_entity["value"],
            "custom_properties": {
                "x_opencti_external_references": external_reference,
            },
        }

        if stix_entity["type"] == "url":
            self.helper.connector_logger.info(
                "[CONNECTOR] Entity, has been identified by URLScan and generation of the Stix bundle is in progress.",
                {"Entity": stix_entity["value"]},
            )
            stix_observable = stix2.URL(**data_submission)
        elif stix_entity["type"] == "domain-name":
            stix_observable = stix2.DomainName(**data_submission)
        elif stix_entity["type"] == "hostname":
            stix_observable = CustomObservableHostname(**data_submission)
        elif stix_entity["type"] == "ipv4-addr":
            stix_observable = stix2.IPv4Address(**data_search)
        elif stix_entity["type"] == "ipv6-addr":
            stix_observable = stix2.IPv6Address(**data_search)
        else:
            return None

        return stix_observable

    def upsert_stix_indicator_with_relationship(
        self,
        data: dict,
        stix_entity: dict,
        external_reference: list,
        labels: list = None,
        prepared_file_png: dict = None,
    ) -> list:
        """
        This method creates and adds a bundle to "self.stix_objects" the IPv4 associated "Indicator"
        in Stix2 format.

        - Relationship : Indicator -> "based-on" -> Observable
        :param data: This parameter contains all the information about the observable enriched by URLScan.
        :param stix_entity: This parameter contains all the information about the observable enriched by OpenCTI.
        :param external_reference: This parameter contains the list of all external references.
        :param labels: This parameter contains the list of all labels.
        :param prepared_file_png: This parameter contains the screen prepare file.
        :return: list
        """

        stix_indicator_with_relationship = []
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        x_opencti_type = stix_entity.get("x_opencti_type", None)

        common_data = {
            "labels": labels,
            "created_by_ref": self.identity["id"],
            "external_references": external_reference,
            "valid_from": now,
            "pattern_type": "stix",
            "custom_properties": {
                "x_opencti_main_observable_type": x_opencti_type,
                "x_opencti_files": (
                    [prepared_file_png] if prepared_file_png is not None else []
                ),
            },
        }

        if stix_entity["type"] == "url":
            data_name_url = data["task"]["url"]
            specific_data = {
                "id": Indicator.generate_id(data_name_url),
                "name": data_name_url,
                "pattern": f"[url:value = '{data_name_url}']",
            }

        elif stix_entity["type"] == "domain-name":
            data_name_domain = data["task"]["apexDomain"]
            specific_data = {
                "id": Indicator.generate_id(data_name_domain),
                "name": data_name_domain,
                "pattern": f"[domain-name:value = '{data_name_domain}']",
            }

        elif stix_entity["type"] == "hostname":
            data_name_hostname = data["task"]["domain"]
            specific_data = {
                "id": Indicator.generate_id(data_name_hostname),
                "name": data_name_hostname,
                "pattern": f"[hostname:value = '{data_name_hostname}']",
            }
        else:
            return []

        merged_data = {
            **common_data,
            **specific_data,
        }
        stix_indicator = stix2.Indicator(**merged_data)

        stix_indicator_with_relationship.append(stix_indicator)

        # Generate Relationship : Indicator -> "based-on" -> Observable
        indicator_to_observable = self.generate_stix_relationship(
            stix_indicator.id, "based-on", stix_entity["id"]
        )
        stix_indicator_with_relationship.append(indicator_to_observable)

        return stix_indicator_with_relationship

    def generate_stix_ip(self, data_stat: dict) -> list:
        """
        This method allows you to check and generate an IPV4 or IPV6 type observable.

        :param data_stat: This parameter contains the organized data associated with the enriched observable.
        :return: list
        """
        all_ips = []
        for ip in data_stat["ips"]:

            if ip is None:
                continue

            is_ipv6 = self.utils.is_ipv6(ip)
            is_ipv4 = self.utils.is_ipv4(ip)

            if is_ipv6 is True:
                stix_ip_addr = stix2.IPv6Address(
                    type="ipv6-addr",
                    value=ip,
                    custom_properties={
                        "x_opencti_created_by_ref": self.identity["id"],
                    },
                )
                all_ips.append(stix_ip_addr)

            if is_ipv4 is True:
                stix_ip_addr = stix2.IPv4Address(
                    type="ipv4-addr",
                    value=ip,
                    custom_properties={
                        "x_opencti_created_by_ref": self.identity["id"],
                    },
                )
                all_ips.append(stix_ip_addr)

        return all_ips

    def generate_stix_asn_with_relationship(self, data_stat, stix_obs_ip):
        """
        This method allows you to generate a asn type observable with these relationships.

        - Relationship : Ip_addr -> "belongs-to" -> ASN
        :param data_stat: This parameter contains the organized data associated with the enriched observable.
        :param stix_obs_ip: This parameter contains the list of IPs in Stix format.
        :return: list
        """
        stix_asn_with_relationship = []

        for index, asn in enumerate(data_stat["asns"]):
            if asn is None:
                continue

            # Generate Asn
            entity_asn = "AS" + str(asn)
            asn_number = int(asn)
            stix_asn = stix2.AutonomousSystem(
                type="autonomous-system",
                number=asn_number,
                name=entity_asn,
                custom_properties={
                    "created_by_ref": self.identity["id"],
                },
            )
            stix_asn_with_relationship.append(stix_asn)

            # Generate Relationship : Ip_addr -> "belongs-to" -> ASN
            ip_to_asn = self.generate_stix_relationship(
                stix_obs_ip[index].id, "belongs-to", stix_asn.id
            )
            stix_asn_with_relationship.append(ip_to_asn)

            return stix_asn_with_relationship

    def generate_stix_hostname_with_relationship(
        self,
        data_stat,
        stix_entity,
        stix_obs_ip,
        external_reference,
        labels,
        prepared_file_png,
    ):
        """
        This method allows you to generate a hostname type observable with these relationships.

        - Relationship : entity -> "related-to" -> hostname
        - Relationship : hostname -> "belongs-to" -> Ip_addr
        :param data_stat: This parameter contains the organized data associated with the enriched observable.
        :param stix_entity: This parameter contains all the information about the observable enriched by OpenCTI.
        :param stix_obs_ip: This parameter contains the list of IPs in Stix format.
        :param external_reference: This parameter contains the list of all external references.
        :param labels: This parameter contains the list of all labels.
        :param prepared_file_png: This parameter contains the screen prepare file.
        :return: list
        """
        stix_hostnames_with_relationship = []

        for index, domain in enumerate(data_stat["domains"]):
            if domain in stix_entity["value"]:
                # Generate Hostname
                stix_hostname = CustomObservableHostname(
                    type="hostname",
                    value=domain,
                    custom_properties={
                        "x_opencti_external_references": external_reference,
                        "x_opencti_labels": labels,
                        "x_opencti_files": (
                            [prepared_file_png] if prepared_file_png is not None else []
                        ),
                        "created_by_ref": self.identity["id"],
                    },
                )
                stix_hostnames_with_relationship.append(stix_hostname)
            else:
                # Generate Hostname
                stix_hostname = CustomObservableHostname(
                    type="hostname",
                    value=domain,
                    custom_properties={
                        "created_by_ref": self.identity["id"],
                    },
                )
                stix_hostnames_with_relationship.append(stix_hostname)

            if stix_entity["id"] != stix_hostname.id:
                # Generate Relationship : entity -> "related-to" -> hostname
                entity_to_hostname = self.generate_stix_relationship(
                    stix_entity["id"], "related-to", stix_hostname.id
                )
                stix_hostnames_with_relationship.append(entity_to_hostname)

            for obs_ip in stix_obs_ip:
                # Generate Relationship : hostname -> "belongs-to" -> Ip_addr
                hostname_to_ip = self.generate_stix_relationship(
                    stix_hostname.id, "resolves-to", obs_ip["id"]
                )
                stix_hostnames_with_relationship.append(hostname_to_ip)

        return stix_hostnames_with_relationship
