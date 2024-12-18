import ipaddress

import stix2
from dateutil.parser import parse
from pycti import Identity, Indicator, Malware, StixCoreRelationship


class ConverterToStix:
    """
    Provides methods for converting various Zvelo IOCs format into STIX 2.1 objects.
    """

    def __init__(self, helper):
        self.helper = helper
        self.author = self.create_author()
        self.tlp = stix2.TLP_AMBER

    @staticmethod
    def create_author() -> stix2.Identity:
        """
        Create Author.
        :return: Author as STIX 2.1 Identity object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="Zvelo", identity_class="organization"),
            name="Zvelo",
            identity_class="organization",
        )
        return author

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

    def _convert_related_ips(
        self, ip_info: list[dict], observable_id: str, labels: list[str]
    ) -> list[stix2.v21._STIXBase21]:
        """
        Convert IOC's associated IPs to STIX 2.1 IPs Observables and link them to the main Observable.
        :param ip_info: List of IOC's associated IPs
        :param observable_id: ID of STIX 2.1 Observable representing IOC
        :param labels: Labels to set to STIX 2.1 IP Observables
        :return: List of STIX 2.1 objects (IP Observables and their relationship)
        """
        stix_objects = []
        for ip_address in ip_info:
            if self._is_ipv4(ip_address.get("ip")):
                stix_related_ip_observable = stix2.IPv4Address(
                    value=ip_address.get("ip"),
                    object_marking_refs=[self.tlp],
                    custom_properties={
                        "x_opencti_created_by_ref": self.author["id"],
                        "labels": labels,
                    },
                )
            elif self._is_ipv6(ip_address.get("ip")):
                stix_related_ip_observable = stix2.IPv6Address(
                    value=ip_address.get("ip"),
                    object_marking_refs=[self.tlp],
                    custom_properties={
                        "x_opencti_created_by_ref": self.author["id"],
                        "labels": labels,
                    },
                )
            else:
                self.helper.log_warning(
                    f"Unable to convert ip_info, bad IP format for IP: {ip_address.get('ip')}"
                )
                continue
            stix_relationship = self._create_relation(
                observable_id, stix_related_ip_observable.id, "related-to"
            )
            stix_objects.append(stix_related_ip_observable)
            stix_objects.append(stix_relationship)
        return stix_objects

    def _create_relation(
        self, source_id: str, target_id: str, relation: str
    ) -> stix2.Relationship:
        """
        Create a STIX 2.1 Relationship object.
        :param source_id: STIX 2.1 source object's ID
        :param target_id: STIX 2.1 target object's ID
        :param relation: Name of relationship to create
        :return: STIX 2.1 relationship object
        """
        stix_relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relation,
                source_id,
                source_id,
            ),
            relationship_type=relation,
            source_ref=source_id,
            target_ref=target_id,
            object_marking_refs=[self.tlp],
        )
        return stix_relationship

    def convert_threat_to_stix(self, data) -> list[stix2.v21._STIXBase21]:
        """
        Convert threat IOC into STIX entities (indicator and related observables)
        :param data: Raw threat data from Zvelo
        :return: List of STIX 2.1 objects and relationships
        """
        bundle_objects = []
        if data.get("ioc_type") == "url":
            # create URL observable
            stix_observable = stix2.URL(
                value=data.get("ioc"),
                object_marking_refs=[self.tlp],
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_score": data.get("confidence_level"),
                    "labels": [data.get("threat_type")],
                },
            )
            # create STIX indicator
            url_value = data.get("ioc").replace(
                "'", "\\'"
            )  # single quotes must be escaped
            pattern_value = "[url:value = '" + url_value + "']"
            observable_type = "Url"

        elif data.get("ioc_type") == "domain":
            # create domain observable
            stix_observable = stix2.DomainName(
                value=data.get("ioc"),
                object_marking_refs=[self.tlp],
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_score": data.get("confidence_level"),
                    "labels": [data.get("threat_type")],
                },
            )
            # create STIX indicator
            pattern_value = "[domain-name:value = '" + data.get("ioc") + "']"
            observable_type = "Domain-Name"

        elif data.get("ioc_type") == "ip":
            if ":" in data.get("ioc"):
                ip_value = data.get("ioc").split(":")[0]
                description = f"Traffic seen on port {data.get('ioc').split(':')[1]}"
            else:
                ip_value = data.get("ioc")
                description = None
            if self._is_ipv4(ip_value):
                # create IPV4 observable
                stix_observable = stix2.IPv4Address(
                    value=ip_value,
                    object_marking_refs=[self.tlp],
                    custom_properties={
                        "x_opencti_created_by_ref": self.author["id"],
                        "x_opencti_score": data.get("confidence_level"),
                        "labels": [data.get("threat_type")],
                        "x_opencti_description": description,
                    },
                )
                # create STIX indicator
                pattern_value = "[ipv4-addr:value = '" + ip_value + "']"
                observable_type = "IPv4-Addr"
            else:
                stix_observable = stix2.IPv6Address(
                    value=ip_value,
                    object_marking_refs=[self.tlp],
                    custom_properties={
                        "x_opencti_created_by_ref": self.author["id"],
                        "x_opencti_score": data.get("confidence_level"),
                        "labels": [data.get("threat_type")],
                    },
                )
                # create STIX indicator
                pattern_value = "[ipv6-addr:value = '" + ip_value + "']"
                observable_type = "IPv6-Addr"

        else:
            self.helper.log_warning(f"Unrecognized ioc_type: {data.get('ioc_type')}")
            return bundle_objects

        # create an indicator for the ioc
        stix_indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern_value),
            name=data.get("ioc"),
            description="",
            created_by_ref=self.author["id"],
            confidence=data.get("confidence_level"),
            pattern_type="stix",
            labels=[data.get("threat_type"), data.get("malware_family")],
            valid_from=parse(data.get("discovered_date")),
            created=parse(data.get("discovered_date")),
            pattern=pattern_value,
            external_references=[],
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": data.get("confidence_level"),
                "x_opencti_main_observable_type": observable_type,
            },
        )

        # create relation between observable and indicator
        stix_relationship = self._create_relation(
            stix_indicator.id, stix_observable.id, "based-on"
        )

        # add object in the bundle_objects
        bundle_objects.append(stix_indicator)
        bundle_objects.append(stix_observable)
        bundle_objects.append(stix_relationship)

        # create relation between indicator and malware
        if data.get("malware_family"):
            # Create the malware object
            stix_malware = stix2.Malware(
                id=Malware.generate_id(data.get("malware_family")),
                name=data.get("malware_family"),
                created_by_ref=self.author["id"],
                object_marking_refs=[self.tlp],
                is_family=False,
            )
            # create relation between observable and indicator
            stix_relationship = self._create_relation(
                stix_indicator.id, stix_malware.id, "indicates"
            )

            # add objects in the bundle
            bundle_objects.append(stix_malware)
            bundle_objects.append(stix_relationship)

        # create an IP observable and create a relation with the main observable
        if data.get("ioc_type") != "ip" and data.get("ip_info"):
            bundle_objects.extend(
                self._convert_related_ips(
                    ip_info=data.get("ip_info"),
                    observable_id=stix_observable.id,
                    labels=[data.get("threat_type")],
                )
            )

        return bundle_objects

    def convert_phish_to_stix(self, data) -> list[stix2.v21._STIXBase21]:
        """
        Convert phish IOC into STIX entities (indicator and related observables)
        :param data: Raw phish data from Zvelo
        :return: List of STIX 2.1 objects and relationships
        """
        bundle_objects = []

        # create URL observable
        stix_observable = stix2.URL(
            value=data.get("url"),
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
                "x_opencti_score": data.get("confidence_level"),
                "labels": ["phishing"],
            },
        )
        # create STIX indicator
        url_value = data.get("url").replace("'", "\\'")  # single quotes must be escaped
        pattern_value = "[url:value = '" + url_value + "']"
        observable_type = "Url"

        # create an indicator for the ioc
        stix_indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern_value),
            name=data.get("url"),
            description=data.get("brand"),
            created_by_ref=self.author["id"],
            confidence=data.get("confidence_level"),
            pattern_type="stix",
            labels=["phishing"],
            valid_from=parse(data.get("discovered_date")),
            created=parse(data.get("discovered_date")),
            pattern=pattern_value,
            external_references=[],
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": data.get("confidence_level"),
                "x_opencti_main_observable_type": observable_type,
            },
        )

        # create relation between observable and indicator
        stix_relationship = self._create_relation(
            stix_indicator.id, stix_observable.id, "based-on"
        )

        # add objects in the bundle objects
        bundle_objects.append(stix_indicator)
        bundle_objects.append(stix_observable)
        bundle_objects.append(stix_relationship)

        # create an IP observable and create a relation with the main observable
        if data.get("ip_info"):
            bundle_objects.extend(
                self._convert_related_ips(
                    ip_info=data.get("ip_info"),
                    observable_id=stix_observable.id,
                    labels=["phishing"],
                )
            )

        return bundle_objects

    def convert_malicious_to_stix(self, data) -> list[stix2.v21._STIXBase21]:
        """
        Convert malicious IOC into STIX entities (indicator and related observables)
        :param data: Raw malicious data from Zvelo
        :return: List of STIX 2.1 objects and relationships
        """
        bundle_objects = []

        # create URL observable
        stix_observable = stix2.URL(
            value=data.get("url"),
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
                "x_opencti_score": data.get("confidence_level"),
                "labels": ["malicious"],
            },
        )
        # create STIX indicator
        url_value = data.get("url").replace("'", "\\'")  # single quotes must be escaped
        pattern_value = "[url:value = '" + url_value + "']"
        observable_type = "Url"

        # create an indicator for the ioc
        stix_indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern_value),
            name=data.get("url"),
            created_by_ref=self.author["id"],
            confidence=data.get("confidence_level"),
            pattern_type="stix",
            labels=["phishing"],
            valid_from=parse(data.get("discovered_date")),
            created=parse(data.get("discovered_date")),
            pattern=pattern_value,
            external_references=[],
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": data.get("confidence_level"),
                "x_opencti_main_observable_type": observable_type,
            },
        )

        # create relation between observable and indicator
        stix_relationship = self._create_relation(
            stix_indicator.id, stix_observable.id, "based-on"
        )

        # add objects in the bundle objects
        bundle_objects.append(stix_indicator)
        bundle_objects.append(stix_observable)
        bundle_objects.append(stix_relationship)

        # create an IP observable and create a relation with the main observable
        if data.get("ip_info"):
            bundle_objects.extend(
                self._convert_related_ips(
                    ip_info=data.get("ip_info"),
                    observable_id=stix_observable.id,
                    labels=["malicious"],
                )
            )

        return bundle_objects
