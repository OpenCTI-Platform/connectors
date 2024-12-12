import ipaddress

import stix2
from dateutil.parser import parse
from pycti import Identity, StixCoreRelationship, Indicator, Malware


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper):
        self.helper = helper
        self.author = self.create_author()
        self.tlp = stix2.TLP_AMBER

    @staticmethod
    def create_author() -> dict:
        """
        Create Author
        :return: Author in Stix2 object
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

    def _convert_related_ips(self, ip_info, observable_id, labels):
        """
        :param ip_info:
        :param observable_id:
        :param labels:
        :return:
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
            else:
                stix_related_ip_observable = stix2.IPv6Address(
                    value=ip_address.get("ip"),
                    object_marking_refs=[self.tlp],
                    custom_properties={
                        "x_opencti_created_by_ref": self.author["id"],
                        "labels": labels,
                    },
                )

            stix_relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to",
                    observable_id,
                    stix_related_ip_observable.id,
                ),
                relationship_type="related-to",
                source_ref=observable_id,
                target_ref=stix_related_ip_observable.id,
                object_marking_refs=[self.tlp],
            )
            stix_objects.append(stix_related_ip_observable)
            stix_objects.append(stix_relationship)
        return stix_objects

    def _create_relation(self, source_id, target_id, relation):
        """
        :param source_id:
        :param target_id:
        :param relation:
        :return:
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

    def convert_threat_to_stix(self, data):
        bundle_objects = []
        if data.get("ioc_type", None) == "url":
            # create URL observable
            stix_observable = stix2.URL(
                value=data.get("ioc"),
                object_marking_refs=[self.tlp],
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_score": data.get("confidence_level"),
                    "labels": [data.get("threat_type", None)],
                },
            )
            # create STIX indicator
            pattern_value = "[url:value = '" + data.get("ioc") + "']"
            observable_type = "Url"

        elif data.get("ioc_type", None) == "domain":
            # create domain observable
            stix_observable = stix2.DomainName(
                value=data.get("ioc"),
                object_marking_refs=[self.tlp],
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_score": data.get("confidence_level"),
                    "labels": [data.get("threat_type", None)],
                },
            )
            # create STIX indicator
            pattern_value = "[domain-name:value = '" + data.get("ioc") + "']"
            observable_type = "Domain-Name"

        elif data.get("ioc_type", None) == "ip":
            if ":" in data.get("ioc"):
                ip_value = data.get("ioc").split(":")[0]
                description = f"Traffic seen on port {data.get("ioc").split(":")[1]}"
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
                        "labels": [data.get("threat_type", None)],
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
                        "labels": [data.get("threat_type", None)],
                    },
                )
                # create STIX indicator
                pattern_value = "[ipv6-addr:value = '" + ip_value + "']"
                observable_type = "IPv6-Addr"

        else:
            self.helper.log_warning(
                f"Unrecognized ioc_type: {data.get("ioc_type", None)}"
            )
            return None

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
        if data.get("malware_family", None):
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
                    labels=[data.get("threat_type", None)],
                )
            )

        return bundle_objects

    def convert_phish_to_stix(self, data):
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
        pattern_value = "[url:value = '" + data.get("url") + "']"
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

    def convert_malicious_to_stix(self, data):
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
        pattern_value = "[url:value = '" + data.get("url") + "']"
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
