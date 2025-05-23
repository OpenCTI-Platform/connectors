"""
############################## TERMS OF USE ####################################
# The following code is provided for demonstration purposes only, and should   #
# not be used without independent verification. Group-IB makes no              #
# representations or warranties, express, implied, statutory, or otherwise,    #
# regarding this code, and provides it strictly "as-is".                       #
# Group-IB shall not be liable for, and you assume all risk of                 #
# using the foregoing.                                                         #
################################################################################
Author: Pavel Reshetnikov, Integration developer, 2024
"""

import ipaddress
from datetime import datetime, timedelta

import data_to_stix2 as ds
from stix2.patterns import HashConstant


class DataToSTIXAdapter:

    def __init__(self, mitre_mapper, collection, tlp_color, helper, is_ioc=False):
        # type: (dict, str, str, Any, bool) -> None

        self.mitre_mapper = mitre_mapper
        self.collection = collection
        self.helper = helper
        self.ta_global_label = self._set_global_label(self.collection)
        self.tlp_color = tlp_color
        self.is_ioc = is_ioc
        self.helper.connector_logger.info("Initializing DataToSTIXAdapter")
        self.author = ds.BaseEntity("", "", "white").author
        self.helper.connector_logger.info(
            f"DataToSTIXAdapter initialized with collection: {collection}, tlp_color: {tlp_color}, is_ioc: {is_ioc}"
        )

    @staticmethod
    def is_ipv4(ipv4):
        # type: (str) -> bool
        """Determine whether the provided IP string is IPv4."""
        try:
            ipaddress.IPv4Address(ipv4)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def is_ipv6(ipv6):
        # type: (str) -> bool
        """Determine whether the provided IP string is IPv6."""
        try:
            ipaddress.IPv6Address(ipv6)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _valid_hash(hash_value, hash_type):
        try:
            HashConstant(value=hash_value, type=hash_type)
            return True
        except ValueError:
            return False

    def _set_global_label(self, collection):
        self.helper.connector_logger.info(
            f"Setting global label for collection: {collection}"
        )
        if collection in ["apt/threat", "apt/threat_actor"]:
            self.helper.connector_logger.debug("Collection identified as nation-state")
            return "nation-state"
        elif collection in ["hi/threat", "hi/threat_actor"]:
            self.helper.connector_logger.debug("Collection identified as criminal")
            return "criminal"
        self.helper.connector_logger.warning(
            f"No global label set for collection: {collection}"
        )
        return None

    @staticmethod
    def _retrieve_link(obj):
        # type: (Union[dict, list]) -> List[Tuple[str, str, str]]
        if isinstance(obj, list):
            result = list()
            for _o in obj:
                _link = _o.get("portal_link", {})
                if _link:
                    link_id = _link.get("dynamic")
                    link_url = _link.get("result")
                    link_description = _link.get("__")
                    result.append((link_id, link_url, link_description))
            return result
        else:
            result = list()
            _link = obj.get("portal_link", {})
            if _link:
                link_id = _link.get("dynamic")
                link_url = _link.get("result")
                link_description = _link.get("__")
                result.append((link_id, link_url, link_description))
            return result

    def _retrieve_date(self, obj, key, alter_key=None):
        # type: (dict, str, str) -> datetime
        self.helper.connector_logger.debug(
            f"Retrieving date for key: {key}, alternate key: {alter_key}"
        )
        date_raw = obj.get(key, "")
        if not date_raw and alter_key:
            date_raw = obj.get(alter_key, "")

        if date_raw:
            if date_raw.startswith("00"):
                self.helper.connector_logger.warning(
                    f"Wrong format of date: {date_raw}"
                )
                return datetime.now()

        try:
            _datetime = datetime.fromisoformat(date_raw)
            self.helper.connector_logger.debug(f"Successfully parsed date: {date_raw}")
        except (Exception,):
            self.helper.connector_logger.warning(
                f"Failed to format date: {date_raw}. Using default."
            )
            _datetime = datetime.now()

        return _datetime

    def _retrieve_ttl_dates(self, obj):
        # type: (dict) -> Tuple[Optional[datetime], Optional[datetime]]
        """
        :returns: (valid_from, valid_until)
        """
        self.helper.connector_logger.debug("Retrieving TTL dates")
        ttl = obj.get("ttl")
        if not ttl:
            ttl = 365
            self.helper.connector_logger.debug(
                "No TTL provided, using default: 365 days"
            )

        # try to extract date-modified
        date_modified_raw = obj.get("date-modified", "")
        date_created_raw = obj.get("date-created", "")

        if date_modified_raw:
            if date_modified_raw.startswith("00"):
                self.helper.connector_logger.warning(
                    f"Wrong format of date_modified: {date_modified_raw}"
                )
                date_modified_raw = None

        if date_created_raw:
            if date_created_raw.startswith("00"):
                self.helper.connector_logger.warning(
                    f"Wrong format of date_created: {date_created_raw}"
                )
                date_created_raw = None

        if not date_modified_raw and not date_created_raw:
            self.helper.connector_logger.warning(
                "No correct date found. "
                "'None' will be used to further set the value by the user or system"
            )
            base_ttl_datetime = None
        else:
            if date_modified_raw:
                base_ttl_raw_date = date_modified_raw
            else:
                base_ttl_raw_date = date_created_raw

            try:
                base_ttl_datetime = datetime.fromisoformat(base_ttl_raw_date)
                self.helper.connector_logger.debug(
                    f"Successfully parsed base TTL date: {base_ttl_raw_date}"
                )
            except (Exception,):
                self.helper.connector_logger.warning(
                    f"Failed to format base_ttl_raw_date: {base_ttl_raw_date}. "
                    "'None' will be used to further set the value by the user or system."
                )
                base_ttl_datetime = None

        valid_from = base_ttl_datetime
        valid_until = (
            base_ttl_datetime + timedelta(days=ttl)
            if base_ttl_datetime
            else base_ttl_datetime
        )
        self.helper.connector_logger.info(
            f"TTL dates set: valid_from={valid_from}, valid_until={valid_until}"
        )
        return valid_from, valid_until

    @staticmethod
    def _generate_relations(
        main_obj, related_objects, helper, relation_type=None, is_ioc=False
    ):
        # type: (Any, List[Any], Union[None, str], bool) -> Any

        relation_type_map = {
            "threat-actor": {
                # SDO
                "attack-pattern": "uses",
                "malware": "uses",
                "vulnerability": "targets",
                # Common
                "base-location": "located-at",
                "target-location": "targets",
            },
            "intrusion-set": {
                # SDO
                "attack-pattern": "uses",
                "malware": "uses",
                "vulnerability": "targets",
                # Common
                "base-location": "originates-from",
                "target-location": "targets",
                # Threat
                "threat-actor": "attributed-to",
            },
            "indicator": {
                # Observable
                "file": "based-on",
                "domain-name": "based-on",
                "url": "based-on",
                "ipv4-addr": "based-on",
                "ipv6-addr": "based-on",
                "email-addr": "based-on",
                # Threat
                "threat-actor": "indicates",
                "intrusion-set": "indicates",
            },
            "ipv4-addr": {
                # SDO
                "threat-actor": "related-to",
                "intrusion-set": "related-to",
                # Observable
                "domain-name": "related-to",
                "url": "related-to",
            },
            "ipv6-addr": {
                # SDO
                "threat-actor": "related-to",
                "intrusion-set": "related-to",
                # Observable
                "domain-name": "related-to",
                "url": "related-to",
            },
            "domain-name": {
                # SDO
                "threat-actor": "related-to",
                "intrusion-set": "related-to",
            },
            "url": {
                # SDO
                "threat-actor": "related-to",
                "intrusion-set": "related-to",
            },
            "file": {
                # SDO
                "threat-actor": "related-to",
                "intrusion-set": "related-to",
            },
            "vulnerability": {},
            "report": {},
            "malware": {
                # Observable
                "ipv4-addr": "communicates-with",
                "ipv6-addr": "communicates-with",
            },
            "yara": {
                # SDO
                "malware": "indicates"
            },
            "suricata": {
                # SDO
                "malware": "indicates"
            },
            "email-addr": {
                # Observable
                "file": "related-to"
            },
        }

        def _gen_rel(
            mo, mo_type, ro, ro_type, gen_rel_processor=main_obj.generate_relationship
        ):
            r_type = relation_type_map.get(mo_type, {}).get(ro_type, None)
            if not r_type:
                raise AttributeError(
                    f"No relation type defined. Main object type: [{mo_type}], "
                    f"Related object type: {ro_type}, Relation type: {relation_type}"
                )
            gen_rel_processor(
                mo,
                ro,
                relation_type=r_type,
            )

        _main_object = main_obj.stix_main_object
        _main_object_c_type = main_obj.c_type
        helper.connector_logger.debug(
            f"Generating relations for main object type: {_main_object_c_type}, is_ioc: {is_ioc}"
        )

        # generate relationship: Indicator --based-on--> Observable
        if (
            is_ioc
            and main_obj.stix_indicator
            and main_obj.c_type not in ["yara", "suricata"]
        ):
            _indicator = main_obj.stix_indicator
            helper.connector_logger.debug(
                f"Processing indicator relationships for {_main_object_c_type}"
            )

            if isinstance(_indicator, list):
                for _ind in _indicator:
                    helper.connector_logger.debug(
                        f"Generating relationship: {_ind.type} -> {_main_object_c_type}"
                    )
                    _gen_rel(_ind, _ind.type, _main_object, _main_object_c_type)
            else:
                helper.connector_logger.debug(
                    f"Generating relationship: {_indicator.type} -> {_main_object_c_type}"
                )
                _gen_rel(_indicator, _indicator.type, _main_object, _main_object_c_type)

        if not related_objects:
            helper.connector_logger.debug(
                "No related objects provided for relationship generation"
            )
            return main_obj

        for _rel_obj in related_objects:
            if _rel_obj:
                if isinstance(_rel_obj, list) and _rel_obj:
                    for _ro in _rel_obj:
                        # generate relationship: Indicator --indicates--> Threat
                        if (
                            is_ioc
                            and main_obj.stix_indicator
                            and _ro.c_type in ["threat-actor", "intrusion-set"]
                        ):
                            _indicator = main_obj.stix_indicator
                            if isinstance(_indicator, list):
                                for _ind in _indicator:
                                    helper.connector_logger.debug(
                                        f"Generating indicator-threat relationship: {_ind.type} -> {_ro.c_type}"
                                    )
                                    _gen_rel(
                                        _ind,
                                        _ind.type,
                                        _ro.stix_main_object,
                                        _ro.c_type,
                                    )
                            else:
                                helper.connector_logger.debug(
                                    f"Generating indicator-threat relationship: {_indicator.type} -> {_ro.c_type}"
                                )
                                _gen_rel(
                                    _indicator,
                                    _indicator.type,
                                    _ro.stix_main_object,
                                    _ro.c_type,
                                )
                        # generate relationship:
                        # - Observable --related-to--> Threat
                        # - Observable/SDO/Threat/Common --any--> Any
                        else:
                            helper.connector_logger.debug(
                                f"Generating relationship: {_main_object_c_type} -> {_ro.c_type}"
                            )
                            _gen_rel(
                                _main_object,
                                _main_object_c_type,
                                _ro.stix_main_object,
                                _ro.c_type,
                            )
                else:

                    if (
                        is_ioc
                        and main_obj.stix_indicator
                        and _rel_obj.c_type in ["threat-actor", "intrusion-set"]
                    ):
                        _indicator = main_obj.stix_indicator
                        if isinstance(_indicator, list):
                            for _ind in _indicator:
                                helper.connector_logger.debug(
                                    f"Generating indicator-threat relationship: {_ind.type} -> {_rel_obj.c_type}"
                                )
                                _gen_rel(
                                    _ind,
                                    _ind.type,
                                    _rel_obj.stix_main_object,
                                    _rel_obj.c_type,
                                )
                        else:
                            helper.connector_logger.debug(
                                f"Generating indicator-threat relationship: {_indicator.type} -> {_rel_obj.c_type}"
                            )
                            _gen_rel(
                                _indicator,
                                _indicator.type,
                                _rel_obj.stix_main_object,
                                _rel_obj.c_type,
                            )

                    else:
                        helper.connector_logger.debug(
                            f"Generating relationship: {_main_object_c_type} -> {_rel_obj.c_type}"
                        )
                        _gen_rel(
                            _main_object,
                            _main_object_c_type,
                            _rel_obj.stix_main_object,
                            _rel_obj.c_type,
                        )

        helper.connector_logger.info(
            f"Completed generating relations for main object type: {_main_object_c_type}"
        )
        return main_obj

    def _generate_mitre_matrix(self, obj_events):
        self.helper.connector_logger.debug("Generating MITRE matrix")
        mitre_matrix = {
            _e.get("attack_pattern"): {
                "kill_chain_phases": list(),
                "portal_links": list(),
            }
            for _e in obj_events
            if _e.get("attack_pattern")
        }
        for _e in obj_events:
            if _e.get("attack_pattern"):
                mitre_matrix[_e.get("attack_pattern")]["kill_chain_phases"].append(
                    _e.get("kill_chain_phase")
                )
                mitre_matrix[_e.get("attack_pattern")]["portal_links"] = (
                    self._retrieve_link(_e)
                )
        self.helper.connector_logger.debug(
            f"MITRE matrix generated with {len(mitre_matrix)} attack patterns"
        )
        return mitre_matrix

    def generate_kill_chain_phases(self, obj_types):
        self.helper.connector_logger.debug(
            f"Generating kill chain phases for types: {obj_types}"
        )
        _name = "mitre-attack"
        _label = "mitre"

        kill_chain_phases = [
            ds.KillChainPhase(
                name=_name,
                c_type=_type,
                # tlp_color=self.tlp_color,
                labels=[self.collection, _label],
            )
            .generate_stix_objects()
            .stix_main_object
            for _type in obj_types
        ]
        self.helper.connector_logger.info(
            f"Generated {len(kill_chain_phases)} kill chain phases"
        )
        return kill_chain_phases

    def generate_stix_domain(self, name):
        self.helper.connector_logger.debug(
            f"Generating STIX domain object for name: {name}"
        )
        _type = "domain-name"
        # _label = "domain"

        domain = ds.Domain(
            name=name,
            c_type=_type,
            tlp_color=self.tlp_color,
            labels=[self.collection],
        )
        self.helper.connector_logger.info(f"STIX domain object generated for: {name}")
        return domain

    def generate_stix_url(self, name):
        self.helper.connector_logger.debug(
            f"Generating STIX URL object for name: {name}"
        )
        _type = "url"
        # _label = "url"

        url = ds.URL(
            name=name,
            c_type=_type,
            tlp_color=self.tlp_color,
            labels=[self.collection],
        )
        self.helper.connector_logger.info(f"STIX URL object generated for: {name}")
        return url

    def generate_stix_ipv4(self, name):
        self.helper.connector_logger.debug(
            f"Generating STIX IPv4 object for name: {name}"
        )
        _type = "ipv4-addr"
        # _label = "ipv4"

        ip = ds.IPAddress(
            name=name,
            c_type=_type,
            tlp_color=self.tlp_color,
            labels=[self.collection],
        )
        self.helper.connector_logger.info(f"STIX IPv4 object generated for: {name}")
        return ip

    def generate_locations(self, obj_country_codes, change_type_to=None):
        self.helper.connector_logger.debug(
            f"Generating locations for country codes: {obj_country_codes}, change_type_to: {change_type_to}"
        )
        _type = "location"
        if change_type_to:
            _type = change_type_to
        # _label = "country"

        locations = [
            ds.Location(
                name=_cc,
                c_type=_type,
                tlp_color=self.tlp_color,
                labels=[self.collection],
            ).generate_stix_objects()
            for _cc in obj_country_codes
            if _cc
        ]
        self.helper.connector_logger.info(
            f"Generated {len(locations)} location objects"
        )
        return locations

    def generate_stix_malware(self, obj, json_date_obj=None):
        self.helper.connector_logger.info("Starting generation of STIX malware objects")
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for malware generation"
            )
            return list()

        _description = obj.get("__")
        _type = "malware"
        # _label = "malware"
        _events = obj.get("malware_report_list", [])

        # _date_updated = self._retrieve_date(
        #    json_date_obj, "date-updated", "date-modified"
        # )

        _stix_objects = list()

        if _events:
            self.helper.connector_logger.debug(
                f"Processing {len(_events)} malware events"
            )
            for _e in _events:
                _name = _e.get("name")
                _malware_types = _e.get("category")
                _malware_aliases = _e.get("aliases")

                _portal_links = self._retrieve_link(_e)

                if _name:
                    if isinstance(_name, list):
                        self.helper.connector_logger.debug(
                            f"Processing list of malware names: {_name}"
                        )
                        for n in _name:
                            malware = ds.Malware(
                                name=n,
                                aliases=_malware_aliases,
                                # last_seen=_date_updated,
                                c_type=_type,
                                malware_types=_malware_types or [],
                                tlp_color="red",
                                labels=[self.collection],
                            )
                            malware.set_description(_description)
                            malware.generate_external_references(_portal_links)
                            malware.generate_stix_objects()
                            self.helper.connector_logger.debug(
                                f"Generated STIX malware object for name: {n}"
                            )

                            _stix_objects.append(malware)
                    else:
                        malware = ds.Malware(
                            name=_name,
                            aliases=_malware_aliases,
                            # last_seen=_date_updated,
                            c_type=_type,
                            malware_types=_malware_types,
                            tlp_color="red",
                            labels=[self.collection],
                        )
                        malware.set_description(_description)
                        malware.generate_external_references(_portal_links)
                        malware.generate_stix_objects()
                        self.helper.connector_logger.debug(
                            f"Generated STIX malware object for name: {_name}"
                        )

                        _stix_objects.append(malware)

        else:
            _name = obj.get("name")
            _malware_types = obj.get("category")
            _malware_aliases = obj.get("aliases")

            _portal_links = self._retrieve_link(obj)

            if _name:
                malware = ds.Malware(
                    name=_name,
                    aliases=_malware_aliases,
                    # last_seen=_date_updated,
                    c_type=_type,
                    malware_types=_malware_types,
                    tlp_color="red",
                    labels=[self.collection],
                )
                malware.set_description(_description)
                malware.generate_external_references(_portal_links)
                malware.generate_stix_objects()
                self.helper.connector_logger.debug(
                    f"Generated STIX malware object for name: {_name}"
                )

                _stix_objects.append(malware)

        self.helper.connector_logger.info(
            f"Generated {len(_stix_objects)} STIX malware objects"
        )
        return _stix_objects

    def generate_stix_vulnerability(
        self, obj, related_objects, json_date_obj=None, json_cvss_obj=None
    ):
        self.helper.connector_logger.info(
            "Starting generation of STIX vulnerability objects"
        )
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for vulnerability generation"
            )
            return list()

        _description = obj.get("__")
        _type = "vulnerability"
        # _label = "vulnerability"
        if json_cvss_obj:
            _cvssv3_score = json_cvss_obj.get("score", None)
            _cvssv3_vector = json_cvss_obj.get("vector", None)
            self.helper.connector_logger.debug(
                f"CVSS score: {_cvssv3_score}, vector: {_cvssv3_vector}"
            )
        else:
            _cvssv3_score = None
            _cvssv3_vector = None
        _events = obj.get("vulnerability_list", [])

        _date_published = self._retrieve_date(json_date_obj, "date-published")

        _stix_objects = list()

        if _events:
            self.helper.connector_logger.debug(
                f"Processing {len(_events)} vulnerability events"
            )
            for _e in _events:
                _name = _e.get("object_id")
                _description = _e.get("description")

                if _name:
                    if isinstance(_name, list):
                        self.helper.connector_logger.debug(
                            f"Processing list of vulnerability names: {_name}"
                        )
                        for n in _name:
                            vulnerability = ds.Vulnerability(
                                name=n,
                                c_type=_type,
                                created=_date_published,
                                cvss_score=_cvssv3_score,
                                cvss_vector=_cvssv3_vector,
                                tlp_color=self.tlp_color,
                                labels=[self.collection],
                            )
                            vulnerability.set_description(_description)
                            vulnerability.generate_stix_objects()
                            self.helper.connector_logger.debug(
                                f"Generated STIX vulnerability object for name: {n}"
                            )

                            self._generate_relations(
                                main_obj=vulnerability,
                                related_objects=related_objects,
                                helper=self.helper,
                            )

                            vulnerability.add_relationships_to_stix_objects()

                            _stix_objects.append(vulnerability)
                    else:
                        vulnerability = ds.Vulnerability(
                            name=_name,
                            c_type=_type,
                            created=_date_published,
                            cvss_score=_cvssv3_score,
                            cvss_vector=_cvssv3_vector,
                            tlp_color=self.tlp_color,
                            labels=[self.collection],
                        )
                        vulnerability.set_description(_description)
                        vulnerability.generate_stix_objects()
                        self.helper.connector_logger.debug(
                            f"Generated STIX vulnerability object for name: {_name}"
                        )

                        self._generate_relations(
                            main_obj=vulnerability,
                            related_objects=related_objects,
                            helper=self.helper,
                        )

                        vulnerability.add_relationships_to_stix_objects()

                        _stix_objects.append(vulnerability)

        else:
            _name = obj.get("object_id")
            _description = obj.get("description")

            if _name:
                vulnerability = ds.Vulnerability(
                    name=_name,
                    c_type=_type,
                    created=_date_published,
                    cvss_score=_cvssv3_score,
                    cvss_vector=_cvssv3_vector,
                    tlp_color=self.tlp_color,
                    labels=[self.collection],
                )
                vulnerability.set_description(_description)
                vulnerability.generate_stix_objects()
                self.helper.connector_logger.debug(
                    f"Generated STIX vulnerability object for name: {_name}"
                )

                self._generate_relations(
                    main_obj=vulnerability,
                    related_objects=related_objects,
                    helper=self.helper,
                )

                vulnerability.add_relationships_to_stix_objects()

                _stix_objects.append(vulnerability)

        self.helper.connector_logger.info(
            f"Generated {len(_stix_objects)} STIX vulnerability objects"
        )
        return _stix_objects

    def generate_stix_attack_pattern(self, obj):
        self.helper.connector_logger.info(
            "Starting generation of STIX attack pattern objects"
        )
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for attack pattern generation"
            )
            return list()

        _description = obj.get("__")
        _type = "attack-pattern"
        # _label = "attack_pattern"
        _events = obj.get("mitre_matrix_list")

        _stix_objects = list()

        event_mitre_matrix = self._generate_mitre_matrix(_events)

        for k, v in event_mitre_matrix.items():

            kill_chain_phases = self.generate_kill_chain_phases(v["kill_chain_phases"])

            if k:
                attack_pattern = ds.AttackPattern(
                    name=self.mitre_mapper.get(k),
                    c_type=_type,
                    mitre_id=k,
                    kill_chain_phases=kill_chain_phases,
                    # tlp_color=self.tlp_color,
                    labels=[self.collection],
                )
                attack_pattern.set_description(_description)
                attack_pattern.generate_external_references(v["portal_links"])
                attack_pattern.generate_stix_objects()
                self.helper.connector_logger.debug(
                    f"Generated STIX attack pattern object for MITRE ID: {k}"
                )

                _stix_objects.append(attack_pattern)

        self.helper.connector_logger.info(
            f"Generated {len(_stix_objects)} STIX attack pattern objects"
        )
        return _stix_objects

    def generate_stix_threat_actor(self, obj, related_objects, json_date_obj=None):
        self.helper.connector_logger.info(
            "Starting generation of STIX threat actor objects"
        )
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for threat actor generation"
            )
            return None, None

        _type = "threat-actor"
        # _label = "threat_actor"
        _global_label = self.ta_global_label
        # _country_type = "country"

        _threat_actor_name = obj.get("name")
        _threat_actor_country = obj.get("country")
        _threat_actor_targeted_countries = obj.get("targeted_countries")
        _threat_actor_aliases = obj.get("aliases")
        _threat_actor_description = obj.get("description")
        _threat_actor_goals = obj.get("goals")
        _threat_actor_roles = obj.get("roles")

        # _date_first_seen = self._retrieve_date(json_date_obj, "first-seen")
        # _date_last_seen = self._retrieve_date(json_date_obj, "last-seen")

        _portal_link = self._retrieve_link(obj)

        threat_actor = None
        locations = None

        if _threat_actor_name and len(_threat_actor_name) > 2:
            self.helper.connector_logger.debug(
                f"Generating threat actor for name: {_threat_actor_name}"
            )
            threat_actor = ds.ThreatActor(
                name=_threat_actor_name,
                c_type=_type,
                global_label=_global_label,
                tlp_color="red",
                labels=[self.collection],
                aliases=_threat_actor_aliases,
                # first_seen=_date_first_seen,
                # last_seen=_date_last_seen,
                goals=_threat_actor_goals,
                roles=_threat_actor_roles,
            )
            threat_actor.set_description(_threat_actor_description)
            threat_actor.generate_external_references(_portal_link)
            threat_actor.generate_stix_objects()
            self.helper.connector_logger.debug(
                f"Generated STIX threat actor object for name: {_threat_actor_name}"
            )

            base_locations = []
            if _threat_actor_country:
                base_locations = self.generate_locations(
                    [_threat_actor_country], change_type_to="base-location"
                )
                self.helper.connector_logger.debug(
                    f"Generated {len(base_locations)} base locations"
                )
            target_locations = []
            if _threat_actor_targeted_countries:
                target_locations = self.generate_locations(
                    _threat_actor_targeted_countries, change_type_to="target-location"
                )
                self.helper.connector_logger.debug(
                    f"Generated {len(target_locations)} target locations"
                )

            locations = base_locations + target_locations

            if _threat_actor_name and base_locations:
                self._generate_relations(
                    main_obj=threat_actor,
                    related_objects=base_locations,
                    helper=self.helper,
                )
                self.helper.connector_logger.debug(
                    "Generated relations for base locations"
                )

            if _threat_actor_name and target_locations:
                self._generate_relations(
                    main_obj=threat_actor,
                    related_objects=target_locations,
                    helper=self.helper,
                )
                self.helper.connector_logger.debug(
                    "Generated relations for target locations"
                )

            self._generate_relations(
                main_obj=threat_actor,
                related_objects=related_objects,
                helper=self.helper,
            )
            self.helper.connector_logger.debug(
                "Generated relations for related objects"
            )

            threat_actor.add_relationships_to_stix_objects()
            self.helper.connector_logger.debug(
                "Added relationships to STIX threat actor objects"
            )

        self.helper.connector_logger.info(
            "Completed generation of STIX threat actor objects"
        )
        return threat_actor, locations

    def generate_stix_intrusion_set(self, obj, related_objects, json_date_obj=None):
        self.helper.connector_logger.info(
            "Starting generation of STIX intrusion set objects"
        )
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for intrusion set generation"
            )
            return None, None

        _type = "intrusion-set"
        # _label = "threat_actor"
        _global_label = self.ta_global_label
        # _country_type = "country"

        _intrusion_set_name = obj.get("name")
        _intrusion_set_country = obj.get("country")
        _intrusion_set_targeted_countries = obj.get("targeted_countries")
        _intrusion_set_aliases = obj.get("aliases")
        _intrusion_set_description = obj.get("description")
        _intrusion_set_goals = obj.get("goals")
        _intrusion_set_roles = obj.get("roles")

        # _date_first_seen = self._retrieve_date(json_date_obj, "first-seen")
        # _date_last_seen = self._retrieve_date(json_date_obj, "last-seen")

        _portal_link = self._retrieve_link(obj)

        intrusion_set = None
        locations = None

        if _intrusion_set_name and len(_intrusion_set_name) > 2:
            self.helper.connector_logger.debug(
                f"Generating intrusion set for name: {_intrusion_set_name}"
            )
            intrusion_set = ds.IntrusionSet(
                name=_intrusion_set_name,
                c_type=_type,
                global_label=_global_label,
                tlp_color="red",
                labels=[self.collection],
                aliases=_intrusion_set_aliases,
                # first_seen=_date_first_seen,
                # last_seen=_date_last_seen,
                goals=_intrusion_set_goals,
                roles=_intrusion_set_roles,
            )
            intrusion_set.set_description(_intrusion_set_description)
            intrusion_set.generate_external_references(_portal_link)
            intrusion_set.generate_stix_objects()
            self.helper.connector_logger.debug(
                f"Generated STIX intrusion set object for name: {_intrusion_set_name}"
            )

            base_locations = []
            if _intrusion_set_country:
                base_locations = self.generate_locations(
                    [_intrusion_set_country], change_type_to="base-location"
                )
                self.helper.connector_logger.debug(
                    f"Generated {len(base_locations)} base locations"
                )
            target_locations = []
            if _intrusion_set_targeted_countries:
                target_locations = self.generate_locations(
                    _intrusion_set_targeted_countries, change_type_to="target-location"
                )
                self.helper.connector_logger.debug(
                    f"Generated {len(target_locations)} target locations"
                )

            locations = base_locations + target_locations

            if _intrusion_set_name and base_locations:
                self._generate_relations(
                    main_obj=intrusion_set,
                    related_objects=base_locations,
                    helper=self.helper,
                )
                self.helper.connector_logger.debug(
                    "Generated relations for base locations"
                )

            if _intrusion_set_name and target_locations:
                self._generate_relations(
                    main_obj=intrusion_set,
                    related_objects=target_locations,
                    helper=self.helper,
                )
                self.helper.connector_logger.debug(
                    "Generated relations for target locations"
                )

            self._generate_relations(
                main_obj=intrusion_set,
                related_objects=related_objects,
                helper=self.helper,
            )
            self.helper.connector_logger.debug(
                "Generated relations for related objects"
            )

            intrusion_set.add_relationships_to_stix_objects()
            self.helper.connector_logger.debug(
                "Added relationships to STIX intrusion set objects"
            )

        self.helper.connector_logger.info(
            "Completed generation of STIX intrusion set objects"
        )
        return intrusion_set, locations

    def generate_stix_file(
        self, obj, json_date_obj=None, related_objects=None, file_is_ioc=True
    ):
        self.helper.connector_logger.info("Starting generation of STIX file objects")
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for file generation"
            )
            return list()

        _description = obj.get("__")
        _type = "file"
        # _label = "file"
        _events = obj.get("file_list")

        valid_from, valid_until = self._retrieve_ttl_dates(json_date_obj)

        _stix_objects = list()

        if _events:
            self.helper.connector_logger.debug(f"Processing {len(_events)} file events")
            for _e in _events:
                _md5 = _e.get("md5", None)
                _sha1 = _e.get("sha1", None)
                _sha256 = _e.get("sha256", None)
                if _md5:
                    if not self._valid_hash(_md5, "MD5"):
                        self.helper.connector_logger.error(
                            f"Error! {_md5} is not valid MD5. Ignored."
                        )
                        _md5 = None
                if _sha1:
                    if not self._valid_hash(_sha1, "SHA1"):
                        self.helper.connector_logger.error(
                            f"Error! {_sha1} is not valid SHA1. Ignored."
                        )
                        _sha1 = None
                if _sha256:
                    if not self._valid_hash(_sha256, "SHA256"):
                        self.helper.connector_logger.error(
                            f"Error! {_sha256} is not valid SHA256. Ignored."
                        )
                        _sha256 = None
                hashes = [_md5, _sha1, _sha256]
                self.helper.connector_logger.debug(
                    f"Processing file hashes: MD5={_md5}, SHA1={_sha1}, SHA256={_sha256}"
                )

                if any(hashes):
                    file = ds.FileHash(
                        name=hashes,
                        c_type=_type,
                        tlp_color=self.tlp_color,
                        labels=[self.collection],
                    )
                    file.set_description(_description)
                    file.is_ioc = file_is_ioc
                    file.set_valid_from(valid_from)
                    file.set_valid_until(valid_until)
                    file.generate_stix_objects()
                    self.helper.connector_logger.debug("Generated STIX file object")

                    self._generate_relations(
                        main_obj=file,
                        related_objects=related_objects,
                        is_ioc=file_is_ioc,
                        helper=self.helper,
                    )
                    self.helper.connector_logger.debug(
                        "Generated relations for file object"
                    )

                    file.add_relationships_to_stix_objects()
                    self.helper.connector_logger.debug(
                        "Added relationships to STIX file object"
                    )

                    _stix_objects.append(file)

        else:
            _md5 = obj.get("md5", None)
            _sha1 = obj.get("sha1", None)
            _sha256 = obj.get("sha256", None)
            if _md5:
                if not self._valid_hash(_md5, "MD5"):
                    self.helper.connector_logger.error(
                        f"Error! {_md5} is not valid MD5. Ignored."
                    )
                    _md5 = None
            if _sha1:
                if not self._valid_hash(_sha1, "SHA1"):
                    self.helper.connector_logger.error(
                        f"Error! {_sha1} is not valid SHA1. Ignored."
                    )
                    _sha1 = None
            if _sha256:
                if not self._valid_hash(_sha256, "SHA256"):
                    self.helper.connector_logger.error(
                        f"Error! {_sha256} is not valid SHA256. Ignored."
                    )
                    _sha256 = None
            hashes = [_md5, _sha1, _sha256]
            self.helper.connector_logger.debug(
                f"Processing file hashes: MD5={_md5}, SHA1={_sha1}, SHA256={_sha256}"
            )

            if any(hashes):
                file = ds.FileHash(
                    name=hashes,
                    c_type=_type,
                    tlp_color=self.tlp_color,
                    labels=[self.collection],
                )
                file.set_description(_description)
                file.is_ioc = file_is_ioc
                file.set_valid_from(valid_from)
                file.set_valid_until(valid_until)
                file.generate_stix_objects()
                self.helper.connector_logger.debug("Generated STIX file object")

                self._generate_relations(
                    main_obj=file,
                    related_objects=related_objects,
                    is_ioc=file_is_ioc,
                    helper=self.helper,
                )
                self.helper.connector_logger.debug(
                    "Generated relations for file object"
                )

                file.add_relationships_to_stix_objects()
                self.helper.connector_logger.debug(
                    "Added relationships to STIX file object"
                )

                _stix_objects.append(file)

        self.helper.connector_logger.info(
            f"Generated {len(_stix_objects)} STIX file objects"
        )
        return _stix_objects

    def generate_stix_network(
        self,
        obj,
        json_date_obj=None,
        related_objects=None,
        url_is_ioc=False,
        domain_is_ioc=False,
        ip_is_ioc=False,
    ):
        self.helper.connector_logger.info("Starting generation of STIX network objects")
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for network generation"
            )
            return list(), list(), list()

        _description = obj.get("__")
        _events = obj.get("network_list", None)
        self.helper.connector_logger.debug(
            f"Processing network events: {len(_events) if _events else 0}"
        )

        valid_from, valid_until = self._retrieve_ttl_dates(json_date_obj)
        self.helper.connector_logger.debug(
            f"TTL dates for network objects: valid_from={valid_from}, valid_until={valid_until}"
        )

        _domain_stix_objects = list()
        _url_stix_objects = list()
        _ip_stix_objects = list()

        if _events:
            self.helper.connector_logger.debug(
                f"Processing {len(_events)} network events"
            )
            for _e in _events:
                _domain = _e.get("domain")
                _url = _e.get("url")
                _ips = _e.get("ip-address")
                self.helper.connector_logger.debug(
                    f"Processing event with domain: {_domain}, url: {_url}, ip-address: {_ips}"
                )
                domain = None

                if _domain:
                    self.helper.connector_logger.debug(f"Processing domain: {_domain}")
                    if self.is_ipv4(_domain):
                        self.helper.connector_logger.info(
                            f"Domain {_domain} identified as IPv4"
                        )
                        ip = self.generate_stix_ipv4(_domain)
                        ip.set_description(_description)
                        ip.is_ioc = domain_is_ioc
                        ip.set_valid_from(valid_from)
                        ip.set_valid_until(valid_until)
                        ip.generate_stix_objects()
                        self.helper.connector_logger.debug(
                            f"Generated STIX IPv4 object for: {_domain}"
                        )
                        self._generate_relations(
                            main_obj=ip,
                            related_objects=related_objects,
                            is_ioc=domain_is_ioc,
                            helper=self.helper,
                        )
                        self.helper.connector_logger.debug(
                            f"Generated relations for IPv4: {_domain}"
                        )
                        ip.add_relationships_to_stix_objects()
                        _ip_stix_objects.append(ip)
                        self.helper.connector_logger.debug(
                            "Added IPv4 object to IP list"
                        )
                    else:
                        domain = self.generate_stix_domain(_domain)
                        domain.is_ioc = domain_is_ioc
                        domain.set_valid_from(valid_from)
                        domain.set_valid_until(valid_until)
                        domain.generate_stix_objects()
                        self.helper.connector_logger.debug(
                            f"Generated STIX domain object for: {_domain}"
                        )
                        self._generate_relations(
                            main_obj=domain,
                            related_objects=related_objects,
                            is_ioc=domain_is_ioc,
                            helper=self.helper,
                        )
                        self.helper.connector_logger.debug(
                            f"Generated relations for domain: {_domain}"
                        )
                        domain.add_relationships_to_stix_objects()
                        _domain_stix_objects.append(domain)
                        self.helper.connector_logger.debug(
                            "Added domain object to domain list"
                        )

                url = None
                if _url:
                    self.helper.connector_logger.debug(f"Processing URL: {_url}")
                    url = self.generate_stix_url(_url)
                    url.is_ioc = url_is_ioc
                    url.set_valid_from(valid_from)
                    url.set_valid_until(valid_until)
                    link_id = "NoId"
                    link_url = _url
                    link_description = "Unknown: Source URL - external reference"
                    url.generate_external_references(
                        [(link_id, link_url, link_description)]
                    )
                    url.generate_stix_objects()
                    self.helper.connector_logger.debug(
                        f"Generated STIX URL object for: {_url}"
                    )
                    self._generate_relations(
                        main_obj=url,
                        related_objects=related_objects,
                        is_ioc=url_is_ioc,
                        helper=self.helper,
                    )
                    self.helper.connector_logger.debug(
                        f"Generated relations for URL: {_url}"
                    )
                    url.add_relationships_to_stix_objects()
                    _url_stix_objects.append(url)
                    self.helper.connector_logger.debug("Added URL object to URL list")

                if _ips:
                    self.helper.connector_logger.debug(f"Processing IPs: {_ips}")
                    for _ip in _ips:
                        ip = self.generate_stix_ipv4(_ip)
                        ip.set_description(_description)
                        ip.is_ioc = ip_is_ioc
                        ip.set_valid_from(valid_from)
                        ip.set_valid_until(valid_until)
                        ip.generate_stix_objects()
                        self.helper.connector_logger.debug(
                            f"Generated STIX IPv4 object for: {_ip}"
                        )
                        self._generate_relations(
                            main_obj=ip,
                            related_objects=related_objects,
                            is_ioc=ip_is_ioc,
                            helper=self.helper,
                        )
                        self.helper.connector_logger.debug(
                            f"Generated relations for IP: {_ip}"
                        )
                        if domain:
                            self._generate_relations(
                                main_obj=ip,
                                related_objects=[domain],
                                helper=self.helper,
                            )
                            self.helper.connector_logger.debug(
                                f"Generated relations between IP: {_ip} and domain: {_domain}"
                            )
                        if url:
                            self._generate_relations(
                                main_obj=ip, related_objects=[url], helper=self.helper
                            )
                            self.helper.connector_logger.debug(
                                f"Generated relations between IP: {_ip} and URL: {_url}"
                            )
                        ip.add_relationships_to_stix_objects()
                        _ip_stix_objects.append(ip)
                        self.helper.connector_logger.debug("Added IP object to IP list")

        else:
            _domain = obj.get("domain")
            _url = obj.get("url")
            _ip = obj.get("ip-address")
            self.helper.connector_logger.debug(
                f"Processing single network object: domain={_domain}, url={_url}, ip={_ip}"
            )
            domain = None

            if _domain:
                self.helper.connector_logger.debug(f"Processing domain: {_domain}")
                if self.is_ipv4(_domain):
                    self.helper.connector_logger.info(
                        f"Domain {_domain} identified as IPv4"
                    )
                    ip = self.generate_stix_ipv4(_domain)
                    ip.set_description(_description)
                    ip.is_ioc = domain_is_ioc
                    ip.set_valid_from(valid_from)
                    ip.set_valid_until(valid_until)
                    ip.generate_stix_objects()
                    self.helper.connector_logger.debug(
                        f"Generated STIX IPv4 object for: {_domain}"
                    )
                    self._generate_relations(
                        main_obj=ip,
                        related_objects=related_objects,
                        is_ioc=domain_is_ioc,
                        helper=self.helper,
                    )
                    self.helper.connector_logger.debug(
                        f"Generated relations for IPv4: {_domain}"
                    )
                    ip.add_relationships_to_stix_objects()
                    _ip_stix_objects.append(ip)
                    self.helper.connector_logger.debug("Added IPv4 object to IP list")
                else:
                    domain = self.generate_stix_domain(_domain)
                    domain.is_ioc = domain_is_ioc
                    domain.set_valid_from(valid_from)
                    domain.set_valid_until(valid_until)
                    domain.generate_stix_objects()
                    self.helper.connector_logger.debug(
                        f"Generated STIX domain object for: {_domain}"
                    )
                    self._generate_relations(
                        main_obj=domain,
                        related_objects=related_objects,
                        is_ioc=domain_is_ioc,
                        helper=self.helper,
                    )
                    self.helper.connector_logger.debug(
                        f"Generated relations for domain: {_domain}"
                    )
                    domain.add_relationships_to_stix_objects()
                    _domain_stix_objects.append(domain)
                    self.helper.connector_logger.debug(
                        "Added domain object to domain list"
                    )

            url = None
            if _url:
                self.helper.connector_logger.debug(f"Processing URL: {_url}")
                url = self.generate_stix_url(_url)
                url.is_ioc = url_is_ioc
                url.set_valid_from(valid_from)
                url.set_valid_until(valid_until)
                link_id = "NoId"
                link_url = _url
                link_description = "Unknown: Source URL - external reference"
                url.generate_external_references(
                    [(link_id, link_url, link_description)]
                )
                url.generate_stix_objects()
                self.helper.connector_logger.debug(
                    f"Generated STIX URL object for: {_url}"
                )
                self._generate_relations(
                    main_obj=url,
                    related_objects=related_objects,
                    is_ioc=url_is_ioc,
                    helper=self.helper,
                )
                self.helper.connector_logger.debug(
                    f"Generated relations for URL: {_url}"
                )
                url.add_relationships_to_stix_objects()
                _url_stix_objects.append(url)
                self.helper.connector_logger.debug("Added URL object to URL list")

            if _ip:
                self.helper.connector_logger.debug(f"Processing IP: {_ip}")
                ip = self.generate_stix_ipv4(_ip)
                ip.set_description(_description)
                ip.is_ioc = ip_is_ioc
                ip.set_valid_from(valid_from)
                ip.set_valid_until(valid_until)
                ip.generate_stix_objects()
                self.helper.connector_logger.debug(
                    f"Generated STIX IPv4 object for: {_ip}"
                )
                self._generate_relations(
                    main_obj=ip,
                    related_objects=related_objects,
                    is_ioc=ip_is_ioc,
                    helper=self.helper,
                )
                self.helper.connector_logger.debug(f"Generated relations for IP: {_ip}")
                if domain:
                    self._generate_relations(
                        main_obj=ip, related_objects=[domain], helper=self.helper
                    )
                    self.helper.connector_logger.debug(
                        f"Generated relations between IP: {_ip} and domain: {_domain}"
                    )
                if url:
                    self._generate_relations(
                        main_obj=ip, related_objects=[url], helper=self.helper
                    )
                    self.helper.connector_logger.debug(
                        f"Generated relations between IP: {_ip} and URL: {_url}"
                    )
                ip.add_relationships_to_stix_objects()
                _ip_stix_objects.append(ip)
                self.helper.connector_logger.debug("Added IP object to IP list")

        self.helper.connector_logger.info(
            f"Generated STIX network objects: {len(_domain_stix_objects)} domains, {len(_url_stix_objects)} URLs, {len(_ip_stix_objects)} IPs"
        )
        return _domain_stix_objects, _url_stix_objects, _ip_stix_objects

    def generate_stix_report(
        self,
        obj,
        json_date_obj,
        report_related_objects_ids,
        json_malware_report_obj,
        json_threat_actor_obj,
    ):
        self.helper.connector_logger.info("Starting generation of STIX report object")
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for report generation"
            )
            return None

        _description = obj.get("title")
        _type = "report"
        _label = "threat_report"
        _id = obj.get("id")
        _date_published = json_date_obj.get("date-published")

        _report_portal_links = self._retrieve_link(obj)
        _threat_actor_portal_links = self._retrieve_link(json_threat_actor_obj)
        _malware_portal_links = self._retrieve_link(
            json_malware_report_obj.get("malware_report_list")
        )
        report_links = (
            _report_portal_links + _threat_actor_portal_links + _malware_portal_links
        )
        self.helper.connector_logger.debug(
            f"Retrieved {len(report_links)} portal links for report"
        )

        ta_label = json_threat_actor_obj.get("name")

        report = ds.Report(
            name=f"{_description}",
            c_type=_type,
            published_time=datetime.strptime(_date_published, "%Y-%m-%d"),
            related_objects_ids=report_related_objects_ids,
            tlp_color=self.tlp_color,
            labels=[self.collection, _label, ta_label],
        )
        report.set_description(f"Report {_id}: {_description}")
        report.generate_external_references(report_links)
        report.generate_stix_objects()
        self.helper.connector_logger.debug(
            f"Generated STIX report object for ID: {_id}"
        )

        self.helper.connector_logger.info("Completed generation of STIX report object")
        return report

    def generate_stix_yara(
        self, obj, json_date_obj=None, related_objects=None, yara_is_ioc=True
    ):
        self.helper.connector_logger.info("Starting generation of STIX YARA object")
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for YARA generation"
            )
            return None

        _yara = obj.get("yara")
        # _yara_rule_name = obj.get("yara-rule-name")
        _context = obj.get("context")
        _type = "yara"
        _label = "yara"

        valid_from, valid_until = self._retrieve_ttl_dates(json_date_obj)

        _date_created = self._retrieve_date(json_date_obj, "date-created")

        yara = ds.Indicator(
            name=_yara,
            c_type=_type,
            context=_context,
            created=_date_created,
            tlp_color=self.tlp_color,
            labels=[self.collection, _label],
        )
        yara.is_ioc = yara_is_ioc
        yara.set_valid_from(valid_from)
        yara.set_valid_until(valid_until)
        yara.generate_stix_objects()
        self.helper.connector_logger.debug("Generated STIX YARA object")

        self._generate_relations(
            main_obj=yara,
            related_objects=related_objects,
            is_ioc=yara_is_ioc,
            helper=self.helper,
        )
        self.helper.connector_logger.debug("Generated relations for YARA object")

        yara.add_relationships_to_stix_objects()
        self.helper.connector_logger.debug("Added relationships to STIX YARA object")

        self.helper.connector_logger.info("Completed generation of STIX YARA object")
        return yara

    def generate_stix_suricata(
        self, obj, json_date_obj=None, related_objects=None, suricata_is_ioc=True
    ):
        self.helper.connector_logger.info("Starting generation of STIX Suricata object")
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for Suricata generation"
            )
            return None

        _suricata = obj.get("signature")
        # _suricata_sid = obj.get("sid")
        _context = obj.get("context")
        _type = "suricata"
        _label = "suricata"

        valid_from, valid_until = self._retrieve_ttl_dates(json_date_obj)

        _date_created = self._retrieve_date(json_date_obj, "date-created")

        suricata = ds.Indicator(
            name=_suricata,
            c_type=_type,
            context=_context,
            created=_date_created,
            tlp_color=self.tlp_color,
            labels=[self.collection, _label],
        )
        suricata.is_ioc = suricata_is_ioc
        suricata.set_valid_from(valid_from)
        suricata.set_valid_until(valid_until)
        suricata.generate_stix_objects()
        self.helper.connector_logger.debug("Generated STIX Suricata object")

        self._generate_relations(
            main_obj=suricata,
            related_objects=related_objects,
            is_ioc=suricata_is_ioc,
            helper=self.helper,
        )
        self.helper.connector_logger.debug("Generated relations for Suricata object")

        suricata.add_relationships_to_stix_objects()
        self.helper.connector_logger.debug(
            "Added relationships to STIX Suricata object"
        )

        self.helper.connector_logger.info(
            "Completed generation of STIX Suricata object"
        )
        return suricata

    def generate_stix_ungrouped(
        self, obj, json_date_obj=None, related_objects=None, email_is_ioc=True
    ):
        self.helper.connector_logger.info(
            "Starting generation of STIX ungrouped (email) objects"
        )
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for ungrouped generation"
            )
            return None

        _emails = obj.get("emails")
        _type = "email-addr"
        # _label = "email"

        valid_from, valid_until = self._retrieve_ttl_dates(json_date_obj)

        _stix_objects = list()

        for _email in _emails:
            self.helper.connector_logger.debug(f"Processing email: {_email}")
            email = ds.Email(
                name=_email,
                c_type=_type,
                tlp_color=self.tlp_color,
                labels=[self.collection],
            )
            email.is_ioc = email_is_ioc
            email.set_valid_from(valid_from)
            email.set_valid_until(valid_until)
            email.generate_stix_objects()
            self.helper.connector_logger.debug(
                f"Generated STIX email object for: {_email}"
            )

            self._generate_relations(
                main_obj=email,
                related_objects=related_objects,
                is_ioc=email_is_ioc,
                helper=self.helper,
            )
            self.helper.connector_logger.debug(
                f"Generated relations for email: {_email}"
            )

            email.add_relationships_to_stix_objects()
            self.helper.connector_logger.debug(
                f"Added relationships to STIX email object for: {_email}"
            )

            _stix_objects.append(email)

        self.helper.connector_logger.info(
            f"Generated {len(_stix_objects)} STIX email objects"
        )
        return _stix_objects
