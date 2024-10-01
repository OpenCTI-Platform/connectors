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

from datetime import datetime, timedelta

import data_to_stix2 as ds
from stix2.patterns import HashConstant


class DataToSTIXAdapter:

    def __init__(self, mitre_mapper, collection, tlp_color, helper, is_ioc=False):
        # type: (dict, str, str, Any, bool) -> None
        self.mitre_mapper = mitre_mapper
        self.collection = collection
        self.ta_global_label = self._set_global_label(self.collection)
        self.tlp_color = tlp_color
        self.is_ioc = is_ioc
        self.helper = helper
        self.author = ds.BaseEntity("", "", "white").author

    @staticmethod
    def _valid_hash(hash_value, hash_type):
        try:
            HashConstant(value=hash_value, type=hash_type)
            return True
        except ValueError:
            return False

    def _set_global_label(self, collection):
        if collection in ["apt/threat", "apt/threat_actor"]:
            return "nation-state"
        elif collection in ["hi/threat", "hi/threat_actor"]:
            return "criminal"

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

        date_raw = obj.get(key, "")
        if not date_raw and alter_key:
            date_raw = obj.get(alter_key, "")

        if date_raw:
            if date_raw.startswith("00"):
                self.helper.log_warning("Wrong format of date: {}".format(date_raw))
                return datetime.now()

        try:
            _datetime = datetime.fromisoformat(date_raw)
        except (Exception,):
            self.helper.log_warning(
                "Failed to format date: {}. Using default.".format(date_raw)
            )
            _datetime = datetime.now()

        return _datetime

    def _retrieve_ttl_dates(self, obj):
        # type: (dict) -> Tuple[datetime, datetime]
        """
        :returns: (valid_from, valid_until)
        """
        ttl = obj.get("ttl")
        if not ttl:
            ttl = 365

        # try to extract date-modified
        date_modified_raw = obj.get("date-modified", "")
        date_created_raw = obj.get("date-created", "")

        if date_modified_raw:
            if date_modified_raw.startswith("00"):
                self.helper.log_warning(
                    "Wrong format of date_modified: {}".format(date_modified_raw)
                )
                date_modified_raw = None

        if date_created_raw:
            if date_created_raw.startswith("00"):
                self.helper.log_warning(
                    "Wrong format of date_created: {}".format(date_created_raw)
                )
                date_created_raw = None

        if not date_modified_raw and not date_created_raw:
            self.helper.log_warning("No correct date found. Using default")
            base_ttl_datetime = datetime.now()
        else:
            if date_modified_raw:
                base_ttl_raw_date = date_modified_raw
            else:
                base_ttl_raw_date = date_created_raw

            try:
                base_ttl_datetime = datetime.fromisoformat(base_ttl_raw_date)
            except (Exception,):
                self.helper.log_warning(
                    "Failed to format base_ttl_raw_date: {}. Using default.".format(
                        base_ttl_raw_date
                    )
                )
                base_ttl_datetime = datetime.now()

        valid_from = base_ttl_datetime
        valid_until = base_ttl_datetime + timedelta(days=ttl)
        return valid_from, valid_until

    @staticmethod
    def _generate_relations(
        main_obj, related_objects, relation_type=None, is_ioc=False
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

        # generate relationship: Indicator --based-on--> Observable
        if (
            is_ioc
            and main_obj.stix_indicator
            and main_obj.c_type not in ["yara", "suricata"]
        ):
            _indicator = main_obj.stix_indicator

            if isinstance(_indicator, list):
                for _ind in _indicator:
                    _gen_rel(_ind, _ind.type, _main_object, _main_object_c_type)
            else:
                _gen_rel(_indicator, _indicator.type, _main_object, _main_object_c_type)

        if not related_objects:
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
                                    _gen_rel(
                                        _ind,
                                        _ind.type,
                                        _ro.stix_main_object,
                                        _ro.c_type,
                                    )
                            else:
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
                                _gen_rel(
                                    _ind,
                                    _ind.type,
                                    _rel_obj.stix_main_object,
                                    _rel_obj.c_type,
                                )
                        else:
                            _gen_rel(
                                _indicator,
                                _indicator.type,
                                _rel_obj.stix_main_object,
                                _rel_obj.c_type,
                            )

                    else:
                        _gen_rel(
                            _main_object,
                            _main_object_c_type,
                            _rel_obj.stix_main_object,
                            _rel_obj.c_type,
                        )

        return main_obj

    def _generate_mitre_matrix(self, obj_events):
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
        return mitre_matrix

    def generate_kill_chain_phases(self, obj_types):
        _name = "mitre-attack"
        _label = "mitre"

        return [
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

    def generate_stix_domain(self, name):
        _type = "domain-name"
        # _label = "domain"

        return ds.Domain(
            name=name,
            c_type=_type,
            tlp_color=self.tlp_color,
            labels=[self.collection],
        )

    def generate_stix_url(self, name):
        _type = "url"
        # _label = "url"

        return ds.URL(
            name=name,
            c_type=_type,
            tlp_color=self.tlp_color,
            labels=[self.collection],
        )

    def generate_stix_ipv4(self, name):
        _type = "ipv4-addr"
        # _label = "ipv4"

        return ds.IPAddress(
            name=name,
            c_type=_type,
            tlp_color=self.tlp_color,
            labels=[self.collection],
        )

    def generate_locations(self, obj_country_codes, change_type_to=None):
        _type = "location"
        if change_type_to:
            _type = change_type_to
        # _label = "country"

        return [
            ds.Location(
                name=_cc,
                c_type=_type,
                tlp_color=self.tlp_color,
                labels=[self.collection],
            ).generate_stix_objects()
            for _cc in obj_country_codes
            if _cc
        ]

    def generate_stix_malware(self, obj, json_date_obj=None):
        if not obj:
            return list()

        _description = obj.get("__")
        _type = "malware"
        # _label = "malware"
        _events = obj.get("malware_report_list", [])

        _date_updated = self._retrieve_date(
            json_date_obj, "date-updated", "date-modified"
        )

        _stix_objects = list()

        if _events:
            for _e in _events:
                _name = _e.get("name")
                _malware_types = _e.get("category")
                _malware_aliases = _e.get("aliases")

                _portal_links = self._retrieve_link(_e)

                if _name:
                    if isinstance(_name, list):
                        for n in _name:
                            malware = ds.Malware(
                                name=n,
                                aliases=_malware_aliases,
                                last_seen=_date_updated,
                                c_type=_type,
                                malware_types=_malware_types or [],
                                tlp_color="red",
                                labels=[self.collection],
                            )
                            malware.set_description(_description)
                            malware.generate_external_references(_portal_links)
                            malware.generate_stix_objects()

                            _stix_objects.append(malware)
                    else:
                        malware = ds.Malware(
                            name=_name,
                            aliases=_malware_aliases,
                            last_seen=_date_updated,
                            c_type=_type,
                            malware_types=_malware_types,
                            tlp_color="red",
                            labels=[self.collection],
                        )
                        malware.set_description(_description)
                        malware.generate_external_references(_portal_links)
                        malware.generate_stix_objects()

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
                    last_seen=_date_updated,
                    c_type=_type,
                    malware_types=_malware_types,
                    tlp_color="red",
                    labels=[self.collection],
                )
                malware.set_description(_description)
                malware.generate_external_references(_portal_links)
                malware.generate_stix_objects()

                _stix_objects.append(malware)

        return _stix_objects

    def generate_stix_vulnerability(
        self, obj, related_objects, json_date_obj=None, json_cvss_obj=None
    ):
        if not obj:
            return list()

        _description = obj.get("__")
        _type = "vulnerability"
        # _label = "vulnerability"
        if json_cvss_obj:
            _cvssv3_score = json_cvss_obj.get("score", None)
            _cvssv3_vector = json_cvss_obj.get("vector", None)
        else:
            _cvssv3_score = None
            _cvssv3_vector = None
        _events = obj.get("vulnerability_list", [])

        _date_published = self._retrieve_date(json_date_obj, "date-published")

        _stix_objects = list()

        if _events:
            for _e in _events:
                _name = _e.get("object_id")
                _description = _e.get("description")

                if _name:
                    if isinstance(_name, list):
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

                            self._generate_relations(vulnerability, related_objects)

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

                        self._generate_relations(vulnerability, related_objects)

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

                self._generate_relations(vulnerability, related_objects)

                vulnerability.add_relationships_to_stix_objects()

                _stix_objects.append(vulnerability)

        return _stix_objects

    def generate_stix_attack_pattern(self, obj):
        if not obj:
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

                _stix_objects.append(attack_pattern)

        return _stix_objects

    def generate_stix_threat_actor(self, obj, related_objects, json_date_obj=None):
        if not obj:
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

        _date_first_seen = self._retrieve_date(json_date_obj, "first-seen")
        _date_last_seen = self._retrieve_date(json_date_obj, "last-seen")

        _portal_link = self._retrieve_link(obj)

        threat_actor = None
        locations = None

        if _threat_actor_name:
            threat_actor = ds.ThreatActor(
                name=_threat_actor_name,
                c_type=_type,
                global_label=_global_label,
                tlp_color="red",
                labels=[self.collection],
                aliases=_threat_actor_aliases,
                first_seen=_date_first_seen,
                last_seen=_date_last_seen,
                goals=_threat_actor_goals,
                roles=_threat_actor_roles,
            )
            threat_actor.set_description(_threat_actor_description)
            threat_actor.generate_external_references(_portal_link)
            threat_actor.generate_stix_objects()

            base_locations = []
            if _threat_actor_country:
                base_locations = self.generate_locations(
                    [_threat_actor_country], change_type_to="base-location"
                )
            target_locations = []
            if _threat_actor_targeted_countries:
                target_locations = self.generate_locations(
                    _threat_actor_targeted_countries, change_type_to="target-location"
                )

            locations = base_locations + target_locations

            if _threat_actor_name and base_locations:
                self._generate_relations(threat_actor, base_locations)

            if _threat_actor_name and target_locations:
                self._generate_relations(threat_actor, target_locations)

            self._generate_relations(threat_actor, related_objects)

            threat_actor.add_relationships_to_stix_objects()

        return threat_actor, locations

    def generate_stix_intrusion_set(self, obj, related_objects, json_date_obj=None):
        if not obj:
            return None

        _type = "intrusion-set"
        # _label = "threat_actor"
        _global_label = self.ta_global_label
        # _country_type = "country"

        _threat_actor_name = obj.get("name")
        # _threat_actor_country = obj.get("country")
        # _threat_actor_targeted_countries = obj.get("targeted_countries")
        _threat_actor_aliases = obj.get("aliases")
        _threat_actor_description = obj.get("description")
        _threat_actor_goals = obj.get("goals")
        _threat_actor_roles = obj.get("roles")

        _date_first_seen = self._retrieve_date(json_date_obj, "first-seen")
        _date_last_seen = self._retrieve_date(json_date_obj, "last-seen")

        _portal_link = self._retrieve_link(obj)

        intrusion_set = None
        # locations = None

        if _threat_actor_name:
            intrusion_set = ds.IntrusionSet(
                name=_threat_actor_name,
                c_type=_type,
                global_label=_global_label,
                tlp_color="red",
                labels=[self.collection],
                aliases=_threat_actor_aliases,
                first_seen=_date_first_seen,
                last_seen=_date_last_seen,
                goals=_threat_actor_goals,
                roles=_threat_actor_roles,
            )
            intrusion_set.set_description(_threat_actor_description)
            intrusion_set.generate_external_references(_portal_link)
            intrusion_set.generate_stix_objects()

            # base_locations = []
            # if _threat_actor_country:
            #     base_locations = self.generate_locations(
            #         [_threat_actor_country], change_type_to="base-location"
            #     )
            # target_locations = []
            # if _threat_actor_targeted_countries:
            #     target_locations = self.generate_locations(
            #         _threat_actor_targeted_countries, change_type_to="target-location"
            #     )

            # locations = base_locations + target_locations
            #
            # if _threat_actor_name and base_locations:
            #     self._generate_relations(intrusion_set, base_locations)
            #
            # if _threat_actor_name and target_locations:
            #     self._generate_relations(intrusion_set, target_locations)

            self._generate_relations(intrusion_set, related_objects)

            intrusion_set.add_relationships_to_stix_objects()

        return intrusion_set  # , locations

    def generate_stix_file(
        self, obj, json_date_obj=None, related_objects=None, file_is_ioc=True
    ):
        if not obj:
            return list()

        _description = obj.get("__")
        _type = "file"
        # _label = "file"
        _events = obj.get("file_list")

        valid_from, valid_until = self._retrieve_ttl_dates(json_date_obj)

        _stix_objects = list()

        if _events:
            for _e in _events:
                _md5 = _e.get("md5", None)
                _sha1 = _e.get("sha1", None)
                _sha256 = _e.get("sha256", None)
                if _md5:
                    if not self._valid_hash(_md5, "MD5"):
                        self.helper.log_error(
                            f"Error! {_md5} is not valid MD5. Ignored."
                        )
                        _md5 = None
                if _sha1:
                    if not self._valid_hash(_sha1, "SHA1"):
                        self.helper.log_error(
                            f"Error! {_sha1} is not valid SHA1. Ignored."
                        )
                        _sha1 = None
                if _sha256:
                    if not self._valid_hash(_sha256, "SHA256"):
                        self.helper.log_error(
                            f"Error! {_sha256} is not valid SHA256. Ignored."
                        )
                        _sha256 = None
                hashes = [_md5, _sha1, _sha256]

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

                    self._generate_relations(file, related_objects, is_ioc=file_is_ioc)

                    file.add_relationships_to_stix_objects()

                    _stix_objects.append(file)
        else:
            _md5 = obj.get("md5", None)
            _sha1 = obj.get("sha1", None)
            _sha256 = obj.get("sha256", None)
            if _md5:
                if not self._valid_hash(_md5, "MD5"):
                    self.helper.log_error(f"Error! {_md5} is not valid MD5. Ignored.")
                    _md5 = None
            if _sha1:
                if not self._valid_hash(_sha1, "SHA1"):
                    self.helper.log_error(f"Error! {_sha1} is not valid SHA1. Ignored.")
                    _sha1 = None
            if _sha256:
                if not self._valid_hash(_sha256, "SHA256"):
                    self.helper.log_error(
                        f"Error! {_sha256} is not valid SHA256. Ignored."
                    )
                    _sha256 = None
            hashes = [_md5, _sha1, _sha256]

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

                self._generate_relations(file, related_objects, is_ioc=file_is_ioc)

                file.add_relationships_to_stix_objects()

                _stix_objects.append(file)

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
        if not obj:
            return list(), list(), list()

        _description = obj.get("__")
        _events = obj.get("network_list", None)

        valid_from, valid_until = self._retrieve_ttl_dates(json_date_obj)

        _domain_stix_objects = list()
        _url_stix_objects = list()
        _ip_stix_objects = list()

        if _events:
            for _e in _events:
                _domain = _e.get("domain")
                _url = _e.get("url")
                _ips = _e.get("ip-address")

                domain = None
                if _domain:
                    domain = self.generate_stix_domain(_domain)
                    domain.is_ioc = domain_is_ioc
                    domain.set_valid_from(valid_from)
                    domain.set_valid_until(valid_until)
                    domain.generate_stix_objects()

                    self._generate_relations(
                        domain, related_objects, is_ioc=domain_is_ioc
                    )

                    domain.add_relationships_to_stix_objects()

                    _domain_stix_objects.append(domain)

                url = None
                if _url:
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

                    self._generate_relations(url, related_objects, is_ioc=url_is_ioc)

                    url.add_relationships_to_stix_objects()

                    _url_stix_objects.append(url)

                if _ips:
                    for _ip in _ips:
                        ip = self.generate_stix_ipv4(_ip)

                        ip.set_description(_description)
                        ip.is_ioc = ip_is_ioc
                        ip.set_valid_from(valid_from)
                        ip.set_valid_until(valid_until)
                        ip.generate_stix_objects()

                        self._generate_relations(ip, related_objects, is_ioc=ip_is_ioc)

                        if domain:
                            self._generate_relations(ip, [domain])
                        if url:
                            self._generate_relations(ip, [url])

                        ip.add_relationships_to_stix_objects()

                        _ip_stix_objects.append(ip)

        else:
            _domain = obj.get("domain")
            _url = obj.get("url")
            _ip = obj.get("ip-address")

            domain = None
            if _domain:
                domain = self.generate_stix_domain(_domain)
                domain.is_ioc = domain_is_ioc
                domain.set_valid_from(valid_from)
                domain.set_valid_until(valid_until)
                domain.generate_stix_objects()

                self._generate_relations(domain, related_objects, is_ioc=domain_is_ioc)

                domain.add_relationships_to_stix_objects()

                _domain_stix_objects.append(domain)

            url = None
            if _url:
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

                self._generate_relations(url, related_objects, is_ioc=url_is_ioc)

                url.add_relationships_to_stix_objects()

                _url_stix_objects.append(url)

            if _ip:
                ip = self.generate_stix_ipv4(_ip)

                ip.set_description(_description)
                ip.is_ioc = ip_is_ioc
                ip.set_valid_from(valid_from)
                ip.set_valid_until(valid_until)
                ip.generate_stix_objects()

                self._generate_relations(ip, related_objects, is_ioc=ip_is_ioc)

                if domain:
                    self._generate_relations(ip, [domain])
                if url:
                    self._generate_relations(ip, [url])

                ip.add_relationships_to_stix_objects()

                _ip_stix_objects.append(ip)

        return _domain_stix_objects, _url_stix_objects, _ip_stix_objects

    def generate_stix_report(
        self,
        obj,
        json_date_obj,
        report_related_objects_ids,
        json_malware_report_obj,
        json_threat_actor_obj,
    ):
        if not obj:
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

        return report

    def generate_stix_yara(
        self, obj, json_date_obj=None, related_objects=None, yara_is_ioc=True
    ):
        if not obj:
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

        self._generate_relations(yara, related_objects, is_ioc=yara_is_ioc)

        yara.add_relationships_to_stix_objects()

        return yara

    def generate_stix_suricata(
        self, obj, json_date_obj=None, related_objects=None, suricata_is_ioc=True
    ):
        if not obj:
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

        self._generate_relations(suricata, related_objects, is_ioc=suricata_is_ioc)

        suricata.add_relationships_to_stix_objects()

        return suricata

    def generate_stix_ungrouped(
        self, obj, json_date_obj=None, related_objects=None, email_is_ioc=True
    ):
        if not obj:
            return None

        _emails = obj.get("emails")
        _type = "email-addr"
        # _label = "email"

        valid_from, valid_until = self._retrieve_ttl_dates(json_date_obj)

        _stix_objects = list()

        for _email in _emails:
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

            self._generate_relations(email, related_objects, is_ioc=email_is_ioc)

            email.add_relationships_to_stix_objects()

            _stix_objects.append(email)

        return _stix_objects
