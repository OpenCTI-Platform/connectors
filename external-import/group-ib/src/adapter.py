from datetime import datetime

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

    @staticmethod
    def _generate_relations(main_obj, related_objects, relation_type=None):
        # type: (Any, List[Any], Union[None, str]) -> Any

        # TODO: create common relationship map for all objects
        relation_type_map = {
            "threat_actor": {
                "attack_pattern": "uses",
                "malware": "uses",
                "vulnerability": "targets",
                "file": "related-to",
                "base_location": "located-at",
                "target_location": "targets",
            },
            "indicator": {"file": "based-on", "ipv4": "based-on", "ipv6": "based-on"},
            "ipv4": {
                "threat_actor": "related-to",
                "domain": "related-to",
                "url": "related-to",
            },
            "ipv6": {
                "threat_actor": "related-to",
                "domain": "related-to",
                "url": "related-to",
            },
            "domain": {"threat_actor": "related-to"},
            "url": {"threat_actor": "related-to"},
            "vulnerability": {},
            "malware": {"ipv4": "communicates-with", "ipv6": "communicates-with"},
        }
        # relation_type_map = {
        #     "attack_pattern": "uses",
        #     "malware": "uses",
        #     "vulnerability": "targets"
        # }
        relation_type_required = True
        if relation_type:
            relation_type_required = False

        for _rel_obj in related_objects:
            if _rel_obj:
                if isinstance(_rel_obj, list) and _rel_obj:
                    for _ro in _rel_obj:
                        if relation_type_required:
                            relation_type = relation_type_map.get(main_obj.type).get(
                                _ro.type, None
                            )
                        if not relation_type:
                            raise AttributeError
                        main_obj.generate_relationship(
                            main_obj.stix_main_object,
                            _ro.stix_main_object,
                            relation_type=relation_type,
                        )
                else:

                    if relation_type_required:
                        relation_type = relation_type_map.get(main_obj.type).get(
                            _rel_obj.type, None
                        )
                    if not relation_type:
                        raise AttributeError
                    main_obj.generate_relationship(
                        main_obj.stix_main_object,
                        _rel_obj.stix_main_object,
                        relation_type=relation_type,
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
                _type=_type,
                # tlp_color=self.tlp_color,
                labels=[self.collection, _label],
            )
            .generate_stix_objects()
            .stix_main_object
            for _type in obj_types
        ]

    def generate_stix_domain(self, name):
        _type = "domain"
        _label = "domain"

        return ds.Domain(
            name=name,
            _type=_type,
            tlp_color=self.tlp_color,
            labels=[self.collection, _label],
        )

    def generate_stix_url(self, name):
        _type = "url"
        _label = "url"

        return ds.URL(
            name=name,
            _type=_type,
            tlp_color=self.tlp_color,
            labels=[self.collection, _label],
        )

    def generate_stix_ipv4(self, name):
        _type = "ipv4"
        _label = "ipv4"

        return ds.IPAddress(
            name=name,
            _type=_type,
            tlp_color=self.tlp_color,
            labels=[self.collection, _label],
        )

    def generate_locations(self, obj_country_codes):
        _type = "location"
        _label = "country"

        return [
            ds.Location(
                name=_cc,
                _type=_type,
                tlp_color=self.tlp_color,
                labels=[self.collection, _label],
            ).generate_stix_objects()
            for _cc in obj_country_codes
            if _cc
        ]

    def generate_stix_malware(self, obj, json_date_obj=None):
        if not obj:
            return list()

        # _description = obj.get("__")
        _type = "malware"
        _label = "malware"
        _events = obj.get("malware_report_list", [])
        _date_updated = None

        if json_date_obj:
            try:
                _date_updated = datetime.strptime(
                    json_date_obj.get("date-updated"), "%Y-%m-%dT%H:%M:%S%z"
                )
            except (Exception,):
                self.helper.log_warning(
                    "Failed to format first_seen: {}. Using default.".format(
                        json_date_obj.get("date-updated"),
                    )
                )
                _date_updated = None

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
                                _type=_type,
                                malware_types=_malware_types or [],
                                tlp_color="red",
                                labels=[self.collection, _label],
                            )
                            malware.generate_external_references(_portal_links)
                            malware.generate_stix_objects()

                            _stix_objects.append(malware)
                    else:
                        malware = ds.Malware(
                            name=_name,
                            aliases=_malware_aliases,
                            last_seen=_date_updated,
                            _type=_type,
                            malware_types=_malware_types,
                            tlp_color="red",
                            labels=[self.collection, _type],
                        )
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
                    _type=_type,
                    malware_types=_malware_types,
                    tlp_color="red",
                    labels=[self.collection, _type],
                )
                malware.generate_external_references(_portal_links)
                malware.generate_stix_objects()

                _stix_objects.append(malware)

        return _stix_objects

    def generate_stix_vulnerability(
        self, obj, related_objects, json_date_obj=None, json_cvss_obj=None
    ):
        if not obj:
            return list()

        # TODO: How to add cvssv2??? cpeTable?

        _description = obj.get("__")
        _type = "vulnerability"
        _label = "vulnerability"
        if json_cvss_obj:
            _cvssv3_score = json_cvss_obj.get("score", None)
            _cvssv3_vector = json_cvss_obj.get("vector", None)
        else:
            _cvssv3_score = None
            _cvssv3_vector = None
        _events = obj.get("vulnerability_list", [])
        _date_published = None

        if json_date_obj:
            try:
                _date_published = datetime.strptime(
                    json_date_obj.get("date-published"), "%Y-%m-%dT%H:%M:%S%z"
                )
            except (Exception,):
                self.helper.log_warning(
                    "Failed to format first_seen: {}. Using default.".format(
                        json_date_obj.get("date-updated"),
                    )
                )
                _date_published = datetime.now()

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
                                _type=_type,
                                created=_date_published,
                                cvss_score=_cvssv3_score,
                                cvss_vector=_cvssv3_vector,
                                tlp_color=self.tlp_color,
                                labels=[self.collection, _label],
                            )
                            vulnerability.generate_stix_objects()

                            if related_objects:
                                self._generate_relations(
                                    vulnerability, related_objects, "related-to"
                                )

                            vulnerability.set_description(_description)
                            vulnerability.add_relationships_to_stix_objects()

                            _stix_objects.append(vulnerability)
                    else:
                        vulnerability = ds.Vulnerability(
                            name=_name,
                            _type=_type,
                            created=_date_published,
                            cvss_score=_cvssv3_score,
                            cvss_vector=_cvssv3_vector,
                            tlp_color=self.tlp_color,
                            labels=[self.collection, _label],
                        )
                        vulnerability.generate_stix_objects()

                        if related_objects:
                            self._generate_relations(
                                vulnerability, related_objects, "related-to"
                            )

                        vulnerability.set_description(_description)
                        vulnerability.add_relationships_to_stix_objects()

                        _stix_objects.append(vulnerability)

        else:
            _name = obj.get("object_id")
            _description = obj.get("description")

            if _name:
                vulnerability = ds.Vulnerability(
                    name=_name,
                    _type=_type,
                    created=_date_published,
                    cvss_score=_cvssv3_score,
                    cvss_vector=_cvssv3_vector,
                    tlp_color=self.tlp_color,
                    labels=[self.collection, _label],
                )
                vulnerability.generate_stix_objects()

                if related_objects:
                    self._generate_relations(
                        vulnerability, related_objects, "related-to"
                    )

                vulnerability.set_description(_description)
                vulnerability.add_relationships_to_stix_objects()

                _stix_objects.append(vulnerability)

        return _stix_objects

    def generate_stix_attack_pattern(self, obj):
        if not obj:
            return list()

        _description = obj.get("__")
        _type = "attack_pattern"
        _label = "attack_pattern"
        _events = obj.get("mitre_matrix_list")

        _stix_objects = list()

        event_mitre_matrix = self._generate_mitre_matrix(_events)

        for k, v in event_mitre_matrix.items():

            kill_chain_phases = self.generate_kill_chain_phases(v["kill_chain_phases"])

            if k:
                attack_pattern = ds.AttackPattern(
                    name=self.mitre_mapper.get(k),
                    _type=_type,
                    mitre_id=k,
                    kill_chain_phases=kill_chain_phases,
                    # tlp_color=self.tlp_color,
                    labels=[self.collection, _label],
                )
                attack_pattern.set_description(_description)
                attack_pattern.generate_external_references(v["portal_links"])
                attack_pattern.generate_stix_objects()

                _stix_objects.append(attack_pattern)

        return _stix_objects

    def generate_stix_threat_actor(self, obj, related_objects, json_date_obj=None):
        if not obj:
            return None, None

        # _description = obj.get("__")
        _type = "threat_actor"
        _label = "threat_actor"
        _global_label = self.ta_global_label
        # _country_type = "country"

        _threat_actor_name = obj.get("name")
        _threat_actor_country = obj.get("country")
        _threat_actor_targeted_countries = obj.get("targeted_countries")
        _threat_actor_aliases = obj.get("aliases")
        _threat_actor_description = obj.get("description")
        _threat_actor_goals = obj.get("goals")
        _threat_actor_roles = obj.get("roles")
        _date_first_seen = None
        _date_last_seen = None

        if json_date_obj:
            try:
                _date_first_seen = datetime.strptime(
                    json_date_obj.get("first-seen"), "%Y-%m-%d"
                )
                _date_last_seen = datetime.strptime(
                    json_date_obj.get("last-seen"), "%Y-%m-%d"
                )
            except (Exception,):
                self.helper.log_warning(
                    "Failed to format first_seen: {}, last_seen: {}. Using default.".format(
                        json_date_obj.get("first-seen"), json_date_obj.get("last-seen")
                    )
                )
                _date_first_seen = None
                _date_last_seen = None

        _portal_link = self._retrieve_link(obj)

        threat_actor = None
        locations = None

        if _threat_actor_name:
            threat_actor = ds.ThreatActor(
                name=_threat_actor_name,
                _type=_type,
                global_label=_global_label,
                tlp_color="red",
                labels=[self.collection, _label],
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
                base_locations = self.generate_locations([_threat_actor_country])
            target_locations = []
            if _threat_actor_targeted_countries:
                target_locations = self.generate_locations(
                    _threat_actor_targeted_countries
                )

            locations = base_locations + target_locations

            if _threat_actor_name and base_locations:
                self._generate_relations(threat_actor, base_locations, "located-at")

            if _threat_actor_name and target_locations:
                self._generate_relations(threat_actor, target_locations, "targets")

            if related_objects:
                self._generate_relations(threat_actor, related_objects)

            threat_actor.add_relationships_to_stix_objects()

        return threat_actor, locations

    def generate_stix_file(self, obj, related_objects=None, is_ioc=True):
        if not obj:
            return list()

        _description = obj.get("__")
        _type = "file"
        _label = "file"
        _events = obj.get("file_list")

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
                        _type=_type,
                        tlp_color=self.tlp_color,
                        labels=[self.collection, _label],
                    )
                    file.set_description(_description)
                    file.is_ioc = is_ioc
                    file.generate_stix_objects()

                    if self.is_ioc:
                        for ind in file.stix_indicator:
                            file.generate_relationship(
                                ind, file.stix_main_object, relation_type="based-on"
                            )

                    if related_objects:
                        self._generate_relations(file, related_objects, "related-to")

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
                    _type=_type,
                    tlp_color=self.tlp_color,
                    labels=[self.collection, _label],
                )
                file.set_description(_description)
                file.is_ioc = is_ioc
                file.generate_stix_objects()

                if self.is_ioc:
                    for ind in file.stix_indicator:
                        file.generate_relationship(
                            ind, file.stix_main_object, relation_type="based-on"
                        )

                if related_objects:
                    self._generate_relations(file, related_objects, "related-to")

                file.add_relationships_to_stix_objects()

                _stix_objects.append(file)

        return _stix_objects

    def generate_stix_network(
        self,
        obj,
        related_objects=None,
        url_is_ioc=False,
        domain_is_ioc=False,
        ip_is_ioc=False,
    ):
        if not obj:
            return list(), list(), list()

        _description = obj.get("__")
        # _type = "ipv4"
        # _label = "ipv4"
        _events = obj.get("network_list", None)

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
                    domain.generate_stix_objects()

                    if domain_is_ioc:
                        domain.generate_relationship(
                            domain.stix_indicator,
                            domain.stix_main_object,
                            relation_type="based-on",
                        )

                    if related_objects:
                        self._generate_relations(domain, related_objects, "related-to")

                    domain.add_relationships_to_stix_objects()

                    _domain_stix_objects.append(domain)

                url = None
                if _url:
                    url = self.generate_stix_url(_url)
                    url.is_ioc = url_is_ioc
                    link_id = ""
                    link_url = _url
                    link_description = "Source external reference"
                    url.generate_external_references(
                        [(link_id, link_url, link_description)]
                    )
                    url.generate_stix_objects()

                    if url_is_ioc:
                        url.generate_relationship(
                            url.stix_indicator,
                            url.stix_main_object,
                            relation_type="based-on",
                        )

                    if related_objects:
                        self._generate_relations(url, related_objects, "related-to")

                    url.add_relationships_to_stix_objects()

                    _url_stix_objects.append(url)

                if _ips:
                    for _ip in _ips:
                        ip = self.generate_stix_ipv4(_ip)

                        ip.set_description(_description)
                        ip.is_ioc = ip_is_ioc
                        ip.generate_stix_objects()

                        if ip_is_ioc:
                            ip.generate_relationship(
                                ip.stix_indicator,
                                ip.stix_main_object,
                                relation_type="based-on",
                            )

                        if related_objects:
                            self._generate_relations(ip, related_objects, "related-to")

                        if domain:
                            self._generate_relations(ip, [domain], "related-to")
                        if url:
                            self._generate_relations(ip, [url], "related-to")

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
                domain.generate_stix_objects()

                if domain_is_ioc:
                    domain.generate_relationship(
                        domain.stix_indicator,
                        domain.stix_main_object,
                        relation_type="based-on",
                    )

                if related_objects:
                    self._generate_relations(domain, related_objects, "related-to")

                domain.add_relationships_to_stix_objects()

                _domain_stix_objects.append(domain)

            url = None
            if _url:
                url = self.generate_stix_url(_url)
                url.is_ioc = url_is_ioc
                link_id = ""
                link_url = _url
                link_description = "Source external reference"
                url.generate_external_references(
                    [(link_id, link_url, link_description)]
                )
                url.generate_stix_objects()

                if url_is_ioc:
                    url.generate_relationship(
                        url.stix_indicator,
                        url.stix_main_object,
                        relation_type="based-on",
                    )

                if related_objects:
                    self._generate_relations(url, related_objects, "related-to")

                url.add_relationships_to_stix_objects()

                _url_stix_objects.append(url)

            if _ip:
                ip = self.generate_stix_ipv4(_ip)

                ip.set_description(_description)
                ip.is_ioc = ip_is_ioc
                ip.generate_stix_objects()

                if ip_is_ioc:
                    ip.generate_relationship(
                        ip.stix_indicator, ip.stix_main_object, relation_type="based-on"
                    )

                if related_objects:
                    self._generate_relations(ip, related_objects, "related-to")

                if domain:
                    self._generate_relations(ip, [domain], "related-to")
                if url:
                    self._generate_relations(ip, [url], "related-to")

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
        _type = "threat_report"
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
            name=f"Report: {_description}",
            _type=_type,
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
        self, obj, json_date_obj=None, related_objects=None, is_ioc=True
    ):
        if not obj:
            return None

        _yara = obj.get("yara")
        # _yara_rule_name = obj.get("yara-rule-name")
        _context = obj.get("context")
        _type = "yara"
        _label = "yara"
        _date_created = None

        if json_date_obj:
            try:
                _date_created = datetime.strptime(
                    json_date_obj.get("date-created"), "%Y-%m-%dT%H:%M:%S%z"
                )
            except (Exception,):
                self.helper.log_warning(
                    "Failed to format first_seen: {}. Using default.".format(
                        json_date_obj.get("date-updated"),
                    )
                )
                _date_created = datetime.now()

        yara = ds.Indicator(
            name=_yara,
            _type=_type,
            context=_context,
            created=_date_created,
            tlp_color=self.tlp_color,
            labels=[self.collection, _label],
        )
        yara.is_ioc = is_ioc
        yara.generate_stix_objects()

        if related_objects:
            self._generate_relations(yara, related_objects, "indicates")

        yara.add_relationships_to_stix_objects()

        return yara

    def generate_stix_suricata(
        self, obj, json_date_obj=None, related_objects=None, is_ioc=True
    ):
        if not obj:
            return None

        _suricata = obj.get("signature")
        # _suricata_sid = obj.get("sid")
        _context = obj.get("context")
        _type = "suricata"
        _label = "suricata"
        _date_created = None

        if json_date_obj:
            try:
                _date_created = datetime.strptime(
                    json_date_obj.get("date-created"), "%Y-%m-%dT%H:%M:%S%z"
                )
            except (Exception,):
                self.helper.log_warning(
                    "Failed to format first_seen: {}. Using default.".format(
                        json_date_obj.get("date-updated"),
                    )
                )
                _date_created = datetime.now()

        suricata = ds.Indicator(
            name=_suricata,
            _type=_type,
            context=_context,
            created=_date_created,
            tlp_color=self.tlp_color,
            labels=[self.collection, _label],
        )
        suricata.is_ioc = is_ioc
        suricata.generate_stix_objects()

        if related_objects:
            self._generate_relations(suricata, related_objects, "indicates")

        suricata.add_relationships_to_stix_objects()

        return suricata
