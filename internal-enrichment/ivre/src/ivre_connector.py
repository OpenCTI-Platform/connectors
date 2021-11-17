"""This module implements an IVRE-based connector for OpenCTI.

IVRE is an open-source network recon framework, which makes it easy to
build self-hosted, fully controlled alternatives to services such as
Shodan, ZoomEye, Censys (wide network scans), Greynoise (scanners
monitoring) and/or PassiveDNS.

See <https://ivre.rocks/> and
<https://doc.ivre.rocks/en/latest/usage/use-cases.html> to learn more
about IVRE.

"""

import os
import re

from pycti import OpenCTIConnectorHelper, get_config_variable
import yaml
from ivre import config as ivre_config
from ivre.db import MetaDB
from ivre.utils import HEX


DATABASES = [
    ("data", "data"),
    ("passive", "passive"),
    ("scans", "nmap"),
]

TYPE_DOMAIN = "Domain-Name"
TYPE_IPV4_ADDR = "IPv4-Addr"
TYPE_IPV6_ADDR = "IPv6-Addr"
TYPES_IP_ADDR = {TYPE_IPV4_ADDR, TYPE_IPV6_ADDR}
TYPE_MAC_ADDR = "Mac-Addr"
TYPE_CERT = "X509-Certificate"
TYPE_AS = "Autonomous-System"

TOR_CERT_SUBJECT = re.compile("^commonName=www\\.[a-z2-7]{8,20}\\.(net|com)$", flags=0)


class IvreConnector:
    """The conector object. Instanciate and .start()."""

    def __init__(self):
        """Instantiate the connector helper from the configuration"""
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as fdesc:
                config = yaml.load(fdesc, Loader=yaml.FullLoader)
        else:
            config = {}
        self.helper = OpenCTIConnectorHelper(config)
        self.use_data = get_config_variable(
            "IVRE_USE_DATA", ["ivre", "use_data"], default=True
        )
        self.use_passive = get_config_variable(
            "IVRE_USE_PASSIVE", ["ivre", "use_passive"], default=True
        )
        self.use_passive_as = get_config_variable(
            "IVRE_USE_PASSIVE_AS", ["ivre", "use_passive_as"], default=True
        )
        self.use_passive_domain = get_config_variable(
            "IVRE_USE_PASSIVE_DOMAIN", ["ivre", "use_passive_domain"], default=True
        )
        self.use_scans = get_config_variable(
            "IVRE_USE_SCANS", ["ivre", "use_scans"], default=True
        )
        self.use_scans_as = get_config_variable(
            "IVRE_USE_SCANS_AS", ["ivre", "use_scans_as"], default=False
        )
        self.use_scans_domain = get_config_variable(
            "IVRE_USE_SCANS_DOMAIN", ["ivre", "use_scans_domain"], default=False
        )
        self.dbase = MetaDB(
            get_config_variable(
                "IVRE_DB_URL",
                ["ivre", "db_url"],
                config,
                default=ivre_config.DB if hasattr(ivre_config, "DB") else None,
            ),
            urls={
                attr: url
                for attr, url in (
                    (
                        attr,
                        get_config_variable(
                            f"IVRE_DB_URL_{name.upper()}",
                            ["ivre", f"db_url_{name}"],
                            config,
                            default=(
                                getattr(ivre_config, f"DB_{attr.upper()}")
                                if hasattr(ivre_config, f"DB_{attr.upper()}")
                                else None
                            ),
                        ),
                    )
                    for name, attr in DATABASES
                )
                if url
            },
        )
        self.databases = {name: getattr(self.dbase, attr) for name, attr in DATABASES}
        self.ivre_instance_name = get_config_variable(
            "CONNECTOR_NAME", ["connector", "name"], config, default="IVRE"
        )
        self.confidence = int(self.helper.connect_confidence_level)
        self.max_tlp = get_config_variable("IVRE_MAX_TLP", ["ivre", "max_tlp"], config)

    @property
    def ivre_entity(self):
        """This property is used to create an organization for the IVRE
        instance, and returns its id.

        """
        try:
            return self._ivre_entity
        except AttributeError:
            pass
        ivre_entity = self.helper.api.stix_domain_object.get_by_stix_id_or_name(
            name=self.ivre_instance_name
        )
        if not ivre_entity:
            self.helper.log_info(f"Creating entity {self.ivre_instance_name}")
            self._ivre_entity = self.helper.api.identity.create(
                type="Organization",
                name=self.ivre_instance_name,
                description=f"IVRE instance {self.ivre_instance_name}\nSee <https://ivre.rocks/>",
            )["id"]
        else:
            self._ivre_entity = ivre_entity["id"]
        return self._ivre_entity

    def add_asn(self, asnum, asname=None):
        """Given an AS number and optionally an AS name, creates an observable
        and return its ID.

        """
        return self.helper.api.stix_cyber_observable.create(
            observableData={
                "type": TYPE_AS.lower(),
                "number": asnum,
                "name": asname or f"AS{asnum}",
            },
            update=True,
        )["id"]

    def add_addr(self, addr):
        """Given an IP address, creates an observable and returns its ID."""
        return self.helper.api.stix_cyber_observable.create(
            observableData={
                "type": (TYPE_IPV6_ADDR if ":" in addr else TYPE_IPV4_ADDR).lower(),
                "value": addr,
            },
            update=True,
        )["id"]

    def add_mac(self, addr):
        """Given a MAC address, creates an observable and returns its ID."""
        return self.helper.api.stix_cyber_observable.create(
            observableData={"type": TYPE_MAC_ADDR, "value": addr},
            update=True,
        )["id"]

    def add_domain(self, name):
        """Given a domain name, creates an observable and returns its ID."""
        return self.helper.api.stix_cyber_observable.create(
            observableData={
                "type": TYPE_DOMAIN.lower(),
                "value": name.lower(),
            },
            update=True,
        )["id"]

    def add_country(self, name, code):
        return self.helper.api.location.create(
            name=name,
            type="Country",
            country=name,
            custom_properties={
                "x_opencti_location_type": "Country",
                "x_opencti_aliases": [name, code],
            },
        )["id"]

    def add_city(self, city_name, country_name, country_code):
        country_id = self.add_country(country_name, country_code)
        city_id = self.helper.api.location.create(
            name=city_name,
            type="City",
            country=country_name,
            custom_properties={"x_opencti_location_type": "City"},
        )["id"]
        self.link_core(city_id, country_id, rel_type="located-at")
        return city_id

    def add_and_link_cert(self, cert, obs_id, firstseen, lastseen):
        """Given a parsed certificate (content of the "infos" field in the
        passive database, or the "ssl-cert" structured script output in the
        scans database), the observable id, the firstseen and lastseen values
        (as datetime.datetime instances), produce the object and the
        relationship between the observable and that object.

        """
        data = {
            "type": TYPE_CERT.lower(),
            # "serial_number": xxx,
            # "version": xxx,
            "hashes": {
                key: cert[key] for key in ["md5", "sha1", "sha256"] if key in cert
            },
            "is_self_signed": cert["self_signed"],
        }
        for fld in ["not_after", "not_before"]:
            if fld in cert:
                data[f"validity_{fld}"] = cert[fld].strftime("%Y-%m-%dT%H:%M:%SZ")
        for fld in ["issuer", "subject"]:
            if f"{fld}_text" in cert:
                data[fld] = cert[f"{fld}_text"].replace("/", ", ")
        if "pubkey" in cert:
            pubkey = cert["pubkey"]
            if "type" in pubkey:
                data["subject_public_key_algorithm"] = pubkey["type"]
            if "exponent" in pubkey:
                data["subject_public_key_exponent"] = pubkey["exponent"]
            if "modulus" in pubkey:
                data["subject_public_key_modulus"] = pubkey["modulus"]
        cert_id = self.helper.api.stix_cyber_observable.create(
            observableData=data,
            update=True,
        )["id"]
        self.link_cyber(obs_id, cert_id, firstseen, lastseen)
        if all(
            TOR_CERT_SUBJECT.search(cert.get(f"{fld}_text", ""))
            for fld in ["issuer", "subject"]
        ):
            self.add_and_link_label(
                "Possible TOR Node",
                obs_id,
                color="#7e4ec2",
            )
            self.add_and_link_label(
                "Possible TOR Certificate",
                cert_id,
                color="#7e4ec2",
            )

    def add_and_link_label(self, value, obs_id, color="#ffffff"):
        label_id = self.helper.api.label.create(value=value, color=color)["id"]
        self.helper.api.stix_cyber_observable.add_label(id=obs_id, label_id=label_id)

    def link_cyber(
        self, from_id, to_id, firstseen, lastseen, rel_type="x_opencti_linked-to"
    ):
        self.helper.api.stix_cyber_observable_relationship.create(
            fromId=from_id,
            toId=to_id,
            createdBy=self.ivre_entity,
            relationship_type=rel_type,
            update=True,
            confidence=self.confidence,
            start_time=firstseen.strftime("%Y-%m-%dT%H:%M:%SZ"),
            stop_time=lastseen.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    def link_core(self, from_id, to_id, rel_type="related-to"):
        self.helper.api.stix_core_relationship.create(
            fromId=from_id,
            toId=to_id,
            createdBy=self.ivre_entity,
            relationship_type=rel_type,
            update=True,
            confidence=self.confidence,
        )

    def link_domain_parent(self, domain, parent, parent_id):
        """Link a domain to one of its parent, creating all the sub-domains
        needed. The caller **has** to make sure that `domain` is a subdomain
        of `parent`! Returns the ID of the observable created for `domain`.

        """
        subdomain = domain[: -(len(parent) + 1)]
        domain_id = cur_dom = self.add_domain(domain)
        while "." in subdomain:
            subdomain = subdomain.split(".", 1)[1]
            next_dom = self.add_domain(f"{subdomain}.{parent}")
            self.link_core(cur_dom, next_dom)
            cur_dom = next_dom
        self.link_core(cur_dom, parent_id)
        return domain_id

    def process_scans_record(self, record, observable):
        """Process a `record` from the scans (nmap) purpose; the query was
        made based on `observable`.

        """
        obs_id = observable["id"]
        obs_type = observable["entity_type"]
        firstseen = record.get("starttime", record.get("endtime"))
        lastseen = record.get("endtime", record.get("starttime"))
        if obs_type in TYPES_IP_ADDR:
            addr_id = obs_id
        else:
            addr_id = self.add_addr(record["addr"])
        if obs_type == TYPE_DOMAIN:
            obs_name = observable["value"].lower().rstrip(".")
        for hname in record.get("hostnames", []):
            if hname["type"] in {"A", "PTR"}:  # Should we add all the hostnames?
                name = hname["name"].lower().rstrip(".")
                if obs_type == TYPE_DOMAIN:
                    if name == obs_name:
                        self.link_cyber(
                            obs_id, addr_id, firstseen, lastseen, rel_type="resolves-to"
                        )
                        continue
                    if name.endswith(f".{obs_name}"):
                        new_obs_id = self.link_domain_parent(name, obs_name, obs_id)
                        self.link_cyber(
                            new_obs_id,
                            addr_id,
                            firstseen,
                            lastseen,
                            rel_type="resolves-to",
                        )
                        continue
                name_id = self.add_domain(name)
                self.link_cyber(
                    name_id, addr_id, firstseen, lastseen, rel_type="resolves-to"
                )
        for port in record.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "ssl-cert":
                    for cert in script.get("ssl-cert", []):
                        self.add_and_link_cert(cert, addr_id, firstseen, lastseen)

    def process_passive_record(self, record, observable):
        """Process a `record` from the passive purpose; the query was made
        based on `observable`.

        """
        obs_id = observable["id"]
        obs_type = observable["entity_type"]
        firstseen = record.get("firstseen", record.get("lastseen"))
        lastseen = record.get("lastseen", record.get("firstseen"))
        # Records with no addr fields are only handled for DNS
        if record.get("addr") is None:
            if "targetval" not in record:
                return
            if obs_type != TYPE_DOMAIN:
                return
            if record["recontype"] != "DNS_ANSWER":
                return
            obs_name = observable["value"].lower().rstrip(".")
            new_ids = {}
            for fld in ["value", "targetval"]:
                val = record[fld].lower().rstrip(".")
                if val == obs_name:
                    new_ids[fld] = obs_id
                elif val.endswith(f".{obs_name}"):
                    new_ids[fld] = self.link_domain_parent(val, obs_name, obs_id)
                else:
                    new_ids[fld] = self.add_domain(val)
            try:
                self.link_cyber(
                    new_ids["value"],
                    new_ids["targetval"],
                    firstseen,
                    lastseen,
                    rel_type="resolves-to",
                )
            except ValueError:
                # Workaround for a bug fixed in
                # e38bf150ab70b145bafcdea77351bf4199078401 (GH#1692)
                self.link_cyber(
                    new_ids["value"],
                    new_ids["targetval"],
                    firstseen,
                    lastseen,
                )
            return
        addr_id = self.add_addr(record["addr"])
        if obs_type == TYPE_AS:
            self.link_core(addr_id, obs_id, rel_type="belongs-to")
        if obs_type == TYPE_CERT:
            self.link_cyber(addr_id, obs_id, firstseen, lastseen)
            return
        if obs_type == TYPE_MAC_ADDR:
            self.link_cyber(
                addr_id, obs_id, firstseen, lastseen, rel_type="resolves-to"
            )
            return
        if obs_type == TYPE_DOMAIN:
            obs_name = observable["value"].lower().rstrip(".")
            value = record["value"].lower().rstrip(".")
            if value == obs_name:
                self.link_cyber(
                    obs_id, addr_id, firstseen, lastseen, rel_type="resolves-to"
                )
            elif value.endswith(f".{obs_name}"):
                new_obs_id = self.link_domain_parent(value, obs_name, obs_id)
                self.link_cyber(
                    new_obs_id, addr_id, firstseen, lastseen, rel_type="resolves-to"
                )
            else:
                self.helper.log_warning(
                    f"BUG! Unexpected record found for domain {obs_name} [{record!r}]"
                )
            return
        # obs_type is either an IP address or a
        # "generator" of IP addresses (e.g., an AS)
        if record["recontype"] == "DNS_ANSWER":
            value = record["value"].lower().rstrip(".")
            name_id = self.add_domain(value)
            self.link_cyber(
                name_id, addr_id, firstseen, lastseen, rel_type="resolves-to"
            )
            return
        if record["recontype"] == "SSL_SERVER":
            if record.get("source") != "cert":
                return
            if "infos" not in record:
                return
            self.add_and_link_cert(record["infos"], addr_id, firstseen, lastseen)
            return
        if record["recontype"] == "MAC_ADDRESS":
            self.link_cyber(
                addr_id,
                self.add_mac(record["value"]),
                firstseen,
                lastseen,
                rel_type="resolves-to",
            )
            return
        if record.get("infos", {}).get("service_name") == "scanner":
            # if record["recontype"] == "UDP_HONEYPOT_HIT":  # spoofable
            self.add_and_link_label(
                f"Scanner {record['infos'].get('service_product', '(unknown)')}",
                addr_id,
                color="#ff8178",
            )
        elif record["recontype"] in {
            "HTTP_HONEYPOT_REQUEST",
            "DNS_HONEYPOT_QUERY",
            "TCP_HONEYPOT_HIT",
            "UDP_HONEYPOT_HIT",
        }:
            self.add_and_link_label("Scanner (unknown)", addr_id, color="#ff8178")

    def process_data_observable(self, observable):
        if observable["entity_type"] not in TYPES_IP_ADDR:
            return
        result = self.dbase.data.infos_byip(observable["value"])
        if not result:
            return
        if "country_name" in result:
            if "city" in result:
                loc_id = self.add_city(
                    result["city"], result["country_name"], result["country_code"]
                )
            else:
                loc_id = self.add_country(
                    result["country_name"], result["country_code"]
                )
            self.link_core(observable["id"], loc_id, rel_type="located-at")
        if "registered_country_name" in result and result[
            "registered_country_name"
        ] != result.get("country_name"):
            country_id = self.add_country(
                result["registered_country_name"], result["registered_country_code"]
            )
            self.link_core(observable["id"], country_id, rel_type="located-at")
        if "as_num" in result:
            asn_id = self.add_asn(result["as_num"], result.get("as_name"))
            self.link_core(observable["id"], asn_id, rel_type="belongs-to")

    def process_passive_observable(self, observable):
        obs_type = observable["entity_type"]
        if obs_type == TYPE_AS:
            if not self.use_passive_as:
                return
            flts = [self.dbase.passive.searchasnum(observable["number"])]
        elif obs_type == TYPE_DOMAIN:
            if not self.use_passive_domain:
                return
            flts = [
                self.dbase.passive.searchdns(observable["value"].lower().rstrip(".")),
                self.dbase.passive.searchdns(
                    observable["value"].lower().rstrip("."), reverse=True
                ),
            ]
        elif obs_type in TYPES_IP_ADDR:
            flts = [self.dbase.passive.searchhost(observable["value"])]
        elif obs_type == TYPE_MAC_ADDR:
            flts = [self.dbase.passive.searchmac(observable["value"])]
        elif obs_type == TYPE_CERT:
            flt_args = None
            if "hashes" in observable:
                for algo in ["sha256", "sha1", "md5"]:
                    for entry in observable["hashes"]:
                        if entry["algorithm"].lower() == algo:
                            flt_args = {algo: entry["hash"].lower()}
                            break
                    if flt_args is not None:
                        break
            if flt_args is None:
                for field in ["observable_value", "value"]:
                    if field in observable:
                        value = observable[field]
                        if HEX.search(value):
                            try:
                                flt_args = {
                                    {32: "md5", 40: "sha1", 64: "sha256"}[
                                        len(value)
                                    ]: value.lower()
                                }
                            except KeyError:
                                pass
                            else:
                                break
            if flt_args is None:
                self.helper.log_warning(
                    f"Cannot process X509-Certificate observable [{observable!r}]"
                )
                return
            flts = [self.dbase.passive.searchcert(**flt_args)]
        for flt in flts:
            for rec in self.dbase.passive.get(flt):
                self.process_passive_record(rec, observable)

    def process_scans_observable(self, observable):
        obs_type = observable["entity_type"]
        if obs_type == TYPE_AS:
            if not self.use_scans_as:
                return
            flt = self.dbase.nmap.searchasnum(observable["number"])
        elif obs_type == TYPE_DOMAIN:
            if not self.use_scans_domain:
                return
            flt = self.dbase.nmap.searchdomain(observable["value"].lower().rstrip("."))
        elif obs_type in TYPES_IP_ADDR:
            flt = self.dbase.nmap.searchhost(observable["value"])
        elif obs_type == TYPE_MAC_ADDR:
            flt = self.dbase.nmap.searchmac(observable["value"])
        elif obs_type == TYPE_CERT:
            flt_args = None
            if "hashes" in observable:
                for algo in ["sha256", "sha1", "md5"]:
                    for entry in observable["hashes"]:
                        if entry["algorithm"].lower() == algo:
                            flt_args = {algo: entry["hash"].lower()}
                            break
                    if flt_args is not None:
                        break
            if flt_args is None:
                for field in ["observable_value", "value"]:
                    if field in observable:
                        value = observable[field]
                        if HEX.search(value):
                            try:
                                flt_args = {
                                    {32: "md5", 40: "sha1", 64: "sha256"}[
                                        len(value)
                                    ]: value.lower()
                                }
                            except KeyError:
                                pass
                            else:
                                break
            if flt_args is None:
                self.helper.log_warning(
                    f"Cannot process X509-Certificate observable [{observable!r}]"
                )
                return
            flt = self.dbase.nmap.searchcert(**flt_args)
        for rec in self.dbase.nmap.get(flt):
            self.process_scans_record(rec, observable)

    def _process_message(self, data):
        """Process a message, depending on its type."""
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if observable is None:
            return
        # Extract TLP
        tlp = "TLP:WHITE"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]
                break

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        if self.use_data:
            self.process_data_observable(observable)
        if self.use_passive:
            self.process_passive_observable(observable)
        if self.use_scans:
            self.process_scans_observable(observable)

    def start(self):
        """Starts the connector."""
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    IvreConnector().start()
