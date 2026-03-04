from dataclasses import asdict, dataclass

import factory
from factory import fuzzy


@dataclass
class Malware:
    name: str
    subsystem: str


@dataclass
class C2FeedExtra:
    status_code: int
    geoip_city: str
    geoip_country: str
    geoip_asn: str
    geoip_asn_num: int
    geoip_subnetwork: str
    domain_private_name: str
    domain_type: str


@dataclass
class C2Feed:
    ip: str
    hostname: str
    scan_uri: str
    timestamp: str
    port: int
    malware: Malware
    extra: C2FeedExtra
    confidence: int

    def to_dict(self):
        result = asdict(self)
        result.update({"malware_name": result["malware"].pop("name")})
        result.update({"malware_subsystem": result["malware"].pop("subsystem")})
        result.pop("malware")
        return result


class MalwareFactory(factory.Factory):
    class Meta:
        model = Malware

    name = fuzzy.FuzzyChoice(["Keitaro", "Tactical RMM"])
    subsystem = fuzzy.FuzzyChoice(["C2", "Team Server", "Victim"])


class C2FeedExtraFactory(factory.Factory):
    class Meta:
        model = C2FeedExtra

    status_code = factory.Faker("random_int", min=100, max=599)
    geoip_city = factory.Faker("city")
    geoip_country = factory.Faker("country")
    geoip_asn = factory.Faker("word")
    geoip_asn_num = factory.Faker("random_int", min=1, max=65535)
    geoip_subnetwork = factory.Faker("ipv4", network=True)
    domain_private_name = factory.Faker("domain_name")
    domain_type = factory.Faker("word")


class C2FeedFactory(factory.Factory):
    class Meta:
        model = C2Feed

    ip = factory.Faker("ipv4")
    hostname = factory.Faker("domain_name")
    scan_uri = factory.Faker("url")
    timestamp = factory.Faker("iso8601")
    port = factory.Faker("random_int", min=1, max=65535)
    confidence = factory.Faker("random_int", min=1, max=100)
    malware = factory.SubFactory(MalwareFactory)
    extra = factory.SubFactory(C2FeedExtraFactory)
