from internal_enrichment_connector.infrastructure import InfrastructureBuilder


class _FakeResolver:
    def __init__(self):
        self.is_available = True

    def resolve_data_source(self, name: str):
        if name == "Network Traffic":
            return {
                "id": "x-mitre-data-source--abc",
                "name": "Network Traffic",
                "x_mitre_platforms": ["Network Device"],
            }
        return None

    def resolve_asset(self, name: str):
        if name == "Network Device":
            return {"name": "Network Device", "x_mitre_platforms": ["Router"]}
        return None

    def get_infrastructure_types(self, asset: dict):
        if asset.get("name") == "Network Device":
            return ["routers-switches"]
        return ["unknown"]


class _FakeMapper:
    is_available = True

    def resolve(self, entry: dict) -> list[str]:
        if entry.get("datamodels") == ["Network_Traffic"]:
            return ["Network Traffic"]
        return []


def test_build_firewall():
    builder = InfrastructureBuilder()
    entry = {
        "vendor": "Palo Alto Networks",
        "product": "Firewall",
        "entity_type": "Infrastructure",
        "description": "Palo Alto Networks Next-Gen Firewall",
        "infrastructure_types": ["firewall"],
    }

    obj = builder.build(entry)
    assert obj is not None
    assert obj["type"] == "infrastructure"
    assert "firewall" in obj["infrastructure_types"]


def test_skip_non_infrastructure():
    builder = InfrastructureBuilder()
    entry = {"entity_type": "SecurityPlatform"}

    assert builder.build(entry) is None


def test_deterministic_id():
    builder = InfrastructureBuilder()
    first = builder.generate_deterministic_id("Palo Alto Networks Firewall")
    second = builder.generate_deterministic_id("Palo Alto Networks Firewall")

    assert first == second
    assert first.startswith("infrastructure--")


def test_description_included():
    builder = InfrastructureBuilder()
    entry = {
        "vendor": "Cisco",
        "product": "ASA",
        "entity_type": "Infrastructure",
        "description": "Cisco ASA firewall platform",
        "infrastructure_types": ["firewall"],
    }

    obj = builder.build(entry)
    assert obj is not None
    assert "Cisco ASA firewall platform" in obj["description"]


def test_infrastructure_types_from_yaml():
    builder = InfrastructureBuilder()
    entry = {
        "vendor": "Cisco",
        "product": "ASA",
        "entity_type": "Infrastructure",
        "infrastructure_types": ["firewall"],
    }

    obj = builder.build(entry)
    assert obj is not None
    assert obj["infrastructure_types"] == ["firewall"]


def test_mitre_resolver_enrichment():
    builder = InfrastructureBuilder(mitre_resolver=_FakeResolver())
    entry = {
        "vendor": "Cisco",
        "product": "ASA",
        "entity_type": "Infrastructure",
        "mitre_data_sources": ["Network Traffic"],
        "infrastructure_types": ["firewall"],
    }

    obj = builder.build(entry)
    assert obj is not None
    assert "routers-switches" in obj["infrastructure_types"]


def test_without_resolver():
    builder = InfrastructureBuilder(mitre_resolver=None)
    entry = {
        "vendor": "Cisco",
        "product": "ASA",
        "entity_type": "Infrastructure",
        "infrastructure_types": ["firewall"],
    }

    obj = builder.build(entry)
    assert obj is not None
    assert obj["infrastructure_types"] == ["firewall"]


def test_normalize_endpoint_security():
    builder = InfrastructureBuilder()
    entry = {
        "vendor": "Vendor",
        "product": "Product",
        "entity_type": "Infrastructure",
        "infrastructure_types": ["endpoint-security"],
    }

    obj = builder.build(entry)
    assert obj is not None
    assert obj["infrastructure_types"] == ["workstation"]


def test_normalize_network_device():
    builder = InfrastructureBuilder()
    entry = {
        "vendor": "Vendor",
        "product": "Product",
        "entity_type": "Infrastructure",
        "infrastructure_types": ["network-device"],
    }

    obj = builder.build(entry)
    assert obj is not None
    assert obj["infrastructure_types"] == ["routers-switches"]


def test_normalize_ids():
    builder = InfrastructureBuilder()
    entry = {
        "vendor": "Vendor",
        "product": "Product",
        "entity_type": "Infrastructure",
        "infrastructure_types": ["ids"],
    }

    obj = builder.build(entry)
    assert obj is not None
    assert obj["infrastructure_types"] == ["unknown"]


def test_normalize_waf():
    builder = InfrastructureBuilder()
    entry = {
        "vendor": "Vendor",
        "product": "Product",
        "entity_type": "Infrastructure",
        "infrastructure_types": ["waf"],
    }

    obj = builder.build(entry)
    assert obj is not None
    assert obj["infrastructure_types"] == ["firewall"]


def test_unknown_type_not_in_map():
    builder = InfrastructureBuilder()
    entry = {
        "vendor": "Vendor",
        "product": "Product",
        "entity_type": "Infrastructure",
        "infrastructure_types": ["completely-unknown"],
    }

    obj = builder.build(entry)
    assert obj is not None
    assert obj["infrastructure_types"] == ["unknown"]


def test_original_type_in_description():
    builder = InfrastructureBuilder()
    entry = {
        "vendor": "Vendor",
        "product": "Product",
        "entity_type": "Infrastructure",
        "description": "Infra description",
        "infrastructure_types": ["network-device"],
    }

    obj = builder.build(entry)
    assert obj is not None
    assert "platform_type: network-device" in obj["description"]


def test_already_valid_stix_type():
    builder = InfrastructureBuilder()
    entry = {
        "vendor": "Vendor",
        "product": "Product",
        "entity_type": "Infrastructure",
        "infrastructure_types": ["firewall"],
    }

    obj = builder.build(entry)
    assert obj is not None
    assert obj["infrastructure_types"] == ["firewall"]


def test_mapper_resolve_used_when_no_explicit_sources():
    builder = InfrastructureBuilder(mitre_resolver=_FakeResolver(), cim_mapper=_FakeMapper())
    entry = {
        "vendor": "Cisco",
        "product": "ASA",
        "entity_type": "Infrastructure",
        "datamodels": ["Network_Traffic"],
        "infrastructure_types": ["firewall"],
    }

    obj = builder.build(entry)
    assert obj is not None
    assert "MITRE Data Sources: Network Traffic" in obj["description"]
    assert obj.get("external_references")
