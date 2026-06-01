from internal_enrichment_connector.yaml_validator import YAMLValidator


class _ResolverAvailable:
    is_available = True

    def validate_names(self, names: list[str]) -> list[str]:
        known = {"Network Traffic", "Firewall"}
        return [name for name in names if name not in known]


class _ResolverUnavailable:
    is_available = False

    def validate_names(self, names: list[str]) -> list[str]:
        return names


def test_all_valid():
    validator = YAMLValidator(_ResolverAvailable())
    data = {
        "sourcetype_map": {
            "cisco:asa": {
                "entity_type": "Infrastructure",
                "mitre_data_sources": ["Network Traffic", "Firewall"],
                "infrastructure_types": ["firewall"],
            },
            "okta:auth": {
                "entity_type": "SecurityPlatform",
                "mitre_data_sources": ["Network Traffic"],
            },
        }
    }

    result = validator.validate(data)
    assert result.valid is True
    assert result.errors == []


def test_invalid_data_source_name():
    validator = YAMLValidator(_ResolverAvailable())
    data = {
        "sourcetype_map": {
            "cisco:asa": {
                "entity_type": "Infrastructure",
                "mitre_data_sources": ["Typo Source"],
                "infrastructure_types": ["firewall"],
            }
        }
    }

    result = validator.validate(data)
    assert any("invalid MITRE data source" in e for e in result.errors)


def test_invalid_infrastructure_type():
    validator = YAMLValidator(_ResolverAvailable())
    data = {
        "sourcetype_map": {
            "cisco:asa": {
                "entity_type": "Infrastructure",
                "mitre_data_sources": ["Network Traffic"],
                "infrastructure_types": ["cloud-service"],
            }
        }
    }

    result = validator.validate(data)
    assert any("invalid infrastructure_type" in e for e in result.errors)


def test_missing_mitre_data_sources():
    validator = YAMLValidator(_ResolverAvailable())
    data = {
        "sourcetype_map": {
            "cisco:asa": {
                "entity_type": "Infrastructure",
                "infrastructure_types": ["firewall"],
            }
        }
    }

    result = validator.validate(data)
    assert any("missing mitre_data_sources" in w for w in result.warnings)


def test_missing_infrastructure_types():
    validator = YAMLValidator(_ResolverAvailable())
    data = {
        "sourcetype_map": {
            "cisco:asa": {
                "entity_type": "Infrastructure",
                "mitre_data_sources": ["Network Traffic"],
            }
        }
    }

    result = validator.validate(data)
    assert any("missing infrastructure_types" in w for w in result.warnings)


def test_invalid_entity_type():
    validator = YAMLValidator(_ResolverAvailable())
    data = {
        "sourcetype_map": {
            "cisco:asa": {
                "entity_type": "Software",
                "mitre_data_sources": ["Network Traffic"],
            }
        }
    }

    result = validator.validate(data)
    assert any("invalid entity_type" in e for e in result.errors)


def test_mixed_valid_invalid():
    validator = YAMLValidator(_ResolverAvailable())
    data = {
        "sourcetype_map": {
            "valid:entry": {
                "entity_type": "Infrastructure",
                "mitre_data_sources": ["Network Traffic"],
                "infrastructure_types": ["firewall"],
            },
            "invalid:entry": {
                "entity_type": "Software",
                "mitre_data_sources": ["Bad Source"],
                "infrastructure_types": ["bad-type"],
            },
        }
    }

    result = validator.validate(data)
    assert result.valid is False
    assert len(result.errors) >= 3


def test_resolver_unavailable_warns():
    validator = YAMLValidator(_ResolverUnavailable())
    data = {
        "sourcetype_map": {
            "cisco:asa": {
                "entity_type": "Infrastructure",
                "mitre_data_sources": ["Network Traffic"],
                "infrastructure_types": ["firewall"],
            }
        }
    }

    result = validator.validate(data)
    assert any("resolver unavailable" in w for w in result.warnings)
