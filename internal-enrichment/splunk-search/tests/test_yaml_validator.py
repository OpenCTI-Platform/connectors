from internal_enrichment_connector.yaml_validator import YAMLValidator


class _ResolverAvailable:
    is_available = True

    def validate_names(self, names: list[str]) -> list[str]:
        known = {
            "Network Traffic",
            "Firewall",
            "Process",
            "File",
            "Application Log",
        }
        return [name for name in names if name not in known]


class _ResolverUnavailable:
    is_available = False

    def validate_names(self, names: list[str]) -> list[str]:
        return names


class _MapperAvailable:
    is_available = True

    def resolve(self, sourcetype_entry: dict) -> list[str]:
        datamodels = sourcetype_entry.get("datamodels") or []
        mapping = {
            "Network_Traffic": ["Network Traffic"],
            "Malware": ["File"],
            "Vulnerabilities": ["Application Log"],
            "Performance": [],
        }
        out = set()
        for model in datamodels:
            for source in mapping.get(model, []):
                out.add(source)
        return sorted(out)


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
    assert any("missing MITRE coverage" in w for w in result.warnings)


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
                "entity_type": "NotValid",
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
                "entity_type": "Infrastructure",
                "mitre_data_sources": ["Bad Source"],
                "infrastructure_types": ["bad-type"],
            },
        }
    }

    result = validator.validate(data)
    assert result.valid is False
    assert len(result.errors) >= 2


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


def test_software_entity_type_valid():
    validator = YAMLValidator(_ResolverAvailable())
    data = {
        "sourcetype_map": {
            "linux:syslog": {
                "entity_type": "Software",
                "vendor": "Linux",
                "product": "syslog",
            }
        }
    }

    result = validator.validate(data)
    assert result.valid is True
    assert result.errors == []


def test_software_no_infrastructure_warning():
    validator = YAMLValidator(_ResolverAvailable())
    data = {
        "sourcetype_map": {
            "linux:syslog": {
                "entity_type": "Software",
            }
        }
    }

    result = validator.validate(data)
    assert not any("infrastructure_types" in w for w in result.warnings)
    assert not any("MITRE coverage" in w for w in result.warnings)


def test_skip_entries_ignored():
    validator = YAMLValidator(_ResolverAvailable())
    data = {
        "sourcetype_map": {
            "splunk:internal": {
                "entity_type": "Infrastructure",
                "skip": True,
                "infrastructure_types": ["invalid-type"],
            }
        }
    }

    result = validator.validate(data)
    assert result.valid is True
    assert result.errors == []
    assert result.warnings == []


def test_normalizable_type_warns_not_errors():
    validator = YAMLValidator(_ResolverAvailable())
    data = {
        "sourcetype_map": {
            "foo:bar": {
                "entity_type": "Infrastructure",
                "mitre_data_sources": ["Network Traffic"],
                "infrastructure_types": ["endpoint-security"],
            }
        }
    }

    result = validator.validate(data)
    assert not any("endpoint-security" in e for e in result.errors)
    assert any("normalizable infrastructure_type 'endpoint-security'" in w for w in result.warnings)


def test_unknown_type_errors():
    validator = YAMLValidator(_ResolverAvailable())
    data = {
        "sourcetype_map": {
            "foo:bar": {
                "entity_type": "Infrastructure",
                "mitre_data_sources": ["Network Traffic"],
                "infrastructure_types": ["definitely-unknown-type"],
            }
        }
    }

    result = validator.validate(data)
    assert any("definitely-unknown-type" in e for e in result.errors)


def test_cim_datamodel_resolution_used_when_no_explicit_sources():
    validator = YAMLValidator(_ResolverAvailable(), cim_mapper=_MapperAvailable())
    data = {
        "sourcetype_map": {
            "foo:bar": {
                "entity_type": "Infrastructure",
                "datamodels": ["Network_Traffic", "Malware"],
                "infrastructure_types": ["firewall"],
            }
        }
    }

    result = validator.validate(data)
    assert result.valid is True
    assert result.errors == []


def test_cim_no_resolution_warns_missing_coverage():
    validator = YAMLValidator(_ResolverAvailable(), cim_mapper=_MapperAvailable())
    data = {
        "sourcetype_map": {
            "foo:bar": {
                "entity_type": "Infrastructure",
                "datamodels": ["Performance"],
                "infrastructure_types": ["firewall"],
            }
        }
    }

    result = validator.validate(data)
    assert any("missing MITRE coverage" in w for w in result.warnings)
