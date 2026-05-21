import sys
import types
from pathlib import Path

pycti_stub = types.ModuleType("pycti")


class OpenCTIConnectorHelperStub:
    @staticmethod
    def get_attribute_in_extension(key: str, data: dict) -> str:
        return data.get(key, "indicator--test")


def get_config_variable_stub(*args, **kwargs) -> str:
    return "http://opencti.local"


pycti_stub.OpenCTIConnectorHelper = OpenCTIConnectorHelperStub
pycti_stub.get_config_variable = get_config_variable_stub
sys.modules.setdefault("pycti", pycti_stub)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from elastic_security_intel_connector.api_handler import ElasticApiHandler


class DummyLogger:
    def debug(self, *args, **kwargs):
        return None


class DummyHelper:
    connector_logger = DummyLogger()


class DummyConfig:
    elastic_url = "https://elastic.local"
    elastic_api_key = "test"
    elastic_client_cert = None
    elastic_client_key = None
    elastic_verify_ssl = False
    elastic_ca_cert = None
    elastic_index_name = "opencti-indicators"
    elastic_opencti_external_url = None

    @staticmethod
    def load():
        return {}


def _create_handler() -> ElasticApiHandler:
    return ElasticApiHandler(DummyHelper(), DummyConfig())


def test_convert_to_ecs_threat_parses_ipv6_pattern_case_insensitive():
    handler = _create_handler()
    indicator_data = {
        "type": "indicator",
        "id": "indicator--ipv6",
        "pattern_type": "stix",
        "pattern": "[IPv6-Addr:value = '2001:db8::1']",
        "name": "IPv6 IOC",
        "created": "2026-01-01T00:00:00Z",
        "modified": "2026-01-02T00:00:00Z",
    }

    result = handler._convert_to_ecs_threat(indicator_data)

    assert result["threat"]["indicator"]["type"] == "ipv6-addr"
    assert result["threat"]["indicator"]["ip"] == ["2001:db8::1"]
    assert result["related"]["ip"] == ["2001:db8::1"]


def test_convert_to_ecs_threat_parses_user_account_pattern():
    handler = _create_handler()
    indicator_data = {
        "type": "indicator",
        "id": "indicator--user-account",
        "pattern_type": "stix",
        "pattern": "[User-Account:user_id = 'alice']",
        "name": "User account IOC",
        "created": "2026-01-01T00:00:00Z",
        "modified": "2026-01-02T00:00:00Z",
    }

    result = handler._convert_to_ecs_threat(indicator_data)

    assert result["threat"]["indicator"]["type"] == "user-account"
    assert result["threat"]["indicator"]["user"] == {"id": "alice"}
    assert result["related"]["user"] == ["alice"]
