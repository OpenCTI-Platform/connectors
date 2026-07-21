import main as main_module
from trukno_connector.client import TruKnoClient
from trukno_connector.config import ConnectorConfig
from trukno_connector.state import ConnectorState


def test_entrypoint_imports():
    assert main_module is not None
    assert TruKnoClient is not None
    assert ConnectorConfig is not None
    assert ConnectorState is not None
