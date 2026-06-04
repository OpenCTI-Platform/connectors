"""Unit tests for VC305 — connector must use connectors-sdk BaseConnectorSettings."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks

_SDK_SETTINGS = """\
from connectors_sdk.models.octi import BaseConnectorSettings

class ConnectorSettings(BaseConnectorSettings):
    my_api_key: str
"""

_CUSTOM_PYDANTIC_OK = """\
from pydantic_settings import BaseSettings

class ConnectorSettings(BaseSettings):
    opencti_url: str
    opencti_token: str
    connector_id: str
    connector_name: str
    connector_type: str
    connector_scope: str
    connector_log_level: str
"""

_LEGACY_DICT_OK = """\
# Legacy pycti-style: config dict loaded from YAML
import yaml

with open("config.yml") as f:
    config = yaml.load(f, Loader=yaml.FullLoader)
"""

_NO_SETTINGS = """\
import os

url = os.environ["OPENCTI_URL"]
token = os.environ["OPENCTI_TOKEN"]
"""


class TestVC305SdkBaseSettings:
    """VC305 checks for connectors-sdk or equivalent settings pattern."""

    def test_passes_sdk_base_settings(self, connector_src):
        path = connector_src(("src/main.py", _SDK_SETTINGS))
        results = run_checks(path, select=["VC305"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_passes_custom_pydantic(self, connector_src):
        """Custom BaseSettings subclass is acceptable (with WARNING)."""
        path = connector_src(("src/main.py", _CUSTOM_PYDANTIC_OK))
        results = run_checks(path, select=["VC305"])
        # Should pass — pydantic approach is acceptable
        errors = [r for r in results if r.severity == Severity.ERROR]
        assert len(errors) == 0

    def test_fails_no_settings(self, connector_src):
        """Bare os.environ usage without any settings class should fail."""
        path = connector_src(("src/main.py", _NO_SETTINGS))
        results = run_checks(path, select=["VC305"])
        assert any(r.severity == Severity.ERROR for r in results)
