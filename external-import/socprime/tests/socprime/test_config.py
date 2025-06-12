import pytest
from socprime import SocprimeConnector

pytestmark = pytest.mark.usefixtures(
    "mocked_opencti_helper",
    "mock_socprime_config",
    "mocked_mitre_attack_requests",
)


def test_config() -> None:
    connector = SocprimeConnector()

    assert connector.helper.opencti_url == "http://test-opencti-url/"
    assert connector.helper.opencti_token == "test-opencti-token"

    assert connector.helper.connect_id == "test-connector-id"
    assert connector.helper.connect_name == "Soc Prime"
    assert connector.helper.connect_type == "EXTERNAL_IMPORT"
    assert connector.helper.connect_scope == "socprime"
    assert connector.helper.log_level == "ERROR"

    assert connector.tdm_api_client._api_key == "api-key"
    assert connector._content_list_names == "name1,name2"
    assert connector._job_ids == "job1,job2"
    assert connector._siem_types_for_refs == "devo,snowflake"
    assert connector._indicator_siem_type == "ChangeMe"
    assert connector.interval_sec == 2000
