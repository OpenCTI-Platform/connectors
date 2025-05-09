import pytest
from hygiene import HygieneConnector


def _generate_mock_stix_domain_entity(domain_name: str) -> dict:
    entity = {
        "type": "domain-name",
        "value": domain_name,
        "labels": [],
    }
    return entity


def _generate_mock_opencti_indiator_entity(domain_name: str) -> dict:
    entity = {
        "entity_type": "Indicator",
        "value": domain_name,
        "observable_value": domain_name,
        "labels": [],
    }
    return entity


@pytest.fixture()
def mock_hygiene_connector(mock_opencti) -> HygieneConnector:
    """Dummy Hygiene Connector."""
    return HygieneConnector()


@pytest.fixture()
def mock_hygiene_connector_with_subdomain_search(
    mock_opencti, mock_config_path
) -> HygieneConnector:
    return HygieneConnector(config_file_path=mock_config_path)


def test_warninglist_search_functions(mock_hygiene_connector: HygieneConnector):
    mock_domain = "www.google.com"
    mock_stix_entity = _generate_mock_stix_domain_entity(mock_domain)
    warninglist_hits = mock_hygiene_connector.warninglists.search(mock_domain)
    assert len(warninglist_hits) >= 1
    use_parent, warninglist_hits = mock_hygiene_connector.search_with_parent(
        result=warninglist_hits, stix_entity=mock_stix_entity
    )
    assert isinstance(warninglist_hits, list)
    assert isinstance(use_parent, bool)
    assert use_parent is False
    octi_entity = _generate_mock_opencti_indiator_entity(domain_name=mock_domain)
    score = mock_hygiene_connector.process_result(
        warninglist_hits=warninglist_hits,
        stix_entity=mock_stix_entity,
        opencti_entity=octi_entity,
        use_parent=False,
        stix_objects=[],
    )
    assert isinstance(score, int)
    assert (score < 30) and (score >= 0)


def test_warninglist_search_function_with_subdomain_search(
    mock_hygiene_connector_with_subdomain_search,
):
    hygiene_connector = mock_hygiene_connector_with_subdomain_search
    assert hygiene_connector.enrich_subdomains
    mock_domain = "cradle.doc.google.com"
    mock_stix_entity = _generate_mock_stix_domain_entity(mock_domain)
    use_parent, warninglist_hits = hygiene_connector.search_with_parent(
        [], mock_stix_entity
    )
    assert isinstance(warninglist_hits, list)
    assert isinstance(use_parent, bool)
    assert use_parent is True
