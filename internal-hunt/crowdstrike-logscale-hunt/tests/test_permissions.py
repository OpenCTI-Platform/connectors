def test_declares_its_permissions_and_what_a_refused_account_lacks(connector_factory):
    # Given/When the connector is started
    connector = connector_factory()

    # Then it declares its least-privilege permissions, its setup documentation
    # and what a refused account lacks
    assert connector.required_permissions
    assert connector.documentation_url.startswith(
        "https://docs.opencti.io/latest/usage/hunt-connectors/#"
    )
    assert set(connector.client.access_denied_hints) == {401, 403}
