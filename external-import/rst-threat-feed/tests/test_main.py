def test_main_module_exports_connector():
    from connector import ConnectorSettings, RSTThreatFeed

    assert RSTThreatFeed is not None
    assert ConnectorSettings is not None
