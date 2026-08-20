def test_main_module_imports_cleanly():
    """Importing the entry point must not execute the run block or raise."""
    import main

    assert hasattr(main, "VisionHeightConnector")
    assert hasattr(main, "ConnectorSettings")
