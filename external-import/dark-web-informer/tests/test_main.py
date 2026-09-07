"""Tests for the connector entry point."""

from unittest.mock import patch


def test_main_wires_helper_and_runs_connector():
    import main

    with (
        patch.object(main, "ConnectorSettings") as settings_cls,
        patch.object(main, "OpenCTIConnectorHelper") as helper_cls,
        patch.object(main, "DarkWebInformerConnector") as connector_cls,
    ):
        main.main()

        settings = settings_cls.return_value
        helper_cls.assert_called_once_with(
            config=settings.to_helper_config.return_value
        )
        connector_cls.assert_called_once_with(
            helper=helper_cls.return_value, settings=settings
        )
        connector_cls.return_value.run.assert_called_once()
