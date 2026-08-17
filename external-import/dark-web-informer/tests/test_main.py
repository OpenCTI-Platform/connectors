"""Tests for the connector entry point."""

from unittest.mock import MagicMock, patch


def test_main_wires_helper_and_runs_connector(mock_env):
    import main

    with (
        patch.object(main, "OpenCTIConnectorHelper") as helper_cls,
        patch.object(main, "DarkWebInformerConnector") as connector_cls,
    ):
        connector_cls.return_value = MagicMock()

        main.main()

        helper_cls.assert_called_once()
        connector_cls.assert_called_once_with(
            helper=helper_cls.return_value,
            settings=connector_cls.call_args.kwargs["settings"],
        )
        connector_cls.return_value.run.assert_called_once()
