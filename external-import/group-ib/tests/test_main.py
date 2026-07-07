from __future__ import annotations

import runpy
from unittest.mock import MagicMock, patch

import main
import pytest


class TestMainModule:
    def test_module_imports_cleanly(self):
        # The module body runs ``dotenv.load_dotenv()`` + defines the
        # ``CustomConnector`` class. Verify both still happen.
        assert hasattr(main, "CustomConnector")
        assert hasattr(main, "dotenv")
        # CustomConnector inherits from ExternalImportConnector.
        from connector.connector import ExternalImportConnector

        assert issubclass(main.CustomConnector, ExternalImportConnector)

    def test_custom_connector_delegates_to_pipeline(self):
        # ``CustomConnector._collect_intelligence`` forwards to the
        # ``pipeline.collect_intelligence`` helper.
        with patch(
            "main.collect_intelligence", return_value=[1, 2, 3]
        ) as mock_pipeline:
            conn = main.CustomConnector.__new__(main.CustomConnector)
            conn.helper = MagicMock()
            out = conn._collect_intelligence(
                collection="apt/threat",
                ttl=30,
                event={},
                mitre_mapper={"T1": "x"},
                config=MagicMock(),
                flag_intrusion_set_instead_of_threat_actor=True,
            )
            mock_pipeline.assert_called_once()
            call_kwargs = mock_pipeline.call_args.kwargs
            assert call_kwargs["collection"] == "apt/threat"
            assert call_kwargs["ttl"] == 30
            assert call_kwargs["mitre_mapper"] == {"T1": "x"}
            assert call_kwargs["flag_intrusion_set_instead_of_threat_actor"] is True
            assert out == [1, 2, 3]


class TestMainEntrypoint:
    """``runpy.run_module(... run_name="__main__")`` re-imports the
    target from scratch, so outside-patches on ``main.CustomConnector``
    don't apply — the fresh ``main`` module pulls in the real connector
    class. The real constructor needs a live OpenCTI platform and so
    raises an exception; ``main.py``'s ``try/except SystemExit(1)`` block
    catches it. Both branches we want covered run as a result, so we
    just assert the SystemExit path.
    """

    def test_main_block_runs_and_exits_cleanly_on_constructor_failure(self):
        # Constructor reaches out to pycti's ``OpenCTIConnectorHelper({})``,
        # which fails without env / platform connectivity. ``main.py``
        # catches and converts to ``SystemExit(1)``.
        with pytest.raises(SystemExit) as excinfo:
            runpy.run_module("main", run_name="__main__")
        assert excinfo.value.code == 1

    def test_main_block_exits_when_construction_raises(self):
        # Same path, this time forcing a controlled exception inside the
        # base ``ExternalImportConnector.__init__``.
        with patch(
            "connector.connector.OpenCTIConnectorHelper",
            side_effect=RuntimeError("boot fail"),
        ):
            with pytest.raises(SystemExit) as excinfo:
                runpy.run_module("main", run_name="__main__")
            assert excinfo.value.code == 1
