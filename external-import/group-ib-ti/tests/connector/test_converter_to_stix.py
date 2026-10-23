from __future__ import annotations

from unittest.mock import MagicMock, patch

from connector.converter_to_stix import ConverterToStix


class TestConverterToStix:
    def test_stores_helper_and_config(self):
        helper = MagicMock()
        config = MagicMock()
        converter = ConverterToStix(helper=helper, config=config)
        assert converter.helper is helper
        assert converter.config is config

    def test_convert_event_forwards_every_argument(self):
        helper = MagicMock()
        config = MagicMock()
        converter = ConverterToStix(helper=helper, config=config)
        event = {"threat_report": {"id": "abc"}}

        with patch(
            "connector.converter_to_stix.collect_intelligence",
            return_value=["obj"],
        ) as mock_collect:
            out = converter.convert_event(
                collection="apt/threat",
                event=event,
                mitre_mapper={"T1059": "Command and Scripting Interpreter"},
                ttl=90,
                flag_intrusion_set_instead_of_threat_actor=True,
            )

        assert out == ["obj"]
        kwargs = mock_collect.call_args.kwargs
        assert kwargs["helper"] is helper
        assert kwargs["config"] is config
        assert kwargs["collection"] == "apt/threat"
        assert kwargs["event"] is event
        assert kwargs["ttl"] == 90
        assert kwargs["mitre_mapper"] == {"T1059": "Command and Scripting Interpreter"}
        assert kwargs["flag_intrusion_set_instead_of_threat_actor"] is True

    def test_convert_event_defaults(self):
        # ttl and the intrusion-set flag are optional; the defaults must reach
        # the pipeline unchanged (no TTL override, threat-actor SDOs).
        converter = ConverterToStix(helper=MagicMock(), config=MagicMock())

        with patch(
            "connector.converter_to_stix.collect_intelligence",
            return_value=[],
        ) as mock_collect:
            assert (
                converter.convert_event(
                    collection="malware/cnc", event={}, mitre_mapper={}
                )
                == []
            )

        kwargs = mock_collect.call_args.kwargs
        assert kwargs["ttl"] is None
        assert kwargs["flag_intrusion_set_instead_of_threat_actor"] is False
