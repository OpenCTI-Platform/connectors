"""Main entry point for the Censys Collections connector."""

import sys
import traceback


def main() -> None:
    try:
        from connectors_sdk import ExternalImportConnector

        from censys_collections.client import Client
        from censys_collections.converter import Converter
        from censys_collections.processor import CollectionsProcessor
        from censys_collections.settings import ConfigLoader

        settings = ConfigLoader()
        client = Client(
            organisation_id=settings.censys_collections.organisation_id.get_secret_value(),
            token=settings.censys_collections.token.get_secret_value(),
            request_timeout_seconds=settings.censys_collections.request_timeout_seconds,
        )
        converter = Converter(
            tlp_level=settings.censys_collections.tlp_level,
            score=settings.censys_collections.indicator_score,
            auto_indicator_by_score=settings.censys_collections.auto_indicator_by_score,
            indicator_score_threshold=settings.censys_collections.indicator_score_threshold,
        )
        processor = CollectionsProcessor(client=client, converter=converter)
        connector = ExternalImportConnector(
            settings=settings,
            data_processors=[processor],
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
