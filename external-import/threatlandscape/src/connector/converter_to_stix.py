from pycti import OpenCTIConnectorHelper


class ConverterToStix:
    """
    Pass-through helper for Threat Landscape STIX bundles.

    The Threat Landscape API already emits fully-formed, valid STIX 2.1 bundles.
    Each bundle includes its own ``created_by_ref`` (``identity--2f63f8e1``,
    ``threatlandscape.io``) and TLP marking definitions. No conversion or
    re-attribution is required.

    This class is responsible only for extracting the raw STIX objects list
    from the API row payload so the connector can collect and forward them.
    """

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        """
        Args:
            helper: OpenCTI connector helper, used for structured logging.
        """
        self.helper = helper

    def extract_objects(self, stix_bundle: dict) -> list[dict]:
        """
        Extract the STIX objects array from a raw bundle dict.

        All source objects — including the ``threatlandscape.io`` identity,
        TLP marking definitions, and every SDO/SRO — are returned verbatim.

        Args:
            stix_bundle: The ``stix_bundle`` value from a single API row.

        Returns:
            List of STIX object dicts. Empty list if the bundle has no objects.
        """
        objects = stix_bundle.get("objects")
        if not isinstance(objects, list):
            self.helper.connector_logger.warning(
                "STIX bundle missing 'objects' array; skipping",
                meta={"bundle_id": stix_bundle.get("id")},
            )
            return []
        return objects
