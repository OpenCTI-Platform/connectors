import sys


def setup_vocabulary(helper, pattern_type, pattern_description=None):
    """
    Register a custom vocabulary pattern type in OpenCTI.
    Uses the connector's existing OpenCTIConnectorHelper instance.
    """
    if not pattern_type:
        helper.connector_logger.warning(
            "[ScoutSearchConnector] No pattern type configured, skipping vocabulary setup"
        )
        return

    try:
        helper.api.vocabulary.create(
            category="pattern_type_ov",
            name=pattern_type,
            description=pattern_description,
        )
        helper.connector_logger.info(
            "[ScoutSearchConnector] Vocabulary added",
            {"pattern_type": pattern_type},
        )
    except Exception as e:
        if "already exists" in str(e).lower():
            helper.connector_logger.info(
                "[ScoutSearchConnector] Vocabulary already exists",
                {"pattern_type": pattern_type},
            )
        else:
            sys.stderr.write(f"Failed to add vocabulary: {str(e)}\n")
            helper.connector_logger.warning(
                "[ScoutSearchConnector] Failed to add vocabulary, continuing",
                {"error": str(e)},
            )
