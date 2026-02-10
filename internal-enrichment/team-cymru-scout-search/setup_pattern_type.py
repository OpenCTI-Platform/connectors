# File: setup_vocab.py
import os
import sys

from pycti import OpenCTIConnectorHelper


def setup_vocabulary():
    # Get configuration from environment variables
    opencti_url = os.environ.get("OPENCTI_URL")
    opencti_token = os.environ.get("OPENCTI_TOKEN")
    pattern_type = os.environ.get("PURE_SIGNAL_SCOUT_INDICATOR_PATTERN_TYPE")
    pattern_description = os.environ.get("PURE_SIGNAL_SCOUT_PATTERN_DESCRIPTION")

    # Validate required environment variables
    if not opencti_url or not opencti_token or not pattern_type:
        sys.stderr.write("Error: Required environment variables are missing\n")
        sys.exit(1)

    # Initialize OpenCTI helper
    helper = OpenCTIConnectorHelper(
        {
            "opencti": {
                "url": opencti_url,
                "token": opencti_token,
            }
        }
    )

    try:
        # Create vocabulary
        helper.api.vocabulary.create(
            category="pattern_type_ov",
            name=pattern_type,
            description=pattern_description,
        )
        sys.stdout.write(f"Vocabulary {pattern_type} added successfully\n")

    except Exception as e:
        # Handle case where vocabulary already exists
        if "already exists" in str(e).lower():
            sys.stdout.write(f"Vocabulary {pattern_type} already exists\n")
        else:
            sys.stderr.write(f"Failed to add vocabulary: {str(e)}\n")
            # Don't exit with error as this shouldn't prevent connector from starting
            sys.stdout.write("Continuing with connector startup\n")


if __name__ == "__main__":
    setup_vocabulary()
