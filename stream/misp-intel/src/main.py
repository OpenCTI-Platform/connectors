#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
MISP Intel Stream Connector - Main Entry Point

This is the main entry point for the MISP Intel stream connector.
It initializes and starts the connector to stream data from OpenCTI to MISP.
"""

import os
import sys
import traceback

# Add the connector module to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from misp_intel_connector import MispIntelConnector
from models import ConfigLoader


def main():
    """
    Main function to start the MISP Intel connector
    """
    try:
        # Load configuration using the new pydantic-based config loader
        config = ConfigLoader()

        # Setup proxy environment variables if configured
        config.setup_proxy_env()

        # Create connector instance with the loaded config
        connector = MispIntelConnector(config)

        # Start the connector
        connector.start()

    except KeyboardInterrupt:
        sys.exit(0)

    except Exception:
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
