#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
MISP Intel Stream Connector - Main Entry Point

This is the main entry point for the MISP Intel stream connector.
It initializes and starts the connector to stream data from OpenCTI to MISP.
"""

import os
import sys
import time
import traceback

# Add the connector module to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from misp_intel_connector import MispIntelConnector


def main():
    """
    Main function to start the MISP Intel connector
    """
    try:
        print("[INFO] Starting MISP Intel Stream Connector...")

        # Create connector instance
        connector = MispIntelConnector()

        # Start the connector
        print("[INFO] Connector initialized. Starting stream listener...")
        connector.start()

    except KeyboardInterrupt:
        print("\n[INFO] Connector stopped by user")
        sys.exit(0)

    except Exception as e:
        print(f"[ERROR] Fatal error in connector: {str(e)}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
