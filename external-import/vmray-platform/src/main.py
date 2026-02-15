"""
Main entry point for the VMRay connector script.
Initializes the connector and runs it.
"""

from sys import exit
from traceback import print_exc

from vmray_connector import VMRayConnector

if __name__ == "__main__":
    # Entry point of the script
    # print_exc(): Prints the exception traceback to stderr
    # exit(1): Signals an error to the operating system
    try:
        connector = VMRayConnector()
        connector.run()
    except Exception:
        print_exc()
        exit(1)
