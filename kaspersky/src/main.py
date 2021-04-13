"""Kaspersky connector main module."""

from kaspersky.connector import KasperskyConnector


if __name__ == "__main__":
    connector = KasperskyConnector()
    try:
        connector.run()
    finally:
        connector.close()
