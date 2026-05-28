"""Stream Exporter connector main file."""

from connector import StreamExporterConnector

if __name__ == "__main__":
    connector = StreamExporterConnector()
    connector.start()
