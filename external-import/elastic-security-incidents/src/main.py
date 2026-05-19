import sys
import traceback

from elastic_security_incidents_connector import ElasticSecurityIncidentsConnector

if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        connector = ElasticSecurityIncidentsConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
