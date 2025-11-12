import time

from crowdstrike_connector import CrowdstrikeConnector

if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        connector = CrowdstrikeConnector()
        connector.start()
    except Exception as err:
        print(err)
        time.sleep(10)
        exit(0)
