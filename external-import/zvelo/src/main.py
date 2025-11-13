import traceback

from zvelo_connector import ConnectorZvelo

if __name__ == "__main__":
    try:
        connector = ConnectorZvelo()
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
