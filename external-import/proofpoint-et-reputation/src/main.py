import traceback

from connector import ProofpointEtReputationConnector

if __name__ == "__main__":
    # Entry point of the script
    try:
        connector = ProofpointEtReputationConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
