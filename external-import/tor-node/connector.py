import requests
import json
from opencti import OpenCTIConnectorHelper

class TorExitNodeConnector:
    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})

    def fetch_exit_nodes(self):
        url = "https://check.torproject.org/torbulkexitlist"
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        lines = response.text.strip().splitlines()
        exit_nodes = []
        for line in lines:
            if line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                port = int(parts[1])
                exit_nodes.append({"ip": ip, "port": port})
        return exit_nodes

    def create_indicators(self, nodes):
        for node in nodes:
            indicator = {
                "type": "Network-Tor-Exit-Node",
                "value": f"{node['ip']}:{node['port']}",
                "source_name": "Tor Exit Node List",
                "description": "Tor exit node indicator",
            }
            self.helper.create_entity(indicator)

    def run(self):
        try:
            nodes = self.fetch_exit_nodes()
            self.create_indicators(nodes)
            return {"status": "success", "processed": len(nodes)}
        except Exception as e:
            return {"status": "error", "error": str(e)}

if __name__ == "__main__":
    connector = TorExitNodeConnector()
    result = connector.run()
    print(json.dumps(result, indent=2))