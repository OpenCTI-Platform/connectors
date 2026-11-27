# OpenCTI BeaconBeagle Connector

## Installation

This connector facilitates CobaltStrike tracking via the [BeaconBeagle](https://beaconbeagle.com/) initiative.

It creates **Observables** and **Indicators** in OpenCTI from the C2 configurations published by BeaconBeagle, optionally with country and BGP-AS context (when `BEACONBEAGLE_SEARCH_BGPAS=true` and the container's `whois` client can reach `bgp.tools`).

## Configuration

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

## Docker Compose Example

See [docker-compose.yml](./docker-compose.yml).

## Not Running on Docker?

You can run the connector without Docker:

### Create venv

```bash
# Folders for the connector and the connectors checkout
mkdir -p /root/opencti/running-connectors/
mkdir -p /root/raw_src/
cd /root/raw_src/
git clone https://github.com/OpenCTI-Platform/connectors.git

# Create the venv
cd /root/opencti/running-connectors/
python3 -m venv --prompt "OCTI Connectors" /root/opencti/running-connectors/.octi_con_venv
source /root/opencti/running-connectors/.octi_con_venv/bin/activate
pip3 install -r /root/raw_src/connectors/external-import/beaconbeagle/src/requirements.txt
nano /root/opencti/running-connectors/connector_beaconbeagle.sh
```

```bash
#!/bin/bash

export OPENCTI_URL="http://localhost:4000"
export OPENCTI_TOKEN="YOUR-USER-TOKEN"
export CONNECTOR_ID="beaconbeagle-ID"
export CONNECTOR_TYPE="EXTERNAL_IMPORT"
export CONNECTOR_NAME="BeaconBeagle Connector"
export CONNECTOR_SCOPE="beaconbeagle"
export CONNECTOR_LOG_LEVEL="info"

export BEACONBEAGLE_URL="https://beaconbeagle.com/api/v1/c2?q=&protocol=&port=&min_endpoints=0&first_after=&first_before=&last_after=&last_before=&sort=firsttime&order=desc"
export BEACONBEAGLE_ADD_URLS="true"
export BEACONBEAGLE_ADD_USERAGENT="true"
export BEACONBEAGLE_LINK_TOOL="CobaltStrike"
export BEACONBEAGLE_LINK_COUNTRY="true"
export BEACONBEAGLE_LINK_BGPAS="true"
export BEACONBEAGLE_SEARCH_BGPAS="true"
export BEACONBEAGLE_LINK_AP="T1071 Standard Application Layer Protocol"
export BEACONBEAGLE_LINK_WATERMARK_TXT=' [CobaltStrikeLicenceWatermark]'
export BEACONBEAGLE_LINKS_DURATION=24
export BEACONBEAGLE_INTERVAL=2
export BEACONBEAGLE_MARKING="TLP:GREEN"

# Activate the venv and run the connector
source /root/opencti/running-connectors/.octi_con_venv/bin/activate
python3 /root/raw_src/connectors/external-import/beaconbeagle/src/BeaconBeagle.py
```

Make the launcher executable:

```bash
chmod +x /root/opencti/running-connectors/connector_beaconbeagle.sh
```

### Service Creation

```bash
nano /etc/systemd/system/opencti-con-beaconbeagle.service
```

```toml
[Unit]
Description=OpenCTI Connector BeaconBeagle
Documentation=https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/beaconbeagle
# Start after OpenCTI
Requires=opencti.service
After=opencti.service

[Service]
User=root
Group=root
WorkingDirectory=/root/opencti/running-connectors/

# Wait a moment before starting
ExecStartPre=/bin/sleep 60

# Run the connector
ExecStart=/bin/bash /root/opencti/running-connectors/connector_beaconbeagle.sh
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

### Activate the service

```bash
systemctl daemon-reload
systemctl enable opencti-con-beaconbeagle.service
systemctl start opencti-con-beaconbeagle.service
```

## Further reading

- STIX objects: <https://oasis-open.github.io/cti-documentation/stix/intro.html>
- STIX relationships: <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html>
