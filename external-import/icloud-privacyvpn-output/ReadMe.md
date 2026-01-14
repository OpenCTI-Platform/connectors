# OpenCTI iCloud Private Relay

## Installation

Official a privacy Gurad, but just another VPN provider

## Configuration

| Parameter   | Docker envvar  | Description |
|----------------------------------|----------------------------------|----------------------------------------------------------------------------------------------------|
| `opencti_url`  | `OPENCTI_URL`  | The URL of the OpenCTI platform. |
| `opencti_token`   | `OPENCTI_TOKEN`   | The default admin token configured in the OpenCTI platform parameters file.   |
| `connector_id` | `CONNECTOR_ID` | A valid arbitrary `UUIDv4` that must be unique for this connector.   |
| `connector_type` | `CONNECTOR_TYPE` | Must be `EXTERNAL_IMPORT`  |
| `connector_name`  | `CONNECTOR_NAME`  | The name of the connector, can be just "Nameshield"   |
| `connector_update_existing_data` | `CONNECTOR_UPDATE_EXISTING_DATA` | If an entity already exists, update its attributes with information provided by this connector. |
| `connector_log_level`   | `CONNECTOR_LOG_LEVEL`   | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).   |
| `iCloud_vpn_endpoints_url` | `ICLOUDVPN_ENDPOINTS_URL` |  URL where infos are available (if it changes one day)   |
| `iCloud_vpn_identity` | `ICLOUDVPN_IDENTITY` | Master Identity to link all element to (dafault `Apple VPN`)  |
| `iCloud_vpn_interval` | `APPLEVPN_INTERVAL` |  Runs everry X hours (default `24` is a good ratio)  |
| `iCloud_vpn_tags` | `APPLEVPN_TAGS` | Tags to set on elements  (default  `Apple,VPN,Cloud`) |
| `iCloud_vpn_chunksize` | `APPLEVPN_CHUNKSIZE` | There is arround 300k line in this source, let's ingest it by blocks |
| `iCloud_vpn_marking` | `ICLOUDVPN_MARKING` | How to mark element   |

## Docker Compose Example

See [docker-compose.yml](./docker-compose.yml)

## Not Running on Docker?
You can run it without docker (or elsewhere)

### Create venv

```bash
# Let's create a folder for connector
mkdir -p /root/opencti/running-connectors/
# Let's create a folder for connectors raw sources
mkdir -p /root/raw_src/
cd /root/raw_src/
git clone https://github.com/OpenCTI-Platform/connectors.git

# Virtual environement creation
cd /root/opencti/running-connectors/
python3 -m venv --prompt "OCTI Connectors" /root/opencti/running-connectors/.octi_con_venv
source /root/opencti/running-connectors/.octi_con_venv/bin/activate
pip3 install -r /root/raw_src/connectors/external-import/icloud-privacyvpn-output/src/requirements.txt
nano /root/opencti/running-connectors/connector_iCloud-privacyvpn-output.sh
```

```bash
#!/bin/bash

export OPENCTI_URL="http://localhost:4000"
export OPENCTI_TOKEN="YOUR-USER-TOKEN"
export CONNECTOR_ID="iCloud-privacyvpn-output-ID"
export CONNECTOR_TYPE="EXTERNAL_IMPORT"
export CONNECTOR_NAME="Apple iCloud Privacy VPN Endpoints"
export CONNECTOR_LOG_LEVEL="info"

export APPLEVPN_ENDPOINTS_URL="https://mask-api.icloud.com/egress-ip-ranges.csv"
export APPLEVPN_INTERVAL=24
export APPLEVPN_TAGS="Apple,VPN,Cloud"
export APPLEVPN_MARKING="TLP:CLEAR"

# Venv activation
source /root/opencti/running-connectors/.octi_con_venv/bin/activate
# Run Connector
python3 /root/raw_src/connectors/external-import/iCloud-privacyvpn-output/src/Get_AppleVPN_Output.py

```
Make it executable
```bash
chmod +x /root/opencti/running-connectors/connector_iCloud-privacyvpn-output.sh
```
### Service Creation
```bash
nano /etc/systemd/system/opencti-con-icloud-privacyvpn.service
```

```toml
[Unit]
Description=OpenCTI Connector iCloud-privacyvpn
Documentation=https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/icloud-privacyvpn-output
# It start after OCTI
Requires=opencti.service
After=opencti.service

[Service]
User=root
Group=root
WorkingDirectory=/root/opencti/running-connectors/

# Wait before running
ExecStartPre=/bin/sleep 60

# Run connector
ExecStart=/bin/bash /root/opencti/running-connectors/connector_iCloud-privacyvpn-output_domains.sh
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

### Activate this service

```bash
systemctl daemon-reload
systemctl enable opencti-con-icloud-privacyvpn-output.service
systemctl start opencti-con-icloud-privacyvpn-output.service
```