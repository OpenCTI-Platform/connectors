# OpenCTI Microsoft Office Endpoint Connector

## Installation

This connector integrates IP, CIDR, domains and other infos available for Office Endpoints.
Thoses observables can helps legitimate Microsoft Cloud elements

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
| `o365_endpoints_url` | `O365_ENDPOINTS_URL` |  URL where infos are available (if it changes one day)  |
| `o365_identity` | `O365_IDENTITY` |  Master Identity to link all element to (dafault `Microsoft Office Endpoints`) |
| `o365_interval` | `O365_INTERVAL` |  Runs everry X hours (default `24` is a good ratio)  |
| `o365_tags` | `O365_TAGS` |  Tags to be set on elements (default: `Microsoft,Office,Cloud`)  |
| `o365_marking` | `O365_MARKING` |  How to mark them  |

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
pip3 install -r /root/raw_src/connectors/external-import/microsoft-office-endpoints/src/requirements.txt
nano /root/opencti/running-connectors/connector_microsoft-office-endpoints.sh
```

```bash
#!/bin/bash

export OPENCTI_URL="http://localhost:4000"
export OPENCTI_TOKEN="YOUR-USER-TOKEN"
export CONNECTOR_ID="microsoft-office-endpoints-ID"
export CONNECTOR_TYPE="EXTERNAL_IMPORT"
export CONNECTOR_NAME="MS Office Endpoints Connector"
export CONNECTOR_LOG_LEVEL="info"

export O365_ENDPOINTS_URL="https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"
export O365_INTERVAL=24
export O365_TAGS=Microsoft,Office,Cloud
export O365_MARKING="TLP:CLEAR"

# Venv activation
source /root/opencti/running-connectors/.octi_con_venv/bin/activate
# Run Connector
python3 /root/raw_src/connectors/external-import/microsoft-office-endpoints/src/MS-OfficeEndpoints.py

```
Make it executable
```bash
chmod +x /root/opencti/running-connectors/connector_microsoft-office-endpoints.sh
```
### Service Creation
```bash
nano /etc/systemd/system/opencti-con-ms-office-endpoints.service
```

```toml
[Unit]
Description=OpenCTI Connector nameshield
Documentation=https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/microsoft-office-endpoints
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
ExecStart=/bin/bash /root/opencti/running-connectors/connector_microsoft-office-endpoints_domains.sh
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

### Activate this service

```bash
systemctl daemon-reload
systemctl enable opencti-con-ms-office-endpoints.service
systemctl start opencti-con-ms-office-endpoints.service
```