# OpenCTI Nameshield Connector

## Installation

This connector facilitates domain names import of from the NameShield registrat.

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
| `nameshield_auth_berear` | `NAMESHIELD_AUTH_BEARER` | You connection bearer provided by nameshield (you need autorise you IP also)   |
| `nameshield_server` | `NAMESHIELD_SERVER` | Must be `api.nameshield.net` (but if Domain name change one day...)  |
| `nameshield_api_version` | `NAMESHIELD_API_VERSION` | Must be `v1` (but if version change one day...)  |
| `nameshield_api_endpoint` | `NAMESHIELD_API_ENDPOINT` | Must be `registrar` (but if it change one day...)  |
| `nameshield_url_list` | `NAMESHIELD_URL_LIST` | Must be `https://{server}/{api_endpoint}/{api_version}/domains` (but if it change one day...)  |
| `nameshield_url_domain` | `NAMESHIELD_URL_DOMAIN` | Must be `https://{server}/{api_endpoint}/{api_version}/domains/{domain}` (but if it change one day...)  |
| `nameshield_interval` | `NAMESHIELD_INTERVAL` | Time (in hours) between run (168 is a good value: once a week)  |
| `nameshield_domain_limit` | `NAMESHIELD_DOMAIN_LIMIT` | Time (in hours) between run (168 is a good value: once a week) in cas yuou have a looooooot of domain name |
| `nameshield_api_endpointmarking` | `NAMESHIELD_MARKING` | Hot to mark you domain `TLP:GREEN` |
| `nameshield_link_to_identities`   | `NAMESHIELD_LINK_TO_IDENTITIES`   | In cas you want to link it to your Firm (for exemple) (or more entities comma separated)   |

## Docker Compose Example

See [docker-compose.yml](./docker-compose.yml)

## Reminders
- <font color="red">YOU NEED TO</font> autorize your IP adress to acces Nameshield API
- if you have several account run it several time with different `CONNECTOR_ID` and `CONNECTOR_NAME`

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
pip3 install -r /root/raw_src/connectors/external-import/NameShield/src/requirements.txt
nano /root/opencti/running-connectors/connector_nameshield_domains.sh
```

```bash
#!/bin/bash

export OPENCTI_URL="http://localhost:4000"
export OPENCTI_TOKEN="YOUR-USER-TOKEN"
export CONNECTOR_ID="nameshield-ID"
export CONNECTOR_TYPE="EXTERNAL_IMPORT"
export CONNECTOR_NAME="NameShield Connector"
export CONNECTOR_LOG_LEVEL="info"

export NAMESHIELD_AUTH_BEARER="CHANGEME"
export NAMESHIELD_SERVER="api.nameshield.net"
export NAMESHIELD_API_VERSION="v1"
export NAMESHIELD_API_ENDPOINT="registrar"
export NAMESHIELD_URL_LIST="https://{server}/{api_endpoint}/{api_version}/domains"
export NAMESHIELD_URL_DOMAIN="https://{server}/{api_endpoint}/{api_version}/domains/{domain}"
export NAMESHIELD_INTERVAL=168
export NAMESHIELD_DOMAIN_LIMIT=10000
export NAMESHIELD_MARKING="TLP:GREEN"

# Venv activation
source /root/opencti/running-connectors/.octi_con_venv/bin/activate
# Run Connector
python3 /root/raw_src/connectors/external-import/NameShield/src/NameShield.py

```
Make it executable
```bash
chmod +x /root/opencti/running-connectors/connector_nameshield_domains.sh
```
### Service Creation
```bash
nano /etc/systemd/system/opencti-con-nameshield.service
```

```toml
[Unit]
Description=OpenCTI Connector nameshield
Documentation=https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/NameShield
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
ExecStart=/bin/bash /root/opencti/running-connectors/connector_nameshield_domains.sh
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

### Activate this service

```bash
systemctl daemon-reload
systemctl enable opencti-con-nameshield.service
systemctl start opencti-con-nameshield.service
```

### Versioning
- 26-02-18 Adding a PGP Signed Commit