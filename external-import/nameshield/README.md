# OpenCTI Nameshield Connector

## Installation

This connector facilitates the import of domain names from the Nameshield registrar.

## Configuration

| Parameter | config.yml | Docker environment variable | Default | Mandatory | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | | Yes | The URL of the OpenCTI platform. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | | Yes | The token of the OpenCTI user the connector runs as. |
| Connector ID | `connector.id` | `CONNECTOR_ID` | `46ae8578-037f-49fc-b68c-f803f1f0d86e` | No | A valid arbitrary `UUIDv4` that must be unique for this connector. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `NameShield` | No | The name of the connector. |
| Connector scope | `connector.scope` | `CONNECTOR_SCOPE` | `NameShield` | No | The scope of the connector. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | The log level for this connector: `debug`, `info`, `warn` or `error` (less verbose). |
| Duration period | `connector.duration_period` | `CONNECTOR_DURATION_PERIOD` | `P7D` | No | ISO-8601 duration between two runs (`P7D`: once a week). Replaces `NAMESHIELD_INTERVAL`. |
| Auth bearer | `nameshield.auth_bearer` | `NAMESHIELD_AUTH_BEARER` | | Yes | Your bearer token provided by NameShield (your IP address must also be allowed). |
| Server | `nameshield.server` | `NAMESHIELD_SERVER` | `api.nameshield.net` | No | NameShield API server, used as `{server}` in the URL templates. |
| API version | `nameshield.api_version` | `NAMESHIELD_API_VERSION` | `v1` | No | NameShield API version, used as `{api_version}` in the URL templates. |
| API endpoint | `nameshield.api_endpoint` | `NAMESHIELD_API_ENDPOINT` | `registrar` | No | NameShield API endpoint, used as `{api_endpoint}` in the URL templates. |
| Domain list URL | `nameshield.url_list` | `NAMESHIELD_URL_LIST` | `https://{server}/{api_endpoint}/{api_version}/domains` | No | URL template of the domain list. |
| Domain details URL | `nameshield.url_domain` | `NAMESHIELD_URL_DOMAIN` | `https://{server}/{api_endpoint}/{api_version}/domains/{domain}` | No | URL template of the domain details. |
| Domain limit | `nameshield.domain_limit` | `NAMESHIELD_DOMAIN_LIMIT` | `10000` | No | Maximum number of domains imported per run, in case you have a lot of domain names. |
| Marking | `nameshield.marking` | `NAMESHIELD_MARKING` | `TLP:GREEN` | No | TLP marking of the imported objects. An unknown value falls back to `TLP:AMBER+STRICT`. |
| Link to identities | `nameshield.link_to_identities` | `NAMESHIELD_LINK_TO_IDENTITIES` | | No | Comma-separated STIX IDs of identities (your firm, for example) the indicators are attributed to. Empty for no link. |

Deprecated settings, still read:

- `NAMESHIELD_INTERVAL` (`nameshield.interval`, in hours): use `CONNECTOR_DURATION_PERIOD`.
- `nameshield.marking_definition` in `config.yml`: use `nameshield.marking`.

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
export CONNECTOR_NAME="NameShield Connector"
export CONNECTOR_LOG_LEVEL="info"
export CONNECTOR_DURATION_PERIOD="P7D"

export NAMESHIELD_AUTH_BEARER="CHANGEME"
export NAMESHIELD_SERVER="api.nameshield.net"
export NAMESHIELD_API_VERSION="v1"
export NAMESHIELD_API_ENDPOINT="registrar"
export NAMESHIELD_URL_LIST="https://{server}/{api_endpoint}/{api_version}/domains"
export NAMESHIELD_URL_DOMAIN="https://{server}/{api_endpoint}/{api_version}/domains/{domain}"
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