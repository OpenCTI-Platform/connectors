# OpenCTI BeaconBeagle Connector

## Installation

This connector facilitates CobaltStrike tracking via the [BeaconBeagle](https://beaconbeagle.com/) initiative.

It creates **Observables** and **Indicators** in OpenCTI from the C2 configurations published by BeaconBeagle, optionally with country and BGP-AS context (when `BEACONBEAGLE_SEARCH_BGPAS=true` and the container's `whois` client can reach `bgp.tools`).

## Configuration

| Parameter                       | Docker envvar                       | Description                                                                                                                                       |
|---------------------------------|-------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                   | `OPENCTI_URL`                       | The URL of the OpenCTI platform.                                                                                                                  |
| `opencti_token`                 | `OPENCTI_TOKEN`                     | The default admin token configured in the OpenCTI platform parameters file.                                                                       |
| `connector_id`                  | `CONNECTOR_ID`                      | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                |
| `connector_type`                | `CONNECTOR_TYPE`                    | Must be `EXTERNAL_IMPORT`.                                                                                                                        |
| `connector_name`                | `CONNECTOR_NAME`                    | The name of the connector, e.g. `BeaconBeagle`.                                                                                                   |
| `connector_scope`               | `CONNECTOR_SCOPE`                   | The connector scope. Use `beaconbeagle` (recommended); aligned with the rest of `external-import/` connectors and with `templates/external-import/docker-compose.yml`. |
| `connector_log_level`           | `CONNECTOR_LOG_LEVEL`               | The log level for this connector — one of `debug`, `info`, `warn`, `error` (less verbose).                                                        |
| `beaconbeagle_url`              | `BEACONBEAGLE_URL`                  | The BeaconBeagle C2 list URL (default: `https://beaconbeagle.com/api/v1/c2?...&sort=firsttime&order=desc`).                                       |
| `beaconbeagle_add_urls`         | `BEACONBEAGLE_ADD_URLS`             | Save URLs from BeaconBeagle into OpenCTI (`true`/`false`).                                                                                        |
| `beaconbeagle_add_useragent`    | `BEACONBEAGLE_ADD_USERAGENT`        | Save User-Agent strings as observables (`true`/`false`).                                                                                          |
| `beaconbeagle_link_tool`        | `BEACONBEAGLE_LINK_TOOL`            | Tool name (e.g. `CobaltStrike`) to link observables to. Leave empty to skip the link.                                                             |
| `beaconbeagle_link_ap`          | `BEACONBEAGLE_LINK_AP`              | Attack-pattern reference. Either a plain name or `<MITRE_ID> <name>` (e.g. `T1071 Standard Application Layer Protocol`). Leave empty to skip.     |
| `beaconbeagle_link_country`     | `BEACONBEAGLE_LINK_COUNTRY`         | Create a Country location for each C2 IP and link it (`true`/`false`).                                                                            |
| `beaconbeagle_link_bgpas`       | `BEACONBEAGLE_LINK_BGPAS`           | Create an Autonomous-System observable for each C2 IP and link it (`true`/`false`).                                                               |
| `beaconbeagle_search_bgpas`     | `BEACONBEAGLE_SEARCH_BGPAS`         | Fall back to `whois -h bgp.tools` when BeaconBeagle's payload is missing the AS / country fields. **Generates traffic to bgp.tools** (`true`/`false`). |
| `beaconbeagle_link_watermark`   | `BEACONBEAGLE_LINK_WATERMARK_TXT`   | Suffix appended to the Text observable that tracks CobaltStrike licence watermarks (leave empty to disable).                                      |
| `beaconbeagle_links_duration`   | `BEACONBEAGLE_LINKS_DURATION`       | Duration in hours used as the indicator `valid_from`–`valid_until` window when BeaconBeagle does not provide a `lasttime` for a C2 entry.         |
| `beaconbeagle_interval`         | `BEACONBEAGLE_INTERVAL`             | Run frequency in hours.                                                                                                                           |
| `beaconbeagle_marking`          | `BEACONBEAGLE_MARKING`              | Marking definition on every produced object (`TLP:CLEAR`, `TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`, `TLP:RED`).                  |

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
