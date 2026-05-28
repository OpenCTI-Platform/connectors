# OpenCTI Criminal IP Connector

The Criminal IP connector enriches **IPv4 addresses** and **domain names** with threat intelligence from [Criminal IP](https://www.criminalip.io).

## Enrichment Details

### IPv4 Address
- Reputation indicator with inbound/outbound risk scores
- Autonomous System (AS) information
- Geolocation (country, city, region)
- Labels based on issue flags (VPN, HOSTING, CLOUD, etc.)
- Vulnerability (CVE) associations

### Domain Name
- Domain scan with phishing probability analysis
- Related IP addresses (resolves-to relationships)
- Server location countries
- Malicious domain indicator (when phishing/suspicious signals detected)

## Configuration

| Parameter                | Docker envvar          | config.yml            | Default               | Required |
|--------------------------|------------------------|-----------------------|-----------------------|----------|
| OpenCTI URL              | `OPENCTI_URL`          | `opencti.url`         |                       | Yes      |
| OpenCTI Token            | `OPENCTI_TOKEN`        | `opencti.token`       |                       | Yes      |
| Connector ID             | `CONNECTOR_ID`         | `connector.id`        |                       | Yes      |
| Connector Name           | `CONNECTOR_NAME`       | `connector.name`      | `Criminal IP`         | No       |
| Connector Scope          | `CONNECTOR_SCOPE`      | `connector.scope`     | `IPv4-Addr,Domain-Name` | No    |
| Connector Auto           | `CONNECTOR_AUTO`       | `connector.auto`      | `false`               | No       |
| Connector Log Level      | `CONNECTOR_LOG_LEVEL`  | `connector.log_level` | `error`               | No       |
| Criminal IP API Token    | `CRIMINAL_IP_TOKEN`    | `criminal_ip.token`   |                       | Yes      |
| Max TLP                  | `CRIMINAL_IP_MAX_TLP`  | `criminal_ip.max_tlp` | `TLP:AMBER`           | No       |

## Installation

### Docker (Recommended)

Build the Docker image:

```bash
docker build -t opencti/connector-criminal-ip:latest .
```

### Docker Compose

```yaml
services:
  connector-criminal-ip:
    image: opencti/connector-criminal-ip:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CRIMINAL_IP_TOKEN=ChangeMe
    restart: always
```

Refer to `docker-compose.yml` for a full example with all optional parameters.

## API Endpoints Used

- `GET /v1/asset/ip/report` - IP address report
- `GET /v1/feature/ip/malicious-info` - IP malicious information
- `GET /v1/domain/reports` - Check existing domain scans
- `POST /v1/domain/scan` - Trigger new domain scan
- `GET /v1/domain/status/{scan_id}` - Poll scan progress
- `GET /v2/domain/report/{scan_id}` - Fetch domain scan results