# PortSpoofPro OpenCTI Connector

Real-time threat intelligence connector that ingests PortSpoofPro telemetry data into OpenCTI. 

> Developed by [SharpSec](https://sharpsec.io) | PortSpoofPro: [portspoof.io](https://portspoof.io)

## Prerequisites

- PortSpoofPro - Central Services Component
- OpenCTI platform (self-hosted or SaaS)
- Python 3.11+ 

## Quick Start

### Docker (Recommended)

```bash
docker compose up -d
```

Configure via `.env` file:

```bash
OPENCTI_URL=https://your-opencti-instance.com
OPENCTI_TOKEN=your-api-token-here
CONNECTOR_ID=$(uuidgen)
RABBITMQ_URL=amqp://portspoof:password@localhost:5672/
```

### Manual Installation

```bash
pip install -r requirements.txt
python src/main.py
```

## Architecture

```
PortSpoofPro Host:
  Sensor Aggregator → RabbitMQ (portspoof-full-state-updates)
                  ↓
  OpenCTI Connector → Consumes messages
                  ↓
  Remote OpenCTI Instance 
```

**Deployment Model**: Connector runs on PortSpoofPro host with access to local RabbitMQ (Central Services Component) and remote OpenCTI instance.

## Configuration

### OpenCTI Settings

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENCTI_URL` | Yes | - | OpenCTI platform URL |
| `OPENCTI_TOKEN` | Yes | - | OpenCTI API token |
| `OPENCTI_SSL_VERIFY` | No | `true` | SSL certificate verification |

### Connector Settings

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CONNECTOR_ID` | Yes | - | Unique UUIDv4 identifier |
| `CONNECTOR_NAME` | No | `PortSpoofPro` | Connector display name |
| `CONNECTOR_LOG_LEVEL` | No | `info` | Log level: `debug`, `info`, `warn`, `error` |

### PortSpoofPro Settings

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RABBITMQ_URL` | Yes | `amqp://guest:guest@localhost:5672/` | RabbitMQ connection URL |
| `RABBITMQ_QUEUE_NAME` | No | `opencti-connector-queue` | Queue name for state updates |
| `PS_LOG_FILE` | No | - | Log file path (stderr if not set) |
| `PS_DEBUG_FULL_DUMPS` | No | `0` | Enable full telemetry logs (set to `1`) |

## STIX Data Model

| Object | Description |
|--------|-------------|
| **Threat-Actor** | Individual adversary identified by source IP |
| **IPv4-Addr / IPv6-Addr** | Source and target IP observables |
| **Indicator** | Malicious IP patterns with STIX expressions |
| **Observed-Data** | Evidence with 43 custom properties (ports, eBPF counters, metrics) |
| **Tool** | Detected scanners (Nmap, masscan, zmap, hping3) |
| **Attack-Pattern** | MITRE ATT&CK + PortSpoofPro techniques + behavioral patterns |
| **Infrastructure** | PortSpoofPro sensor metadata |
| **Report** | Session summary with object references |
| **Relationship** | Links: `based-on`, `indicates`, `located-at`, `uses`, `targets` |
| **Sighting** | Threat actor sightings with sensor references |

## Features

- Real-time ingestion via event-driven RabbitMQ consumer
- STIX Indicators linked to Observables via `based-on` relationships
- MITRE ATT&CK mapping with 57 detection rules
- Tool fingerprinting (Nmap, masscan, zmap, hping3)
- TCP scan technique counters (SYN/FIN/NULL/XMAS/ACK scans)
- Behavioral analytics (velocity, concurrent connections, patterns)
- Automatic deduplication via deterministic STIX IDs
- Work tracking in OpenCTI UI

### Telemetry Coverage

**TCP Scan Technique Counters:**
- SYN/FIN/NULL/XMAS/ACK scan probes
- TCP/UDP port scan detection

**Behavioral Metrics:**
- TCP velocity, peak concurrent connections
- Service interaction depth and metrics

**Intelligence Extraction:**
- Tool fingerprints 
- Scan techniques 
- Behavioral patterns 
- Attack classifications 

**Full Context:**
- Complete target IP lists
- Port lists by scan technique (SYN, FIN, NULL, XMAS, ACK, UDP)

## Docker Deployment

### Build Image

```bash
docker build . -t opencti/connector-portspoof:latest
```

### Docker Compose

Example `docker-compose.yml`:

```yaml
version: '3'
services:
  connector-portspoof:
    image: opencti/connector-portspoof:latest
    environment:
      - OPENCTI_URL=${OPENCTI_URL}
      - OPENCTI_TOKEN=${OPENCTI_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_ID}
      - RABBITMQ_URL=${RABBITMQ_URL}
    restart: always
```

Run:

```bash
docker compose up -d
```

## Monitoring

Check connector status in OpenCTI:
1. Navigate to **Data → Connectors**
2. Find "PortSpoofPro" connector
3. View status and statistics

## Troubleshooting

### Connector not connecting to OpenCTI

- Verify `OPENCTI_URL` is accessible from connector host
- Check `OPENCTI_TOKEN` has connector permissions
- Review logs: `docker compose logs -f`

### No messages received

- Verify RabbitMQ exchange `portspoof-full-state-updates` exists
- Check PortSpoofPro aggregator is publishing messages
- Inspect queue: `opencti-connector-queue`

### High error rate

- Enable debug logging: `CONNECTOR_LOG_LEVEL=debug`
- Check Dead Letter Queue: `opencti-connector-dlq-queue`
- Review error logs: `PS_LOG_FILE=/path/to/connector.log`

## Support

- **PortSpoofPro**: [portspoof.io](https://portspoof.io)
- **SharpSec**: [sharpsec.io](https://sharpsec.io)
- **Issues**: [GitHub Issues](https://github.com/sharpsec-io/portspoof-opencti-connector/issues)
- **OpenCTI**: [docs.opencti.io](https://docs.opencti.io)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## About

Developed and maintained by [SharpSec](https://sharpsec.io).

PortSpoofPro is an advanced deception platform with eBPF-based detection. Learn more at [portspoof.io](https://portspoof.io).