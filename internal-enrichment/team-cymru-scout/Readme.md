# Pure Signal Scout Internal Enrichment Connector

| Type               | Status      | OpenCTI Version | Deployment          |
|--------------------|-------------|------------------|---------------------|
| Internal Enrichment | ✅ Supported | ≥ 6.7.16         | Docker / Manual     |

> **⚠️ EARLY ACCESS VERSION**
>
> This connector is currently in early access. Features and functionality may change as development continues. Please report any issues or feedback to help improve the connector.

## 🧭 Introduction

**Pure Signal Scout** is a powerful cyber threat intelligence tool that uniquely provides real-time visibility of external threats, at speeds others can't match. This internal enrichment connector allows **OpenCTI** users to query the **Team Cymru Scout API** to enrich observables like IP addresses and domain names with high-fidelity **STIX 2.1** intelligence.

This connector queries the Scout API endpoints in real-time and transforms the response into standardized STIX 2.1 bundles compatible with the OpenCTI platform.

---

## 🧬 Supported Observable Types

| Observable Type | STIX Type   |
|------------------|-------------|
| IPv4 Address     | IPv4-Addr   |
| IPv6 Address     | IPv6-Addr   |
| Domain Name      | Domain-Name |

---

## 🔗 API Endpoints Used

| Method | Endpoint                               | Description                                  |
|--------|----------------------------------------|----------------------------------------------|
| GET    | `/ip/foundation?ips={ip_address}`      | Used for IPv4 or IPv6 observable enrichment  |
| GET    | `/search?query={domain}`               | Used for Domain enrichment                   |

---

## ✅ Requirements

- OpenCTI Platform version: **≥ 6.7.16**
- **Docker Engine** (for container-based deployment)
- **Python ≥ 3.9** (for manual deployment)

---

## ⚙️ Configuration Variables

This connector supports two configuration methods:

- **Environment variables** (recommended for Docker)
- **config.yml** (for manual deployment)

### OpenCTI Environment Variables

| Variable       | Description               | Required |
|----------------|---------------------------|----------|
| `OPENCTI_URL`  | OpenCTI platform URL      | ✅       |
| `OPENCTI_TOKEN`| OpenCTI platform token    | ✅       |

### Connector Base Environment Variables

| Variable                    | Description                               | Required | Example                       |
|-----------------------------|-------------------------------------------|----------|-------------------------------|
| `CONNECTOR_ID`              | Unique connector instance ID              | ✅       | pure-signal-scout-connector   |
| `CONNECTOR_TYPE`           | Always set to `INTERNAL_ENRICHMENT`       | ✅       | INTERNAL_ENRICHMENT           |
| `CONNECTOR_NAME`           | Display name in OpenCTI UI                | ✅       | Pure Signal Scout             |
| `CONNECTOR_SCOPE`          | Supported observable types                | ✅       | IPv4-Addr,IPv6-Addr,Domain-Name |
| `CONNECTOR_AUTO`           | Auto enrichment enabled (true/false)      | ✅       | false                         |
| `CONNECTOR_CONFIDENCE_LEVEL`| Confidence score (0–100)                 | ✅       | 100                           |
| `CONNECTOR_LOG_LEVEL`      | Logging level (`debug`, `info`, `error`) | ✅       | error                         |

### Scout API Environment Variables

| Variable                     | Description                                | Required | Example                               |
|------------------------------|--------------------------------------------|----------|---------------------------------------|
| `PURE_SIGNAL_SCOUT_API_URL`  | Base URL of the Scout API                  | ✅       | https://taxii.cymru.com/api/scout     |
| `PURE_SIGNAL_SCOUT_API_TOKEN`| Bearer token for the Scout API            | ✅       | (Set securely)                        |
| `PURE_SIGNAL_SCOUT_MAX_TLP`  | Max TLP level to return in enrichment     | ✅       | TLP:AMBER                             |

---

## 🚀 Deployment

### 🐳 Docker Deployment

**1. Configure Environment Variables:**

Copy the sample environment file and update with your values:

```bash
cp .env.sample .env
```

Edit `.env` and set your actual values:
- `OPENCTI_URL` - Your OpenCTI instance URL
- `OPENCTI_TOKEN` - Your OpenCTI API token
- `PURE_SIGNAL_SCOUT_API_TOKEN` - Your Scout API token
- Adjust other settings as needed

**2. Update docker-compose.yml (if needed):**

The default `docker-compose.yml` uses the external network `docker_default`. If your OpenCTI instance uses a different network name, update the network configuration:

```yaml
networks:
  docker_default:
    external: true
    name: your-network-name  # Change this to match your OpenCTI network
```

**3. Build and Start:**

```bash
docker compose up -d
```

Or using make:

```bash
make docker-build
make docker-up
```

---

### 🏢 Team Cymru Internal Deployment

> **Note:** The `docker-compose-cymru.yml` file and associated CI/CD pipeline are for **Team Cymru internal use only**.

This deployment method uses pre-built images from the GitLab Container Registry and is managed via the GitLab CI/CD pipeline. See `.gitlab-ci.yml` for pipeline configuration details


## ⚙️ Behavior

- **Default Mode**: Manual enrichment only (`CONNECTOR_AUTO=false`)

### Routing Logic:
| Observable Type | API Endpoint Used |
|-----------------|-------------------|
| IPv4-Addr / IPv6-Addr | `/ip/foundation?ips={ip_address}` |
| Domain-Name | `/search?query={domain}` |

### Processing:
- Responses are returned as STIX 2.1 bundles (no transformation required)
- No bundle validation needed
- **Rate Limiting**: Respects 1 request per second

## 📜 Logging

Default logging level: error

For detailed logs, set CONNECTOR_LOG_LEVEL=debug


