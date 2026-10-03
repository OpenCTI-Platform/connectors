# Testing the IPGeolocation.io Connector on a Fresh OpenCTI Instance

Complete guide: zero → enriched observable in the UI.

---

## Prerequisites

- **Machine**: 8 GB RAM minimum (16 GB recommended). Linux, macOS, or Windows with WSL2.
- **Docker**: Docker Engine + Docker Compose v2 installed.
- **IPGeolocation.io account**: Free tier gives 1,000 credits/day (enough for testing). Sign up at https://ipgeolocation.io — copy your API key from the dashboard.

---

## Step 1 — Set the Elasticsearch kernel parameter (Linux only)

```bash
# Required by Elasticsearch — without this, the container crashes
sudo sysctl -w vm.max_map_count=262144

# Make it persistent across reboots
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

On macOS/Windows (Docker Desktop), this is handled automatically.

---

## Step 2 — Clone the official OpenCTI Docker repo

```bash
git clone https://github.com/OpenCTI-Platform/docker.git opencti
cd opencti
```

---

## Step 3 — Create your .env file

```bash
cp .env.sample .env
```

Now edit `.env` and fill in the required values. At minimum you need:

```bash
# Generate these with: uuidgen  (run it once per field)
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=ChangeMeNow123!
OPENCTI_ADMIN_TOKEN=<paste-a-uuidv4-here>

# For MinIO (S3 storage)
MINIO_ROOT_USER=<uuidgen>
MINIO_ROOT_PASSWORD=<uuidgen>

# For RabbitMQ
RABBITMQ_DEFAULT_USER=guest
RABBITMQ_DEFAULT_PASS=guest

# Elasticsearch memory (use 4G if you have 16GB RAM, 2G if 8GB)
ELASTIC_MEMORY_SIZE=4G

# Health check key
OPENCTI_HEALTHCHECK_ACCESS_KEY=<any-random-string>

# Connector IDs (one uuidgen per connector)
CONNECTOR_HISTORY_ID=<uuidgen>
CONNECTOR_EXPORT_FILE_STIX_ID=<uuidgen>
CONNECTOR_EXPORT_FILE_CSV_ID=<uuidgen>
CONNECTOR_EXPORT_FILE_TXT_ID=<uuidgen>
CONNECTOR_IMPORT_FILE_STIX_ID=<uuidgen>
CONNECTOR_IMPORT_DOCUMENT_ID=<uuidgen>
```

Quick way to generate all the UUIDs at once:

```bash
for i in $(seq 1 10); do uuidgen; done
```

---

## Step 4 — Start the OpenCTI core stack (without XTM One)

The official repo now includes XTM One services you don't need. Start only what matters:

```bash
SERVICES="opencti worker \
  connector-export-file-stix connector-export-file-csv connector-export-file-txt \
  connector-import-file-stix connector-import-document \
  connector-analysis connector-opencti connector-mitre"

docker compose up -d $SERVICES
```

First run pulls ~5 GB of images. Wait 3–5 minutes for Elasticsearch to become healthy.

Check status:

```bash
docker compose ps          # All services should show "healthy" or "running"
docker compose logs opencti --tail 50   # Look for "Platform started on port 8080"
```

---

## Step 5 — Log in and verify

Open **http://localhost:8080** in your browser.

- Email: whatever you set in `OPENCTI_ADMIN_EMAIL`
- Password: whatever you set in `OPENCTI_ADMIN_PASSWORD`

You should see the empty OpenCTI dashboard. Give MITRE a few minutes to populate (the mitre connector auto-imports ATT&CK data).

---

## Step 6 — Add the IPGeolocation.io connector

**Option A: Add to docker-compose (recommended)**

Create a file called `docker-compose.override.yml` in the same `opencti/` directory:

```yaml
version: "3"
services:
  connector-ipgeolocation:
    build: /path/to/your/opencti-ipgeolocation
    # Or if you don't want to build, mount the source:
    # image: python:3.12-slim
    # command: bash -c "pip install -r /connector/requirements.txt && python -m src.main"
    # volumes:
    #   - /path/to/opencti-ipgeolocation:/connector
    # working_dir: /connector
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=<generate-a-new-uuidv4>
      - CONNECTOR_NAME=IPGeolocation.io
      - CONNECTOR_SCOPE=IPv4-Addr,IPv6-Addr
      - CONNECTOR_AUTO=false
      - CONNECTOR_CONFIDENCE_LEVEL=80
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_UPDATE_EXISTING_DATA=true
      - IPGEOLOCATION_API_KEY=<your-ipgeolocation-api-key>
      - IPGEOLOCATION_USE_GEO_API=true
      - IPGEOLOCATION_USE_SECURITY_API=true
      - IPGEOLOCATION_USE_ASN_API=true
      - IPGEOLOCATION_USE_ABUSE_API=true
      - IPGEOLOCATION_SINGLE_CALL_MODE=true
      - IPGEOLOCATION_CREATE_LABELS=true
      - IPGEOLOCATION_CREATE_INDICATORS=true
      - IPGEOLOCATION_CREATE_RELATIONSHIPS=true
      - IPGEOLOCATION_CREATE_NOTES=true
      - IPGEOLOCATION_CREATE_OPINIONS=false
      - IPGEOLOCATION_CREATE_SUMMARY=true
      - IPGEOLOCATION_MAX_TLP=TLP:AMBER
      - IPGEOLOCATION_DEFAULT_MARKING=TLP:WHITE
    restart: unless-stopped
    depends_on:
      - opencti
```

Then:

```bash
docker compose up -d connector-ipgeolocation
```

**Option B: Run locally with Python (easier for development)**

```bash
cd /path/to/opencti-ipgeolocation
pip install -r requirements.txt
cp config.yml.sample config.yml
```

Edit `config.yml`:

```yaml
opencti:
  url: "http://localhost:8080"
  token: "<your-OPENCTI_ADMIN_TOKEN-from-.env>"

connector:
  id: "<generate-a-uuidv4>"
  type: "INTERNAL_ENRICHMENT"
  name: "IPGeolocation.io"
  scope: "IPv4-Addr,IPv6-Addr"
  auto: false
  confidence_level: 80
  log_level: "info"

ipgeolocation:
  api_key: "<your-ipgeolocation-api-key>"
  use_geo_api: true
  use_security_api: true
  use_asn_api: true
  use_abuse_api: true
  single_call_mode: true
  create_labels: true
  create_indicators: true
  create_relationships: true
  create_notes: true
  create_summary: true
```

Run:

```bash
python -m src.main
```

You should see:
```
IPGeolocation.io connector starting (scope=IPv4-Addr,IPv6-Addr, single_call=True)
```

---

## Step 7 — Verify the connector is registered

In OpenCTI UI:

1. Go to **Data** → **Ingestion** → **Connectors**
2. You should see "IPGeolocation.io" listed as an INTERNAL_ENRICHMENT connector
3. Status should show a green indicator

---

## Step 8 — Create a test observable and trigger enrichment

**Method A: Via the UI**

1. Go to **Observations** → **Observables**
2. Click the **+** button (bottom right)
3. Choose **IPv4 Address**
4. Enter: `2.56.188.34` (a known VPN/proxy IP with high threat score)
5. Click **Create**
6. Open the observable you just created
7. Click the **cloud icon** (☁️) at the top right → "Enrichment"
8. You should see "IPGeolocation.io" in the list → click it
9. Wait a few seconds for the enrichment to complete

**Method B: Via the API (curl)**

```bash
# Replace with your actual values
OPENCTI_URL="http://localhost:8080"
OPENCTI_TOKEN="your-admin-token"

# Create an IPv4 observable
curl -X POST "$OPENCTI_URL/graphql" \
  -H "Authorization: Bearer $OPENCTI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { stixCyberObservableAdd(type: \"IPv4-Addr\", IPv4Addr: { value: \"2.56.188.34\" }) { id standard_id entity_type observable_value } }"
  }'
```

Then trigger enrichment from the UI as described above.

---

## Step 9 — See the results

After enrichment completes, on the observable page you should see:

### Knowledge tab
- **Relationships**: located-at (United States), belongs-to (AS15169), related-to (Packethub S.A.)
- **Indicators**: A malicious IP indicator (if threat score ≥ 50)
- **Locations**: Country (United States) and City (Dallas, Texas)
- **Organizations**: Google LLC, Packethub S.A., Abuse Contact

### Overview tab
- **Labels**: `vpn`, `proxy`, `residential-proxy`, `known-attacker`, `cloud-provider`, `hosting`, `risk:critical`
- **Score**: Updated to the unified risk score (e.g., 100/100 for this IP)
- **External References**: Link to ipgeolocation.io

### Notes tab
- A rich markdown note with: Executive Summary, IP Summary table, Security Assessment narrative, Infrastructure Profile, Network Context, Abuse Contact info, Geo Intelligence, Timeline, Confidence explanation

---

## Good test IPs to try

| IP | Expected result |
|---|---|
| `2.56.188.34` | High risk: VPN + proxy + known attacker |
| `8.8.8.8` | Low risk: Google DNS, cloud provider |
| `1.1.1.1` | Low risk: Cloudflare DNS, anycast |
| `185.220.101.1` | TOR exit node (usually) |
| `103.224.182.250` | Various threat signals |

---

## Troubleshooting

**Connector not showing up in OpenCTI:**
- Check logs: `docker compose logs connector-ipgeolocation` or the terminal where you ran `python -m src.main`
- Verify the `OPENCTI_URL` is reachable from the connector (use `http://opencti:8080` in Docker, `http://localhost:8080` locally)
- Verify the `OPENCTI_TOKEN` matches your admin token

**Enrichment fails silently:**
- Check connector logs for API errors
- Verify your IPGeolocation.io API key is valid (test with: `curl "https://api.ipgeolocation.io/v3/ipgeo?apiKey=YOUR_KEY&ip=8.8.8.8"`)
- Free plan does NOT include security/abuse modules — you need a paid plan for full enrichment

**"Observable not found" error:**
- The observable needs to exist in OpenCTI before enrichment is triggered
- Make sure the connector scope matches: `IPv4-Addr,IPv6-Addr`

**Rate limiting:**
- IPGeolocation.io free plan: 1,000 credits/day