# OpenCTI PolySwarm Scan & Sandbox Connector

[![Version](https://img.shields.io/badge/version-1.5.0-blue.svg)](https://github.com/polyswarm)
[![OpenCTI](https://img.shields.io/badge/OpenCTI-6.x-green.svg)](https://opencti.io)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A comprehensive OpenCTI internal enrichment connector that integrates with PolySwarm's malware intelligence platform, providing multi-engine scanning and dual-sandbox (CAPE & Triage) behavioral analysis capabilities.

## 🚀 Features

### Core Capabilities
- **Multi-Engine Scanning**: Submit files to 70+ antivirus engines via PolySwarm
- **Dual Sandbox Analysis**: Execute files in both CAPE and Triage sandboxes simultaneously
- **AI Threat Reports**: LLM-generated threat analysis summaries for scan and sandbox results
- **Automated STIX Generation**: Full STIX 2.1 compliant object creation
- **Malware Profile Enrichment**: Enhanced intelligence using curated malware family profiles
- **Actionable Error Notes**: Every failure (quota, access denied, timeout, file size) creates a visible Note on the artifact with guidance and contact info

### Analysis Output
| Category | Objects Created |
|----------|-----------------|
| **Indicators** | SHA-256 hash patterns with comprehensive descriptions |
| **Malware** | Family objects with aliases, types, and relationships |
| **Attack Patterns** | MITRE ATT&CK TTPs from sandbox behavioral analysis |
| **Network IOCs** | Domains, IPs, URLs, C2 candidates from sandbox execution |
| **Threat Actors** | Associated actors from malware profiles |
| **Vulnerabilities** | Exploited CVEs from malware profiles |
| **Notes** | Separate analysis notes (Scan, Triage, CAPE, Threat Intel, LLM AI Summary) |
| **Error Notes** | Actionable error notes with guidance (quota, auth, timeout, file size) |

### Reports & Attachments
- **JSON Reports**: Raw scan and sandbox results attached to artifacts
- **PDF Reports**: Professional PDF reports for scan and each sandbox provider
- **AI LLM Reports**: AI-generated threat analysis summaries embedded in scan and sandbox notes

## 📋 Requirements

- OpenCTI Platform 6.x+
- Docker & Docker Compose
- PolySwarm API Key ([Get one here](https://polyswarm.network))

## ⚡ Quick Start

### 1. Clone the Repository
```bash
git clone <repository-url>
cd opencti-polyswarm-connector
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env with your configuration
```

**Required variables:**
```env
OPENCTI_ADMIN_TOKEN=your-opencti-token
POLYSWARM_API_KEY=your-polyswarm-api-key
CONNECTOR_ID=generate-a-uuid-v4
```

### 3. Deploy with Docker
```bash
# Build the image
docker build -t polyswarm-scan-and-sandbox-v1.5:latest .

# Start the connector
docker-compose up -d

# View logs
docker-compose logs -f connector-polyswarm-sandbox
```

## ⚙️ Configuration

### Sandbox Providers

| Provider | VM Slug | Description |
|----------|---------|-------------|
| **CAPE** | `win-10-build-19041` | Windows 10 sandbox with deep analysis |
| **Triage** | `windows11-21h2-x64` | Windows 11 sandbox |
| **Triage** | `ubuntu-22.04-amd64` | Ubuntu Linux sandbox |
| **Triage** | `android-11-x64` | Android sandbox |

### Environment Variables

#### Required
| Variable | Description |
|----------|-------------|
| `OPENCTI_URL` | OpenCTI platform URL |
| `OPENCTI_TOKEN` | OpenCTI admin API token |
| `CONNECTOR_ID` | Unique connector ID (UUID v4) |
| `CONNECTOR_ENRICHMENT_RESOLUTION` | Set to `AUTHORIZED_AUTHORITIES` (required for OpenCTI ≥6.8.9) |
| `POLYSWARM_API_KEY` | PolySwarm API key |

#### Feature Toggles
| Variable | Default | Description |
|----------|---------|-------------|
| `POLYSWARM_SANDBOX_ENABLED` | `true` | Enable sandbox analysis |
| `POLYSWARM_SANDBOX_PROVIDER` | `both` | `cape`, `triage`, or `both` |
| `POLYSWARM_JSON_REPORT_ENABLED` | `true` | Attach JSON reports |
| `POLYSWARM_PDF_REPORT_ENABLED` | `true` | Attach PDF reports |
| `POLYSWARM_LLM_REPORT_ENABLED` | `false` | Generate AI threat analysis summaries (opt-in) |
| `POLYSWARM_LLM_REPORT_TIMEOUT` | `120` | LLM report generation timeout (seconds) |

#### Sandbox Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `POLYSWARM_SANDBOX_VM_CAPE` | `win-10-build-19041` | CAPE VM slug |
| `POLYSWARM_SANDBOX_VM_TRIAGE` | `windows11-21h2-x64` | Triage VM slug |
| `POLYSWARM_SANDBOX_NETWORK_ENABLED` | `true` | Allow internet access |
| `POLYSWARM_SANDBOX_TIMEOUT` | `600` | Timeout in seconds |

#### Enrichment Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `POLYSWARM_MIN_POLYSCORE` | `50` | Min score for indicators (0-100) |
| `POLYSWARM_CREATE_INDICATORS` | `true` | Create indicator objects |
| `POLYSWARM_CREATE_OBSERVABLES` | `true` | Create network IOCs |
| `POLYKG_API_URL` | *(empty)* | polykg REST API URL for malware profile enrichment (optional) |

## 📊 STIX Objects Generated

### From Scan Results
- **Indicator**: File hash pattern with PolyScore
- **Malware**: Family identification from PolyUnite consensus
- **Note**: "PolySwarm Scan Results" with detection stats, hashes, file type

### From Sandbox Results (per provider)
- **Attack Patterns**: MITRE ATT&CK techniques observed
- **Domain Names**: DNS queries and contacted domains
- **IPv4 Addresses**: Network connections and C2 candidates
- **Note**: Provider-specific analysis (scores, TTPs, signatures, IOCs)

### From Malware Profiles
- **Threat Actors**: Associated APT groups
- **Locations**: Target countries
- **Sectors**: Target industries
- **Vulnerabilities**: Exploited CVEs
- **Note**: "Extended Threat Intelligence" with full profile data

### Relationships Created
```
Indicator → indicates → Malware
Indicator → indicates → Attack Pattern
Indicator → based-on → File (Artifact)
Malware → uses → Attack Pattern
Malware → targets → Location
Malware → targets → Sector
Malware → exploits → Vulnerability
Malware → related-to → Related Malware
Threat Actor → uses → Malware
Threat Actor → targets → Location
Threat Actor → targets → Sector
Malware → attributed-to → Threat Actor
```

## 📝 Usage

### Basic Workflow

1. **Upload a file** to OpenCTI as an Artifact
2. **Trigger enrichment** via the connector
3. **View results** in the artifact's enrichment tab

### Password-Protected Files

If you are submitting a password-protected ZIP or 7z file, the connector needs the password to decrypt it before submitting to PolySwarm.

**How to set the decryption password in OpenCTI:**

1. Navigate to **Observations → Artifacts** in OpenCTI
2. Open the artifact you want to enrich
3. In the artifact details, set the **`decryption_key`** field to the archive password (e.g., `infected`)
4. Then trigger the PolySwarm enrichment

The connector checks these fields in order:
- `decryption_key` (preferred — standard OpenCTI artifact field)
- `x_opencti_encryption_password` (legacy fallback)

> **Note:** If the password is not provided for an encrypted archive, the scan engines will not be able to analyze the contents and results will be limited.

### Malware Profile Enrichment (Optional)

When `POLYKG_API_URL` is configured, the connector fetches live malware family profiles from the polykg REST API. This provides enhanced intelligence including threat actors, target locations, exploited CVEs, and related malware. The connector works fully without polykg — it just produces basic scan/sandbox enrichment without the extended threat intel.

## 🔧 Troubleshooting

### Common Issues

**Connector not starting:**
```bash
docker-compose logs connector-polyswarm-sandbox
# Check OpenCTI connectivity
curl http://opencti:8080/health
```

**No enrichment data:**
- Verify `POLYSWARM_MIN_POLYSCORE` threshold
- Check PolySwarm API quota
- Ensure file size is under limit (32MB default)

**Sandbox timeout:**
- Increase `POLYSWARM_SANDBOX_TIMEOUT`
- Check network connectivity

### Log Levels

Set `CONNECTOR_LOG_LEVEL` to:
- `debug`: Verbose logging
- `info`: Standard logging
- `warning`: Warnings only
- `error`: Errors only

## 📁 Project Structure

```
polyswarm-sandbox/
├── __metadata__/
│   └── connector_manifest.json  # OpenCTI connector catalog metadata
├── src/
│   ├── main.py                  # Entry point (ConnectorSettings)
│   ├── requirements.txt         # Python dependencies
│   ├── config.yml.sample        # YAML config template
│   ├── .env.sample              # Environment variable template
│   └── connector/               # Main package
│       ├── __init__.py
│       ├── polyswarm_connector.py  # Orchestration (scan → sandbox → reports → STIX)
│       ├── polyswarm_client.py     # PolySwarm API wrapper with retry
│       ├── stix_builder.py         # STIX 2.1 object generation
│       ├── scan_processor.py       # Scan result mapping
│       ├── sandbox_processor.py    # Sandbox result mapping (Triage + Cape)
│       ├── artifact_handler.py     # File download from OpenCTI
│       ├── ttp_mapping.py          # MITRE ATT&CK TTP database
│       └── models/configs/
│           └── settings.py         # Pydantic config (connectors_sdk)
├── tests/                       # 62+ unit tests
├── .dockerignore
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## 📈 Performance

| Operation | Typical Duration |
|-----------|------------------|
| Scan | 30-60 seconds |
| CAPE Sandbox | 5-10 minutes |
| Triage Sandbox | 3-7 minutes |
| Both Sandboxes | 10-15 minutes |

## 🔒 Security

- Files processed in memory (not written to disk)
- API keys via environment variables
- Network sandboxing configurable
- No sensitive data in logs

## 📄 License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## 🤝 Support

- **Sales & Quotas**: [sales@polyswarm.io](mailto:sales@polyswarm.io)
- **PolySwarm Docs**: [docs.polyswarm.io](https://docs.polyswarm.io)
- **OpenCTI Docs**: [docs.opencti.io](https://docs.opencti.io)
- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)

## 🙏 Credits

Developed for OpenCTI integration with PolySwarm's next-generation malware intelligence platform.
