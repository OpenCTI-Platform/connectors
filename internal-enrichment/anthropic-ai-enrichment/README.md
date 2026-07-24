# Anthropic AI Enrichment

The Anthropic AI Enrichment connector enriches OpenCTI reports, intrusion sets, threat actor groups, and malware objects with analyst-reviewable summaries and structured relationships.

The connector sends selected object text to the configured Anthropic model and asks for structured JSON containing:

- executive summary
- named threat actors
- malware and tool names
- MITRE ATT&CK technique identifiers
- target sectors
- target countries
- confidence score

The connector can create OpenCTI notes, link existing threat actors and malware, create or link attack patterns by ATT&CK ID, and update the OpenCTI score from the returned confidence value.

## Analyst Validation

AI output is an enrichment aid, not authoritative intelligence. Operators should review every generated note, relationship, ATT&CK mapping, and score before using it for detection engineering, reporting, or attribution.

## Configuration

| Parameter | Description | Required |
| --- | --- | --- |
| `OPENCTI_URL` | OpenCTI platform URL. | Yes |
| `OPENCTI_TOKEN` | OpenCTI API token. | Yes |
| `CONNECTOR_ID` | Connector UUID. | Yes |
| `CONNECTOR_NAME` | Connector display name. | No |
| `CONNECTOR_SCOPE` | OpenCTI entity scope. | No |
| `CONNECTOR_LOG_LEVEL` | Connector log level. | No |
| `ANTHROPIC_API_KEY` | Anthropic API key. | Yes |
| `AI_MODEL` | Anthropic model name. | No |

## Deployment

Copy `docker-compose.yml` into your OpenCTI deployment, set the required environment variables, and start the connector service.

```bash
docker compose up -d connector-anthropic-ai-enrichment
```

The connector is configured as an internal enrichment connector with `auto` disabled. Analysts can run it on selected entities from the OpenCTI interface.
