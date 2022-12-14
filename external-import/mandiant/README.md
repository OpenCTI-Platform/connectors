# Mandiant Connector

This connector connects to the Mandiant Advantage API V4 and gather all data from a given date.

## Configuration

The connector can be configured with the following variables:

| Env var | Default | Description |
| - | - | - |
| `MANDIANT_API_URL` | https://api.intelligence.mandiant.com | URL for the Mandiant API |
| `MANDIANT_API_V4_KEY_ID` | | Mandiant API Key ID |
| `MANDIANT_API_V4_KEY_SECRET` | | Mandiant API Key Secret |
| `MANDIANT_INTERVAL` | 1 | Number of the days between each collection. |
| `MANDIANT_IMPORT_START_DATE` | 2023-01-01 | Date to start collect data |
| `MANDIANT_COLLECTIONS` | actor,malware,indicator,vulnerability,report | Type of data to be collected |
| `MANDIANT_REPORT_TYPES_IGNORED` | News Analysis| Type of data to be collected |

### Collections

* actor
* malware
* indicator
* vulnerability
* report

### Report Types

* Actor Profile
* Country Profile
* Event Coverage/Implication
* Executive Perspective
* ICS Security Roundup
* Industry Reporting
* Malware Profile
* Network Activity Reports
* News Analysis
* Patch Report
* TTP Deep Dive
* Threat Activity Alert
* Threat Activity Report
* Trends and Forecasting
* Vulnerability Report
* Weekly Vulnerability Exploitation Report
