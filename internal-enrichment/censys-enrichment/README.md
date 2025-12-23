# Censys Enrichment Connector

Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
    - [Requirements](#requirements)
- [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
- [Usage](#usage)
- [Behavior](#behavior)
- [Additional information](#additional-information)

---

## Introduction

The **Censys Enrichment Connector** allows OpenCTI to enrich observables with intelligence retrieved from
the [Censys](https://search.censys.io/) API.

---

## Installation

### Requirements

- OpenCTI Platform >= 6.8.11

## Configuration variables

The connector can be configured via `config.yml`, `.env` or environment variables (Preferred in Docker).

---

## Deployment

### Docker Deployment

1. Configure environment variables in `docker-compose.yml`.
2. Run docker-compose:
   ```sh
   docker compose up -d
   ```

### Manual Deployment

1. Copy `.env.sample` to `.env`.
2. Edit with your OpenCTI and Censys credentials.
3. Install dependencies (preferably in a virtual environment):
   ```sh
   pip install -r requirements.txt
   ```  
4. Run the connector:
   ```sh
   python3 main.py
   ```

## Usage

- The connector will enrich supported observables (Domains, Hosts, IPs) with Censys data.
- The connector will fetch matching infrastructure and push it into OpenCTI.

## Behavior
  The connector enriches the following observable types:

  ### IPv4/IPv6 Addresses
  - Retrieves host information including geolocation, ASN, and services
  - Creates location entities (City, Country, Region, Administrative Area)
  - Links autonomous systems and organizations
  - Extracts DNS names associated with the IP
  - Creates software entities for detected services
  - Includes service banners as notes

  ### Domain Names
  - Searches for hosts with the domain in their DNS records
  - Creates IP address observables for discovered hosts
  - **Discovers X.509 certificates** that reference the domain in their Subject Alternative Names (SANs) or Common Name (CN)
  - Creates certificate entities with full metadata (issuer, validity, extensions)
  - Links certificates to the domain for infrastructure mapping

  This comprehensive domain enrichment is particularly useful for:
  - Certificate transparency monitoring
  - Threat actor infrastructure discovery
  - Identifying shared hosting or certificate patterns
  - Detecting potential phishing domains using similar certificates

  ### X.509 Certificates
  - Enriches certificates by their hash values (MD5, SHA-1, SHA-256)
  - Extracts detailed certificate metadata including extensions and key information

  **Note**: Certificate discovery for domains adds an additional API call per domain enrichment. Be mindful of Censys API rate limits.

## Additional information

- API reference: [Censys Search API](https://search.censys.io/api).
- Roadmap: potential support for more STIX observable types (e.g. Certificate, URL).  