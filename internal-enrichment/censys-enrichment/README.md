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

## Additional information

- API reference: [Censys Search API](https://search.censys.io/api).
- Roadmap: potential support for more STIX observable types (e.g. Certificate, URL).  