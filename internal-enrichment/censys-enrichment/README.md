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

- OpenCTI Platform >= 6.9

## Configuration variables

The connector can be configured via `config.yml`, `.env` or environment variables (Preferred in Docker).

---

## Deployment

### Docker Deployment

1. Set the pycti version in `requirements.txt` to match your OpenCTI version.
2. Build the Docker image:
   ```sh
   docker build . -t opencti-censys-enrichment:latest
   ```  
3. Configure environment variables in `docker-compose.yml`.
4. Run the container:
   ```sh
   docker compose up -d
   ```

### Manual Deployment

1. Copy `config.yml.sample` to `config.yml`.
2. Edit with your OpenCTI and Censys credentials.
3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```  
4. Run the connector:
   ```sh
   python3 main.py
   ```

## Usage

- The connector runs automatically and will enrich supported observables (Domains, Hosts, IPs) with Censys data.
- The connector will fetch matching infrastructure and push it into OpenCTI.

## Behavior

## Additional information

- API reference: [Censys Search API](https://search.censys.io/api).
- The connector is licensed under the Community license.
- Roadmap: potential support for more STIX observable types (e.g. Certificate, URL).  