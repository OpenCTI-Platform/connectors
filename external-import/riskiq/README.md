# Depreciation of RiskIQ connector

> [!WARNING]  
> **This connector is now obsolete.**  
> Microsoft who acquired RiskIQ has decommissioned all RiskIQ's APIs and integrated RiskIQ data directly into their product.
> The Community version is no longer functional.
> This connector will no longer be maintained. Please do not use it again.

# OpenCTI RiskIQ Connector

The OpenCTI RiskIQ connector can be used to import knowledge from the [RiskIQ API](https://api.riskiq.net).

The connector import RiskIQ's articles. An article is stored as a STIX `Report`, containing multiples `Indicators`.

By default, the connector runs every day, starting from the last state. The saved state is the `createdDate` of the inserted article.

For each `Report`, the following observable are implemented:

- `File` (for hashes: MD5, SHA-1, SHA-256)
- `Domain`
- `EmailAdress`
- `File`
- `IPv4Address`
- `Mutex`
- `X509Certificate`

## Configuration

The connector can be configured with the following variables:

| Config Parameter  | Docker env var         | Default                           | Description                                                                                                       |
| ----------------- | ---------------------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `base_url`        | `RISKIQ_BASE_URL`      | `https://api.riskiq.net/pt/v2/`   | The base URL for the RiskIQ API.
| `user`            | `RISKIQ_USER`          | `ChangeMe`                        | The user name required for the authentication.
| `password`        | `RISKIQ_PASSWORD`      | `ChangeMe`                        | The password required for the authentication.
| `interval_sec`    | `RISKIQ_INTERVAL_SEC`  | `86400`                           | The interval, in seconds, between two imports.

## Behaviour

1. Retrieves all the new articles since the last state from RiskIQ's API.
2. For each article, create a `Report` with all its `Indicators`.
3. Bundle each article and send it to RabbitMQ.
4. Update the state and wait the wanted interval before running again.
