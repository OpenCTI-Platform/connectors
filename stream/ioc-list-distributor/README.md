# OpenCTI IOC List Distributor Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | - | - |

Reads indicators from one OpenCTI live stream, keeps the current IOC set in a local SQLite database and
publishes it as plain-text lists (IP, domain, URL, hash; one entry per line) over HTTP and/or HTTPS,
for any client to pull.

> This is not OpenCTI's built-in CSV feed (*Data > Data sharing > CSV feeds*). This connector keeps
> its own copy of the IOCs, so the lists stay served while OpenCTI is unreachable, and it adds entry
> caps per feed, exclude lists, backups and drop guards.

## Table of Contents
- [Introduction](#introduction)
- [Requirements](#requirements)
- [OpenCTI stream setup](#opencti-stream-setup)
- [Configuration variables](#configuration-variables)
- [Deployment](#deployment)
- [Behavior](#behavior)
- [Files served](#files-served)
- [Database retention](#database-retention)
- [Database maintenance](#database-maintenance)
- [Debugging](#debugging)
- [Limitations](#limitations)

## Introduction
Two services, built from one image, share one volume (`/data`):

```
OpenCTI live stream (filters set in OpenCTI)
        │ outbound HTTPS (optional proxy)
        ▼
connector ──► /data/ioc.db (SQLite) ──► feed-distributor: export every N min ──► /data/feeds/*.txt
                                                └─ HTTP(S) ──► GET /feeds/ip.txt ... (clients)
```

1. **connector**: listens to the live stream and stores, updates and removes the IOC values of each
   indicator. It is the only service that talks to OpenCTI.
2. **feed-distributor**: every `EXPORT_INTERVAL_MINUTES`, builds one file per IOC type (filters, cap,
   sort) and serves the files over HTTP and/or HTTPS. It never receives the OpenCTI token.

If the stream connection stops, the last files keep being served.

## Requirements
- OpenCTI 7.261023.1 or later (SaaS or self-hosted).
- Docker Engine with Docker Compose v2.
- Outbound HTTPS from the host to OpenCTI, directly or through a proxy.
- Inbound access from the clients to the feed port (8080 for HTTP, 8443 for HTTPS by default).
- A **persistent volume** for `/data`. Without it, every restart reads the whole stream again.
- Disk space: about 650 bytes per stored IOC (1 million IOCs = about 650 MB).
- Optional: a TLS certificate and key for HTTPS.

## OpenCTI stream setup
1. **User and token.** Create a dedicated user in a group with the *Connector* role and read access
   to the indicators to publish. Copy its API token.
2. **Live stream.** *Data > Data sharing > Live streams > Create*, with at least these filters:
   - `Entity type = Indicator`
   - `Pattern type = stix`

   Add any other filters there (observable type, score, detection, revoked, TLP, labels, …).
   **The connector publishes everything the stream sends it**, apart from the safety filters
   described under [Behavior](#behavior). Copy the stream ID.
3. **Connector ID.** Generate a UUID v4, for example with `uuidgen | tr A-Z a-z`. The stream
   position is stored in OpenCTI under it.

## Configuration variables
Settings are read from environment variables. With Docker, they are set in the `environment:` list
of each service in `docker-compose.yml`, which lists every setting with its default and a comment.
Without Docker, the same settings can be put in `src/config.yml` (copy `config.yml.sample`); an
environment variable always wins over `config.yml`. A required setting that is missing, or
`CONNECTOR_LIVE_STREAM_ID` still set to `ChangeMe`, stops the connector at startup with the setting
named.

Each service only gets the settings it uses: the OpenCTI, connector and outbound proxy settings go
to `connector`; the export, custom feed and feed distributor settings go to `feed-distributor`.
The feed-distributor never receives the OpenCTI token.

### OpenCTI environment variables
| Parameter | Docker environment variable | Mandatory | Default | Description |
|---|---|---|---|---|
| OpenCTI URL | `OPENCTI_URL` | Yes | | The URL of the OpenCTI platform |
| OpenCTI token | `OPENCTI_TOKEN` | Yes | | The token of the connector's OpenCTI user |
| SSL verify | `OPENCTI_SSL_VERIFY` | No | `true` | `false` accepts any certificate |

### Base connector environment variables
| Parameter | Docker environment variable | Mandatory | Default | Description |
|---|---|---|---|---|
| Connector ID | `CONNECTOR_ID` | Yes | | A UUID v4, kept across restarts (the stream position is stored under it) |
| Live stream ID | `CONNECTOR_LIVE_STREAM_ID` | Yes | | ID of the live stream created in OpenCTI |
| Name | `CONNECTOR_NAME` | No | `IOC List Distributor` | Name shown in *Data > Ingestion > Connectors* |
| Replay start | `CONNECTOR_LIVE_STREAM_START_TIMESTAMP` | No | empty | Epoch milliseconds, read only when the connector has no saved state |
| Log level | `LOG_LEVEL` | No | `info` | `debug`, `info`, `warning`, `error`. Set on each service |
| Name fallback | `PARSER_NAME_FALLBACK` | No | `false` | Use the indicator name when the pattern gives no value, only if the name is a valid value of the main observable type |

### Export environment variables
| Parameter | Docker environment variable | Mandatory | Default | Description |
|---|---|---|---|---|
| Export interval | `EXPORT_INTERVAL_MINUTES` | No | `5` | Minutes between two exports |
| Export ip | `EXPORT_ENABLED_IP` | No | `true` | `false`: the ip files of every feed are not exported and return 404. Its IOCs are still stored |
| Export domain | `EXPORT_ENABLED_DOMAIN` | No | `true` | `false`: the domain files of every feed are not exported and return 404. Its IOCs are still stored |
| Export url | `EXPORT_ENABLED_URL` | No | `true` | `false`: the url files of every feed are not exported and return 404. Its IOCs are still stored |
| Export hash | `EXPORT_ENABLED_HASH` | No | `true` | `false`: the hash files of every feed are not exported and return 404. Its IOCs are still stored |
| Hard limit | `EXPORT_HARD_MAX_ENTRIES` | No | `500000` | Caps every file of every feed; a cap above it (or `0`) is reduced to it. `0` = off |
| Entries per file | `EXPORT_MAX_ENTRIES` | No | `5000` | Main feed cap per file. `0` = no cap (up to the hard limit) |
| ip entries | `EXPORT_MAX_ENTRIES_IP` | No | empty | Overrides `EXPORT_MAX_ENTRIES` for `ip.txt`. Empty = `EXPORT_MAX_ENTRIES` |
| domain entries | `EXPORT_MAX_ENTRIES_DOMAIN` | No | empty | Overrides `EXPORT_MAX_ENTRIES` for `domain.txt`. Empty = `EXPORT_MAX_ENTRIES` |
| url entries | `EXPORT_MAX_ENTRIES_URL` | No | empty | Overrides `EXPORT_MAX_ENTRIES` for `url.txt`. Empty = `EXPORT_MAX_ENTRIES` |
| hash entries | `EXPORT_MAX_ENTRIES_HASH` | No | empty | Overrides `EXPORT_MAX_ENTRIES` for `hash.txt`. Empty = `EXPORT_MAX_ENTRIES` |
| Rolling window | `EXPORT_ROLLING_WINDOW_MINUTES` | No | `43200` (30 days) | Only IOCs whose base attribute is inside the window are exported. `0` = no window |
| ip window | `EXPORT_ROLLING_WINDOW_MINUTES_IP` | No | empty | Overrides `EXPORT_ROLLING_WINDOW_MINUTES` for ip. Empty = the main window; `0` = no window |
| domain window | `EXPORT_ROLLING_WINDOW_MINUTES_DOMAIN` | No | empty | Overrides `EXPORT_ROLLING_WINDOW_MINUTES` for domain. Empty = the main window; `0` = no window |
| url window | `EXPORT_ROLLING_WINDOW_MINUTES_URL` | No | empty | Overrides `EXPORT_ROLLING_WINDOW_MINUTES` for url. Empty = the main window; `0` = no window |
| hash window | `EXPORT_ROLLING_WINDOW_MINUTES_HASH` | No | empty | Overrides `EXPORT_ROLLING_WINDOW_MINUTES` for hash. Empty = the main window; `0` = no window |
| Base attribute | `EXPORT_BASE_ATTRIBUTE` | No | `modified` | `created`, `modified` (OpenCTI), `first_seen_local`, `last_updated_local` (connector) |
| Sort order | `EXPORT_SORT_ORDER` | No | `base_attribute` | Which entries are kept over the cap: `base_attribute` (newest first) or `score` (highest first) |
| Exclude expired | `EXPORT_EXCLUDE_EXPIRED` | No | `true` | Leave out indicators past their `valid_until` |
| Hash algorithms | `EXPORT_HASH_ALGORITHMS` | No | `md5,sha1,sha256` | Written to `hash.txt` (`md5`, `sha1`, `sha256`, `sha512`) |
| Split hash files | `EXPORT_HASH_SPLIT_FILES` | No | `false` | Also write `hash_md5.txt`, `hash_sha1.txt`, ... |
| Strip URL scheme | `EXPORT_URL_STRIP_SCHEME` | No | `true` | Write URLs without `http://` / `https://` |
| Drop non-public IPs | `EXPORT_DROP_NON_PUBLIC_IPS` | No | `true` | Never export private, loopback, link-local, multicast and reserved ranges |
| Widest IPv4 range | `EXPORT_IP_MIN_PREFIX_V4` | No | `24` | A wider CIDR is never exported. `0` = no limit |
| Widest IPv6 range | `EXPORT_IP_MIN_PREFIX_V6` | No | `48` | Same for IPv6 |
| IP exclude list | `EXPORT_IP_EXCLUDE` | No | empty | Comma-separated IPs / CIDRs never exported. See [Behavior](#behavior) |
| Domain exclude list | `EXPORT_DOMAIN_EXCLUDE` | No | empty | Comma-separated domains (subdomains included) never exported |
| IP exclude file | `EXPORT_IP_EXCLUDE_FILE` | No | empty | One entry per line, e.g. `/config/ip_exclude.txt` |
| Domain exclude file | `EXPORT_DOMAIN_EXCLUDE_FILE` | No | empty | e.g. `/config/domain_exclude.txt` |
| Keep previous on empty | `EXPORT_KEEP_PREVIOUS_ON_EMPTY` | No | `true` | Keep the current file if the new export is empty |
| Max drop | `EXPORT_MAX_DROP_PERCENT` | No | `0` (off) | Keep the current file if the entry count drops by more than this % |
| Warn on drop | `EXPORT_WARN_DROP_PERCENT` | No | `0` (off) | Log a WARNING when a file drops by more than this %. Log only |
| Error on drop | `EXPORT_ERROR_DROP_PERCENT` | No | `0` (off) | Log an ERROR when a file drops by more than this %. Log only |
| Backups | `BACKUP_RETENTION` | No | `5` | Previous versions kept per file |
| DB retention | `DB_RETENTION_DAYS` | No | `0` (off); `docker-compose.yml` sets `90` | Delete stored IOCs not modified for this many days. See [Database retention](#database-retention) |

### Custom feed environment variables
Each enabled custom feed adds its own files next to the main feed, with its own cap.

`n` in the variable names below is the number of the custom feed, from `1` to `CUSTOM_FEED_COUNT`.
Every custom feed uses the same variables with its own number: for example, `CUSTOM_FEED1_ENABLED`
and `CUSTOM_FEED1_NAME` set up the first custom feed, `CUSTOM_FEED2_ENABLED` the second.
`docker-compose.yml` lists feeds 1-3.

| Parameter | Docker environment variable | Mandatory | Default | Description |
|---|---|---|---|---|
| Feed count | `CUSTOM_FEED_COUNT` | No | `3` | Number of custom feeds read (0-10). Raise it to add feeds 4-10 |
| Feed n enabled | `CUSTOM_FEEDn_ENABLED` | No | `false` | `true` publishes custom feed `n` |
| Feed n name | `CUSTOM_FEEDn_NAME` | No | `custom<n>` | Prefix of its files (`<name>_ip.txt`, ...). Lower-cased; letters, digits, `-`, `_`; not `ip`/`domain`/`url`/`hash`; unique |
| Feed n entries | `CUSTOM_FEEDn_MAX_ENTRIES` | No | empty | Cap per file. Empty = the main feed's cap; `0` = no cap of its own (up to the hard limit) |
| Feed n entries per type | `CUSTOM_FEEDn_MAX_ENTRIES_<TYPE>` | No | empty | Optional, commented out in `docker-compose.yml`. Overrides `CUSTOM_FEEDn_MAX_ENTRIES` for one type; `<TYPE>` is `IP`, `DOMAIN`, `URL` or `HASH` (e.g. `CUSTOM_FEED1_MAX_ENTRIES_IP`) |

### Database environment variables
| Parameter | Docker environment variable | Mandatory | Default | Description |
|---|---|---|---|---|
| SQLite file | `DB_SQLITE_PATH` | No | `/data/ioc.db` | Path inside the containers (set it on both services) |

### Feed distributor environment variables
| Parameter | Docker environment variable | Mandatory | Default | Description |
|---|---|---|---|---|
| Listen address | `FEED_DISTRIBUTOR_HOST` | No | `0.0.0.0` | |
| HTTP | `FEED_DISTRIBUTOR_HTTP_ENABLED` | No | `true` | |
| HTTP port | `FEED_DISTRIBUTOR_HTTP_PORT` | No | `8080` | |
| HTTPS | `FEED_DISTRIBUTOR_HTTPS_ENABLED` | No | `false` | |
| HTTPS port | `FEED_DISTRIBUTOR_HTTPS_PORT` | No | `8443` | |
| TLS certificate | `FEED_DISTRIBUTOR_TLS_CERT_FILE` | With HTTPS | | Full chain, PEM, e.g. `/certs/server.crt` |
| TLS key | `FEED_DISTRIBUTOR_TLS_KEY_FILE` | With HTTPS | | Unencrypted PEM key, e.g. `/certs/server.key` |
| API docs | `FEED_DISTRIBUTOR_DOCS_ENABLED` | No | `false` | Serve `/docs` |
| Authentication | `FEED_DISTRIBUTOR_AUTH_MODE` | No | `none` | `none`, `basic` or `bearer`. See [Deployment](#deployment) |
| User | `FEED_DISTRIBUTOR_AUTH_USER` | With `basic` | | Cannot contain `:` |
| Passtoken | `FEED_DISTRIBUTOR_AUTH_PASSTOKEN` | With `basic` / `bearer` | | Never logged |

### Outbound proxy and Docker environment variables
| Parameter | Docker environment variable | Mandatory | Default | Description |
|---|---|---|---|---|
| Proxy | `OUTBOUND_PROXY_URL` | No | empty | e.g. `http://proxy.corp.local:3128` (connector to OpenCTI) |
| No proxy | `OUTBOUND_NO_PROXY` | No | empty | e.g. `localhost,127.0.0.1` |
| Proxy CA bundle | `OUTBOUND_PROXY_CA_BUNDLE` | No | empty | Only for a TLS-inspecting proxy: PEM with the proxy CA **and** the public CAs |
| pycti version | `PYCTI_VERSION` | No | `7.261023.1` | Build argument (`PYCTI_VERSION=... docker compose build`), not a runtime setting |

Docker log rotation is set in `docker-compose.yml` (`x-logging`: 5 files of 10 MB per container).

## Deployment
### Docker deployment
Edit `docker-compose.yml`: fill in `OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID` and
`CONNECTOR_LIVE_STREAM_ID` under `connector`, and the export and feed settings under
`feed-distributor`. Then:
```
docker compose up -d --build
docker compose logs -f
```
- After changing a setting, run `docker compose up -d <service>`. A `docker compose restart` does
  not apply a changed environment.
- **Avoid `$` in values**: Docker Compose expands it. Write `$$` for a literal `$`.
- To keep the token out of the file, write `- OPENCTI_TOKEN=${OPENCTI_TOKEN}` and set
  `OPENCTI_TOKEN` in the shell that runs `docker compose`.
- If you change `FEED_DISTRIBUTOR_HTTP_PORT` or `FEED_DISTRIBUTOR_HTTPS_PORT`, change the matching
  `ports:` line too.

Both services use the same image. `./certs` is mounted read-only at `/certs`, and `./exclusions`
at `/config` in the feed-distributor. On first start the connector reads the stream's existing
content, so the files fill up over the first minutes. After that, the stream position is saved in
OpenCTI and the connector resumes from it after a restart.

### HTTPS
HTTP and HTTPS can run at the same time on different ports. Under `feed-distributor`:
```
      - FEED_DISTRIBUTOR_HTTPS_ENABLED=true
      - FEED_DISTRIBUTOR_TLS_CERT_FILE=/certs/server.crt
      - FEED_DISTRIBUTOR_TLS_KEY_FILE=/certs/server.key
```
Put two files in `./certs`, readable by UID 10001 (the container user):

| File | Content |
|---|---|
| `server.crt` | Certificate in PEM, full chain: server certificate first, then the intermediates |
| `server.key` | Matching private key in PEM, not password-protected |

`./certs` holds `server.crt.sample` and `server.key.sample`, which describe each file and how to
check it. They are never read. Use a certificate from an internal or public CA: most clients reject
a self-signed certificate unless its CA is imported.

### Feed authentication
One shared credential for every client:

| `FEED_DISTRIBUTOR_AUTH_MODE` | Client sends | Uses |
|---|---|---|
| `none` (default) | nothing | - |
| `basic` | `Authorization: Basic base64(user:passtoken)` | `FEED_DISTRIBUTOR_AUTH_USER` + `FEED_DISTRIBUTOR_AUTH_PASSTOKEN` |
| `bearer` | `Authorization: Bearer <passtoken>` | `FEED_DISTRIBUTOR_AUTH_PASSTOKEN` only |

Generate a passtoken:
```
docker compose run --rm feed-distributor python -m ioc_distributor.feed_auth make-token
```
- The feed files and `/stats` are protected; a refused request gets `401`.
- Credentials are compared in constant time and never logged.
- **Use HTTPS**: over plain HTTP the credentials are readable on the network.
- **Avoid `$` in the passtoken**: Docker Compose expands it and silently changes it (or write `$$`).

For a client with no credential fields, keep `none` and restrict access by source IP.

### Outbound proxy
Under `connector`:
```
      - OUTBOUND_PROXY_URL=http://proxy.corp.local:3128
      - OUTBOUND_NO_PROXY=localhost,127.0.0.1
      - OUTBOUND_PROXY_CA_BUNDLE=/certs/proxy-ca-bundle.pem   # only for a TLS-inspecting proxy
```
The connector is the only service that goes out (to OpenCTI). The CA bundle replaces the default
trust store, so it must also contain the public CAs.

## Behavior
- **Stream events:** a created or updated indicator has its values extracted and stored; values it
  no longer carries are removed. A revoked, deleted or merged-away indicator, or one that no longer
  matches the stream filters, has its values removed. Other entity types are ignored.
- **Value extraction:** values come from the STIX pattern, not the indicator name. `OR` patterns give
  one entry per value. Patterns with `AND`, `FOLLOWEDBY`, `NOT`, qualifiers or operators other than
  `=` are skipped. Values are refanged, lower-cased where relevant and validated.

  | Pattern | File |
  |---|---|
  | `[ipv4-addr:value = ...]`, `[ipv6-addr:value = ...]` | `ip.txt` |
  | `[domain-name:value = ...]`, `[hostname:value = ...]` | `domain.txt` |
  | `[url:value = 'http://evil.com/a']` | `url.txt` (as `evil.com/a`) |
  | `[file:hashes.'SHA-256' = ...]` (MD5, SHA-1, SHA-256, SHA-512) | `hash.txt` |

- **Export cycle:** every `EXPORT_INTERVAL_MINUTES`, each enabled type is filtered (rolling window,
  expiry, safety filters, exclude lists), sorted, cut to its cap, and written atomically, so a
  client never downloads half a file. The previous file is kept as a backup. A file cut by its cap
  logs a WARNING naming the setting behind it. The same data and settings always give the same files.
- **Custom feeds:** each enabled custom feed adds `<name>_ip.txt`, `<name>_domain.txt`, ... with its
  own cap, e.g. one feed per client with its own size limit. A smaller feed's entries are always a subset of a
  larger one's.
- **Rolling window per type:** e.g. 7 days for IPs, 30 days for domains and URLs, 90 days for hashes
  (`EXPORT_ROLLING_WINDOW_MINUTES_<TYPE>`).
- **Safety guards:** a file that would become empty (`EXPORT_KEEP_PREVIOUS_ON_EMPTY`) or drop by more
  than `EXPORT_MAX_DROP_PERCENT` keeps its current content, and a WARNING is logged.
  `EXPORT_WARN_DROP_PERCENT` / `EXPORT_ERROR_DROP_PERCENT` only log. Private and reserved IP ranges,
  and CIDRs wider than `/24` (IPv4) or `/48` (IPv6), are never exported, so one bad indicator cannot
  cut a network off.
- **Exclude lists:** IPs, CIDRs and domains (subdomains included) that are never distributed, e.g.
  your own public IPs and domains. They apply to the matching type and to URLs whose host matches.
  Files go in `./exclusions/` (one entry per line, `#` comments; examples included) and are read at
  startup. An unreadable file or invalid entry stops startup, so the protection is never silently lost.

## Files served
| Endpoint | Content |
|---|---|
| `GET /feeds/ip.txt` | IPv4 and IPv6 addresses and CIDRs |
| `GET /feeds/domain.txt` | Domains and hostnames |
| `GET /feeds/url.txt` | URLs (scheme stripped by default) |
| `GET /feeds/hash.txt` | MD5, SHA-1 and SHA-256 hashes (configurable) |
| `GET /feeds/hash_<algo>.txt` | One file per algorithm, with `EXPORT_HASH_SPLIT_FILES=true` |
| `GET /feeds/<name>_<type>.txt` | Custom feed files |
| `GET /stats` | Values per type, stream activity, last export per file, active settings |

Files have no header or comment lines, `\n` line endings, and are sorted alphabetically. Responses
carry `ETag` / `Last-Modified` and answer `304 Not Modified` to conditional requests.

Set each cap to fit the smallest client that reads that feed.

## Database retention
Rows leave the database when OpenCTI sends a delete or a revoke on the stream. Everything else is
kept, including IOCs too old to appear in any file. `DB_RETENTION_DAYS` is the safeguard against
the database growing forever:

- It deletes the rows not modified for that many days. `0` (the built-in default) keeps every row;
  `docker-compose.yml` sets `90`.
- Set it **above the longest rolling window** in use (e.g. `90` with the 30-day default), so a
  deleted row could not have been in any file.
- The purge runs at each export and logs how many rows it deleted. An indicator updated later in
  OpenCTI comes back through the stream.
- Deleting rows does not make the file smaller: SQLite reuses the free space for new rows. To
  shrink the file, see below.

IOCs that are never revoked (no `valid_until`, or one years away) leave in two steps:

1. **The files:** the rolling window drops an IOC once OpenCTI has not modified the indicator
   within the window, whatever its `valid_until`. An indicator OpenCTI keeps updating (decay,
   enrichment, an analyst edit) stays in.
2. **The database:** `DB_RETENTION_DAYS` deletes the row after that many days without a
   modification. It does not look at `valid_until` either.

A window longer than `DB_RETENTION_DAYS` is cut short, because the older rows are already deleted.
To keep long-lived IOCs in the files, lengthen the window (or one type's window) and raise
`DB_RETENTION_DAYS` above it. To end them in OpenCTI instead, use indicator decay: the revoke it
sends deletes the row.

## Database maintenance
Size of the database and free disk (safe while the connector runs):
```
docker compose exec feed-distributor sh -c 'ls -lh /data/ioc.db*; df -h /data'
```

How old the rows are (rows older than the rolling window are never published):
```
docker compose exec feed-distributor python -c "import sqlite3;c=sqlite3.connect('/data/ioc.db');print(c.execute(\"select case when d>=date('now','-30 day') then '<30d' when d>=date('now','-90 day') then '30-90d' when d>=date('now','-365 day') then '90d-1y' else '>1y' end,count(*) from (select coalesce(modified,last_updated_local) d from ioc) group by 1\").fetchall())"
```

Shrink the file with `VACUUM`, after a large purge (e.g. the first export after turning on
`DB_RETENTION_DAYS`). It never runs on its own. Back up the volume first, and make sure the disk has
about twice the database size free. **Stop the connector first**; the feed-distributor keeps
serving the files, and the stream position is kept in OpenCTI, so nothing is replayed:
```
docker compose stop connector
docker compose exec feed-distributor python -c "import sqlite3;c=sqlite3.connect('/data/ioc.db',timeout=600,isolation_level=None);c.execute('VACUUM');c.execute('PRAGMA wal_checkpoint(TRUNCATE)');print('done')"
docker compose start connector
```
It takes a few minutes on a large database. An export that starts meanwhile may log
`Export failed`; the files served stay as they were and the next export runs normally.

Do not delete the database to free space: the connector would read the whole stream again.

## Debugging
- Set `LOG_LEVEL=debug` to log each indicator stored, skipped, deleted, revoked or merged.
- At `info`, the connector logs a stream summary every 5 minutes while events arrive, and the
  feed-distributor logs one line per file at each export.
- Every value left out of a file is logged once with its reason (`not exported: ...`) and listed in
  `/stats`.

| Symptom | Cause and fix |
|---|---|
| Files empty, or `/stats` shows no stream events | Wrong `OPENCTI_URL` or token, the user cannot read the indicators, or the stream filters match nothing. The first start takes some minutes |
| Certificate errors towards OpenCTI | TLS-inspecting proxy: set `OUTBOUND_PROXY_CA_BUNDLE` |
| Client gets `401` | Wrong user or passtoken, or a `$` in the value changed by Docker Compose |
| Client gets `404` for a file | The type is switched off, or the custom feed is disabled or renamed |
| `<file> capped at N of M available` | Raise the cap within the client's limit, or shorten the rolling window |
| `kept previous` | A safety guard held the file: see [Behavior](#behavior) |
| A changed setting has no effect | `docker compose restart` does not apply a changed environment: use `docker compose up -d <service>`. Check the setting is under the service that uses it |
| ERROR and `failed` on database writes | Disk full: see [Database maintenance](#database-maintenance) |

## Limitations
- One instance per stream and database (no high availability).
- The connector keeps a local database, so it needs a persistent volume.
- Only STIX patterns with `=` comparisons on IPv4, IPv6, domain, hostname, URL and file hashes are
  published.
- Nothing warns when the database or the disk grows; a full disk stops database writes (the files
  already published keep being served). Use `DB_RETENTION_DAYS` and check the free space.
- **Connector state reset in the OpenCTI UI:** the connector reads the whole stream again. Nothing
  is duplicated, but indicators deleted while it was down can stay in the database until
  `DB_RETENTION_DAYS` removes them. To start clean, remove the data volume as well.
- pycti is installed at `PYCTI_VERSION` (default 7.261023.1) and works with OpenCTI 7.x. Rebuild with
  the platform version when the major version changes.
- One shared feed credential: changing it means updating every client at the same time.
