# Optional: multiple connector containers (same image)

Several OpenCTI connector registrations (different `CONNECTOR_ID`, name, container), one image, each with its own collection subset.

The repository root **`docker-compose.yml`** and **`.env.sample`** are unchanged.

## How env files work

1. **Generate `env/common.env`** from the minimal multi-instance template (globals only — OpenCTI, MQ, TI API, extra settings; **no** per-collection knobs):

   ```bash
   cd docker-instances/env
   cp common.env.sample common.env
   ```

2. **Edit `env/common.env`** (secrets, global defaults). You normally leave all `TI_API__COLLECTIONS__*__ENABLE=false` here.

3. **Per service**: copy `env/groups/<profile>.env.sample` → `env/groups/<profile>.env`, set **`CONNECTOR_ID`**, adjust connector display name if needed.

`docker-compose.yml` loads **`env/common.env`** then **`env/groups/<profile>.env`** for that service (later overrides earlier).

See **`env/README.md`** for the per-profile mapping (collections → OpenCTI entities → TLP).

## Commands

```bash
cd docker-instances
docker compose up -d connector_accounts_unique
```

Change the external network in `docker-compose.yml` if not `docker_default`.

> Each service's group env file is declared `required: false` (and `env/common.env` `required: true`), so you only need to create `env/common.env` plus the `env/groups/<profile>.env` for the profile(s) you actually run — the other services' group files may be absent. Requires Docker Compose ≥ 2.24.

## Profiles (16)

| Scope                                        | Compose service                | Group file               |
| -------------------------------------------- | ------------------------------ | ------------------------ |
| Accounts (unique mode)                       | `connector_accounts_unique`    | `accounts-unique.env`    |
| Accounts (combolist mode)                    | `connector_accounts_combolist` | `accounts-combolist.env` |
| Bank cards (masked + unmasked)               | `connector_cards`              | `cards.env`              |
| Public + Git leaks                           | `connector_leaks`              | `leaks.env`              |
| Compromised access (initial-access brokers)  | `connector_compromised_access` | `compromised-access.env` |
| Discord & messenger chats                    | `connector_compromised_chat`   | `compromised-chat.env`   |
| OSI vulnerabilities                          | `connector_vulnerabilities`    | `vulnerabilities.env`    |
| Suspicious payment details (SPD)             | `connector_spd`                | `spd.env`                |
| Suspicious IP feeds (5)                      | `connector_suspicious_ip`      | `suspicious-ip.env`      |
| Malware CnC                                  | `connector_malware_cnc`        | `malware-cnc.env`        |
| DDoS / Deface / Phishing                     | `connector_attacks`            | `attacks.env`            |
| Darkweb forum posts                          | `connector_darkweb`            | `darkweb.env`            |
| APT reports + actors                         | `connector_apt_reports`        | `apt-reports.env`        |
| HI reports + actors + open-threats           | `connector_hi_reports`         | `hi-reports.env`         |
| Malware reports / config / signatures / YARA | `connector_malware_reports`    | `malware-reports.env`    |
| Common IOC stream                            | `connector_iocs`               | `iocs.env`               |

For collection → OpenCTI entity / TLP / relationship mapping, see the **Collection → OpenCTI mapping** section in [`../README.md`](../README.md).
