# OpenCTI Scoring Calculator Connector

An enrichment connector for OpenCTI that dynamically adjusts Indicator scores based on the entities they are linked with.

The connector evaluates its relationships with labeled entities (threats, locations, sectors, etc.) and increases its score accordingly. This allows organizations to adjust Indicator score based on their own threat landscape, context, and intelligence priorities.

## How It Works

1. Label your entities. Apply priority labels to the entities in your platform that should influence Indicator scores (e.g., specific Threat Actors, Countries, Sectors).
2. When triggered, the connector evaluates relationships. It looks at the entities attached to the Indicator and checks whether they carry a priority label.
3. The score is impacted. For each matching category, a relative percentage is added to the Indicator's current score based on the priority level and your configuration.

Example of label name for the three available priority levels:

| Label                     | Impact Level                |
|---------------------------|-----------------------------|
| [Scoring] High priority   | Highest impact on the score |
| [Scoring] Medium priority | Medium impact on the score  |
| [Scoring] Low priority    | Lowest impact on the score  |

> **Note:** The label names need to be configured (see "Configuration" section).

## Supported Categories

The connector evaluates the following categories of related entities:

| Category | Entity Types                                                  | Description                                     |
|----------|---------------------------------------------------------------|-------------------------------------------------|
| Threat   | Intrusion Sets, Threat Actor Groups, Threat Actor Individuals | Threat targeting your organization or sector.   |
| Toolbox  | Malware, Tools                                                | Tools and malware families.                     |
| Location | Countries, Regions                                            | Geographic relevance to your organization.      |
| Sector   | Sectors                                                       | Industry sectors relevant to your organization. |
| TTP      | Attack Patterns                                               | Techniques and tactics.                         |
| Author   | Indicator `created_by_ref`                                    | Intelligence sources and feed providers.        |

Each category can be independently enabled or disabled.

## Scoring Formula

The impact on the score is relative — a percentage is applied to the remaining score margin (distance to 100). The formula is:

```
new_score = ((100 - current_score) * calculated_impact) + current_score
```

Key properties:

- The higher the current score, the smaller the absolute increase.
- The lower the current score, the larger the absolute increase.
- The score can never exceed 100.

#### Example

An Indicator with a current score of 30 is related to a Threat Actor labeled "[Scoring] High priority", configured with a 40% impact:

```
new_score = ((100 - 30) * 0.40) + 30
new_score = (70 * 0.40) + 30
new_score = 28 + 30
new_score = 58
```

The same Indicator, if it started at a score of 80:

```
new_score = ((100 - 80) * 0.40) + 80
new_score = (20 * 0.40) + 80
new_score = 8 + 80
new_score = 88
```

## Prerequisites

- An OpenCTI API token with sufficient permissions.
- Entities in your platform labeled with the appropriate priority labels (e.g. "[Scoring] High priority", "[Scoring] Medium priority", "[Scoring] Low priority").

## Configuration

### Generic Parameters

| Parameter             | Required | Description                            | Example                                |
|-----------------------|----------|----------------------------------------|----------------------------------------|
| `OPENCTI_URL`         | ✅        | URL of your OpenCTI platform           | `http://localhost`                     |
| `OPENCTI_TOKEN`       | ✅        | OpenCTI API token                      | `ChangeMe`                             |
| `CONNECTOR_ID`        | ✅        | Unique connector ID (UUIDv4)           | `12b22ff8-85fd-46e6-bb5f-d6c9b27e245d` |
| `CONNECTOR_NAME`      | ✅        | Display name of the connector          | `Scoring calculator`                   |
| `CONNECTOR_SCOPE`     | ✅        | Entity scope to enrich                 | `Indicator`                            |
| `CONNECTOR_LOG_LEVEL` | ✅        | Log verbosity level                    | `error`                                |
| `CONNECTOR_AUTO`      | ✅        | Auto-trigger on entity creation/update | `true`                                 |

### Scoring Parameters

| Parameter                                     | Required | Description                                            | Default                                    |
|-----------------------------------------------|----------|--------------------------------------------------------|--------------------------------------------|
| `CONNECTOR_SCORING_HIGH_PRIORITY_LABELS`      | ❌        | JSON array of labels for high priority                 | `[]`                                       |
| `CONNECTOR_SCORING_MEDIUM_PRIORITY_LABELS`    | ❌        | JSON array of labels for medium priority               | `[]`                                       |
| `CONNECTOR_SCORING_LOW_PRIORITY_LABELS`       | ❌        | JSON array of labels for low priority                  | `[]`                                       |
| `CONNECTOR_SCORING_INDICATOR_TYPE_ENRICHABLE` | ❌        | Comma-separated list of observable types to enrich     | `IPv4-Addr,IPv6-Addr,Domain-Name,StixFile` |
| `CONNECTOR_SCORING_BROWSE_REPORT`             | ❌        | Whether to browse reports for additional relationships | `false`                                    |

### Category-Specific Parameters

Each category follows the same pattern. Set `*_IMPACT_SCORE` to `true` to enable the category, then configure the percentage impact for each priority level.

#### Threat

| Parameter                                  | Required | Description                | Default |
|--------------------------------------------|----------|----------------------------|---------|
| `CONNECTOR_SCORING_THREAT_IMPACT_SCORE`    | ❌        | Enable threat category     | `false` |
| `CONNECTOR_SCORING_THREAT_HIGH_PRIORITY`   | ❌        | High priority impact (%)   | `0`     |
| `CONNECTOR_SCORING_THREAT_MEDIUM_PRIORITY` | ❌        | Medium priority impact (%) | `0`     |
| `CONNECTOR_SCORING_THREAT_LOW_PRIORITY`    | ❌        | Low priority impact (%)    | `0`     |

#### Toolbox

| Parameter                                   | Required | Description                | Default |
|---------------------------------------------|----------|----------------------------|--------|
| `CONNECTOR_SCORING_TOOLBOX_IMPACT_SCORE`    | ❌        | Enable toolbox category    | `false` |
| `CONNECTOR_SCORING_TOOLBOX_HIGH_PRIORITY`   | ❌        | High priority impact (%)   | `0`    |
| `CONNECTOR_SCORING_TOOLBOX_MEDIUM_PRIORITY` | ❌        | Medium priority impact (%) | `0`    |
| `CONNECTOR_SCORING_TOOLBOX_LOW_PRIORITY`    | ❌        | Low priority impact (%)    | `0`    |

#### Location

| Parameter                                    | Required | Description                | Default |
|----------------------------------------------|----------|----------------------------|---------|
| `CONNECTOR_SCORING_LOCATION_IMPACT_SCORE`    | ❌        | Enable location category   | `false` |
| `CONNECTOR_SCORING_LOCATION_HIGH_PRIORITY`   | ❌        | High priority impact (%)   | `0`     |
| `CONNECTOR_SCORING_LOCATION_MEDIUM_PRIORITY` | ❌        | Medium priority impact (%) | `0`     |
| `CONNECTOR_SCORING_LOCATION_LOW_PRIORITY`    | ❌        | Low priority impact (%)    | `0`     |

#### Sector

| Parameter                                  | Required | Description                | Default |
|--------------------------------------------|----------|----------------------------|---------|
| `CONNECTOR_SCORING_SECTOR_IMPACT_SCORE`    | ❌        | Enable sector category     | `false` |
| `CONNECTOR_SCORING_SECTOR_HIGH_PRIORITY`   | ❌        | High priority impact (%)   | `0`     |
| `CONNECTOR_SCORING_SECTOR_MEDIUM_PRIORITY` | ❌        | Medium priority impact (%) | `0`     |
| `CONNECTOR_SCORING_SECTOR_LOW_PRIORITY`    | ❌        | Low priority impact (%)    | `0`     |

#### TTP

| Parameter                               | Required | Description                | Default |
|-----------------------------------------|----------|----------------------------|---------|
| `CONNECTOR_SCORING_TTP_IMPACT_SCORE`    | ❌        | Enable TTP category        | `false` |
| `CONNECTOR_SCORING_TTP_HIGH_PRIORITY`   | ❌        | High priority impact (%)   | `0`     |
| `CONNECTOR_SCORING_TTP_MEDIUM_PRIORITY` | ❌        | Medium priority impact (%) | `0`     |
| `CONNECTOR_SCORING_TTP_LOW_PRIORITY`    | ❌        | Low priority impact (%)    | `0`     |

#### Author

| Parameter                                  | Required | Description                | Default |
|--------------------------------------------|----------|----------------------------|---------|
| `CONNECTOR_SCORING_AUTHOR_IMPACT_SCORE`    | ❌        | Enable author category     | `false` |
| `CONNECTOR_SCORING_AUTHOR_HIGH_PRIORITY`   | ❌        | High priority impact (%)   | `0`     |
| `CONNECTOR_SCORING_AUTHOR_MEDIUM_PRIORITY` | ❌        | Medium priority impact (%) | `0`     |
| `CONNECTOR_SCORING_AUTHOR_LOW_PRIORITY`    | ❌        | Low priority impact (%)    | `0`     |

## Usage Example

Below is a concrete example showing how the connector could be configured for an organization focused on the **European region**.

### Step 1 — Label your entities

Apply priority labels to the entities that matter to your organization:

| Category     | High Priority                                                                                                                      | Medium Priority                                                     | Low Priority                                                    |
|--------------|------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------|-----------------------------------------------------------------|
| **Threat**   | APT28, APT29, Sandworm, Turla                                                                                                      | Lazarus Group, APT31, Gamaredon, WIRTE, UNC1189                     | -                                                               |
| **Toolbox**  | All ransomware malware                                                                                                             | -                                                                   | -                                                               |
| **Location** | France, Germany, United Kingdom                                                                                                    | EU member states (Italy, Spain, Netherlands, Poland, Belgium, etc.) | Other European countries (Switzerland, Norway, Western Balkans) |
| **Sector**   | Government, Defense, Energy (Nuclear, Electricity, Gas), Finance (Banking, Insurance), Healthcare, Transportation (Aviation, Rail) | Telecommunications, Education, Manufacturing                        | -                                                               |
| **TTP**      | Spear-Phishing, Supply Chain Compromise                                                                                            | Valid Accounts, Exploitation of Public-Facing Applications          | -                                                               |
| **Author**   | ANSSI, ENISA                                                                                                                       | Mandiant/Google, Recorded Future                                    | Group-IB, Kaspersky                                             |

### Step 2 — The connector runs automatically

When an Indicator is created, the connector evaluates its relationships and adjusts the score. For example:

> An Indicator with a base score of **20** is related to **APT28** (Threat - High Priority, +40%) and targets **France** (Location - High Priority, +30%).

**Calculation:**

```
After Threat:    ((100 - 20) * 0.40) + 20 = 52
After Location:  ((100 - 52) * 0.30) + 52 = 66.4
```

**Final score: ~66**

The Indicator's score has been automatically updated based on your organization's context.