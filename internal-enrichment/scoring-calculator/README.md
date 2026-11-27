# OpenCTI Scoring Calculator Connector

An enrichment connector for OpenCTI that dynamically adjusts Indicator scores based on the entities they are linked with.

The connector evaluates its relationships with labeled entities (threats, locations, sectors, etc.) and increases its score accordingly. This allows organizations to adjust Indicator score based on their own threat landscape, context, and intelligence priorities.

## How It Works

1. Label your entities. Apply priority labels to the entities in your platform that should influence Indicator scores (e.g., specific Threat Actors, Countries, Sectors).
2. When triggered, the connector evaluates relationships. It looks at the entities attached to the Indicator and checks whether they carry a priority label.
3. The score is impacted. Every matching entity contributes its category + priority impact percentage to a combined impact ratio (summed across all matching entities, then capped at 100%); the relative-percentage formula below is applied once to the Indicator's current score using that combined ratio.

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

Where `calculated_impact` is the combined ratio of all matching entities (e.g. a single Threat-High at +40% gives `0.40`; a Threat-High at +40% combined with a Location-High at +30% gives `0.70`). Combined ratios above `1.0` are capped so the formula never reduces the remaining margin below zero.

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

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

> **Note:** `CONNECTOR_MAX_TLP` is listed there, but the connector does not check it yet.

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
Combined impact:  40% (Threat - High) + 30% (Location - High) = 70%  →  ratio 0.70
new_score:        ((100 - 20) * 0.70) + 20
                = (80 * 0.70) + 20
                = 56 + 20
                = 76
```

**Final score: 76**

The Indicator's score has been automatically updated based on your organization's context.