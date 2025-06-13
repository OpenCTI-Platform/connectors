# TDR: Structure models mirroring OCTI UI

## Overview

This TDR proposes to structure for the connectors-sdk octi models package in a way that mirrors the structure of the OCTI UI. This will help maintain consistency between the connectors and frontend, making it easier for developers to navigate and understand the codebase and the results.
This structure will also facilitate the development of new features and improvements by providing a clear and organized framework.

---

## Motivation
<!-- Why is this needed? What problem does it solve? -->

To start the development of the connectors-sdk octi models package, it is essential to have a clear and organized structure. Defining this structure is crucial for the maintainability and scalability of the codebase. By mirroring the OCTI UI structure, we can ensure that the connectors models align with the frontend components, making it easier for developers to work on both ends of the application. This approach is driven by the Model Driven Engineering methodology, which helps avoid confusion between connectors-sdk and pycti, the Python API client used to interact with OCTI.

---

## Proposed Solution
<!-- What are you implementing? Mention key classes/functions or architectural points. -->

The architecture will align with the OCTI UI structure, which is organized into the following main components (consulted on 6.6.14):

```plaintext
├── activities
│   ├── analyses
│   │   ├── reports
│   │   ├── groupings
│   │   ├── malware_analyses
│   │   ├── notes
│   │   └── external_references
│   ├── cases
│   │   ├── incident_responses
│   │   ├── requests_for_information
│   │   ├── requests_for_takedown
│   │   ├── tasks
│   │   └── feedbacks
│   ├── events
│   │   ├── incidents
│   │   ├── sightings
│   │   └── observed_data
│   └── observations
│       ├── observables
│       ├── artifacts
│       ├── indicators
│       └── infrastructures
├── knowledge
│   ├── threats
│   │   ├── threat_actors
│   │   ├── intrusions_sets
│   │   └── campaigns
│   ├── arsenal
│   │   ├── malware
│   │   ├── channels
│   │   ├── tools
│   │   └── vulnerabilities
│   ├── techniques
│   │   ├── attack_patterns
│   │   ├── naratives
│   │   ├── courses_of_action
│   │   ├── data_components
│   │   └── data_sources
│   ├── entities
│   │   ├── sectors
│   │   ├── events
│   │   ├── organizations
│   │   ├── systems
│   │   └── individuals
│   └── locations
│       ├── regions
│       ├── countries
│       ├── administrative_areas
│       ├── cities
│       └── positions
```

To enhance usability, the models will be made publicly accessible through the `models.octi` package by utilizing the `__init__.py` file.

The common methods and tools will be implemented in the `_common.py` module in each subpackages.

The proposed structure will be as follows:

```plaintext
├── models
│   ├── __init__.py
│   ├── octi
│   │   ├── __init__.py
│   │   ├── _common.py
│   │   ├── activities
│   │   │   ├── __init__.py
│   │   │   ├── _common.py
│   │   │   ├── analyses.py # containing OCTIReports, OCTIGroupings, ... classes
│   │   │   ├── ...

```

---

## Advantages
<!-- What are the benefits of this solution? -->
This structure provides several advantages:

- **Consistency**: By mirroring the OCTI UI structure, developers can easily relate  models to frontend components, reducing confusion and improving collaboration.
- **Effort Reduction**: Modeling the items organization has already been done in the OCTI UI, so we can leverage this existing work to reduce development effort.
- **Scalability**: The clear organization allows for easier addition of new features and models in the future.

---

## Disadvantages
<!-- What are the potential downsides or trade-offs? -->

- **Cmplexity with MDE**: While MDE helps avoid confusion, it can also introduce complexity in understanding the relationships between different models and their usage.
- **Keeping in Sync**: As the OCTI UI evolves, the models will need to be updated accordingly, which requires ongoing maintenance. This is reduced by the fact OCTI is now stable and the models are not expected to change frequently.

---

## Alternatives Considered
<!-- What other solutions were considered? Why were they not chosen? -->

- **Flat Structure**: A flat structure was considered, but it would lead to confusion and difficulty in navigating the codebase as the number of models grows.
- **Custom Structure**: Creating a custom structure for the connectors-sdk models was considered, but it would lead to more complexity as the sdk grows. More over this would not align with the MDE principles, which emphasize the importance of a shared understanding of the domain, and would have led to confusion between the connectors-sdk and pycti.

---

## References
<!-- Any relevant links, documentation, or resources that support your TDR. -->
- [Model driven engineering (MDE)](https://en.wikipedia.org/wiki/Model-driven_engineering) (consulted on 2025-06-04)
- [OCTI UI Structure](https://github.com/OpenCTI-Platform/opencti/blob/97156f7431de1e54ed21a0ea10718efe0c2c7b2e/opencti-platform/opencti-front/src/private/components/nav/LeftBar.jsx) (consulted on 2025-06-04)

---
