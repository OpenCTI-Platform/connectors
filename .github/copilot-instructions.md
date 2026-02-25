# OpenCTI Connectors Repository - Copilot Instructions

## Repository Overview

This is the **OpenCTI connectors** monorepo, containing 200+ Python-based connectors that integrate the OpenCTI threat intelligence platform with external tools and data sources. The repository uses a multi-connector architecture with shared utilities and strict validation pipelines.

**Key Statistics:**
- **Language:** Python 3.11-3.12 (Alpine-based Docker images)
- **Connector Types:** 128 external-import, 53 internal-enrichment, 28 stream, 6 internal-export-file, 6 internal-import-file
- **Build System:** CircleCI with dynamic pipeline generation
- **Testing:** pytest with isolated virtual environments per connector

## Critical Build & Validation Requirements

### Code Formatting (ALWAYS REQUIRED)

**Before committing any Python code changes, you MUST run both formatters:**

```bash
# Install formatting tools (if not already installed)
pip install isort==7.0.0 black==25.12.0 --user

# Run isort first
isort --profile black --line-length 88 .

# Then run black
black .
```

**Note:** The CI will fail if code is not properly formatted. These commands MUST be run before pushing code.

### Linting Requirements

**1. Flake8 (Basic Linting)**
```bash
pip install flake8 --user
flake8 --ignore=E,W .
```

**2. Custom Pylint Plugin (STIX ID Validation - CRITICAL)**

This custom checker ensures STIX2 objects use deterministic IDs. **ALWAYS run this before committing connector code:**

```bash
cd shared/pylint_plugins/check_stix_plugin
pip install -r requirements.txt

# Run on your connector directory (example for external-import/mycconnector)
PYTHONPATH=. python -m pylint ../../../external-import/myconnector \
  --disable=all \
  --enable=no_generated_id_stix,no-value-for-parameter,unused-import \
  --load-plugins linter_stix_id_generator
```

**Common Issue:** If you create STIX2 objects, you MUST use deterministic ID generation via pycti or the new connectors-sdk models. Never let stix2 library auto-generate IDs.

### Running Tests

**Test Structure:** Each connector with tests has a `tests/test-requirements.txt` file. Tests run in isolated virtual environments.

```bash
bash run_test.sh ./external-import/myconnector/tests/test-requirements.txt
```

**Notes:**
- Test script checks for changes from `master` branch
- Tests only run if connector or connectors-sdk changed (non-master branches)
- Installs latest pycti from GitHub master branch
- If connector depends on connectors-sdk, installs local version
- Output goes to `test_outputs/` directory

**Test Dependencies Pattern:**
```
pytest
pycti
connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@release/6.9.x#subdirectory=connectors-sdk
```

## Repository Structure

### Top-Level Directories

```
├── .circleci/               # CI/CD configuration
│   ├── config.yml          # Main CircleCI workflow
│   ├── scripts/            # Dynamic pipeline generation (generate_ci.py)
│   └── vars.yml            # Connector-specific build configurations
├── .github/                 # GitHub workflows & templates
├── connectors-sdk/          # Shared SDK for connector development (Python 3.11+)
├── external-import/         # 128 connectors for importing external threat intel
├── internal-enrichment/     # 53 connectors for enriching existing data
├── internal-export-file/    # 6 connectors for exporting data files
├── internal-import-file/    # 6 connectors for importing data files
├── stream/                  # 28 connectors for streaming data
├── shared/                  # Shared utilities
│   ├── pylint_plugins/     # Custom pylint plugins (STIX ID checker)
│   └── tools/              # Manifest/schema generation scripts
├── templates/               # Connector templates for each type
└── tests/                   # Repository-level tests
```

### Standard Connector Structure

Every connector follows this pattern:

```
external-import/myconnector/
├── __metadata__/
│   ├── connector_manifest.json    # Connector metadata (title, description, etc.)
│   ├── connector_config_schema.json  # Config JSON schema (auto-generated)
│   └── logo.png                   # Connector logo
├── src/
│   ├── connector/                 # Main logic
│   │   ├── connector.py          # Core connector class
│   │   ├── converter_to_stix.py  # STIX conversion logic
│   │   └── settings.py           # Config validation
│   ├── main.py                   # Entry point
│   └── requirements.txt          # Python dependencies
├── tests/
│   ├── tests_connector/          # Test modules
│   ├── conftest.py              # pytest configuration
│   └── test-requirements.txt    # Test dependencies
├── .env.sample                   # Environment variable template
├── docker-compose.yml            # Docker deployment config
├── Dockerfile                    # Container build
├── entrypoint.sh                # Container entrypoint
└── README.md                     # Connector documentation
```

## Creating New Connectors

```bash
cd templates
sh create_connector_dir.sh -t <TYPE> -n <NAME>
```

**Types:** `external-import`, `internal-enrichment`, `stream`, `internal-import-file`, `internal-export-file`

**After creating:** Replace `Template`/`template` references, update `__metadata__/connector_manifest.json`, configure `.env.sample`, implement logic in `src/connector/connector.py`.

## Key Configuration Files

### Key Files

- **`.flake8`** - Ignores: E203, E266, E501, W503, F403, F401
- **`.pre-commit-config.yaml`** - Pre-commit hooks (black, flake8, isort, GPG signing)
- **`ci-requirements.txt`** - CI deps: isort==7.0.0, black==25.12.0, pytest==8.4.2
- **`Makefile`** - Manifest/schema generation commands
- **`run_test.sh`** - Test execution (checks changes, runs pytest)

### CircleCI Pipeline

**Workflow Steps:**
1. **ensure_formatting** - isort and black checks (Python 3.12)
2. **base_linter** - flake8 with `--ignore=E,W`
3. **linter** - Custom pylint plugin for STIX ID validation
4. **test** - pytest for changed connectors (parallelism: 4, Python 3.11)
5. **build_manifest** - Generates manifest.json and config schemas
6. **build** - Builds Docker images for changed connectors

Tests and builds only run for connectors with changes (unless on master or connectors-sdk changed).

## Connectors SDK

**Location:** `connectors-sdk/` - Provides STIX2.1 models with deterministic IDs, pre-built classes for IOCs/Authors/Markings/Relationships, exception handling, Pydantic config validation.

**Install:**
```bash
pip install "connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@release/6.9.x#subdirectory=connectors-sdk"
```

**Example:**
```python
from connectors_sdk.models import IPV4Address, OrganizationAuthor, TLPMarking
from connectors_sdk.models.octi import related_to

author = OrganizationAuthor(name="Example Author")
ip = IPV4Address(value="127.0.0.1", author=author, markings=[TLPMarking(level="amber+strict")])
stix_object = ip.to_stix2_object()  # Deterministic ID
```

## Dockerfile Pattern

All connectors use Alpine-based Python images:

```dockerfile
FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY src /opt/opencti-connector-name

RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-name && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

**Note:** Some connectors use Python 3.11 (see `.circleci/vars.yml` for exceptions).

## Common Issues & Workarounds

- **Test script fails "fatal: Not a valid object name origin/master"** - Script expects origin/master ref; fetch master branch first in shallow clones
- **Tests not running** - Only runs for changed code; set `CIRCLE_BRANCH=master` to force all tests
- **Pylint plugin fails** - Use pycti's `generate_id()` or connectors-sdk models for deterministic STIX IDs
- **Import/dependency errors in tests** - Tests install latest pycti from GitHub; pin version if needed

## Manifest & Schema Generation

```bash
make connector_manifest          # Single connector
make connectors_manifests        # All connectors
make connector_config_schema     # Single schema
make connectors_config_schemas   # All schemas
make global_manifest             # Global manifest.json
```

Scripts scan `__metadata__/connector_manifest.json` files and consolidate them.

## Python Version Requirements

- **Connectors SDK:** Python >=3.11, <3.13
- **Most Connectors:** Python 3.12 (Alpine)
- **Some Stream Connectors:** Python 3.11 (see `.circleci/vars.yml`)
- **CI Environment:** Python 3.11 for tests, Python 3.12 for linting

## Important Notes

1. **ALWAYS format code** with black and isort before committing
2. **ALWAYS run custom pylint plugin** when changing connector code that creates STIX objects
3. **NEVER auto-generate STIX IDs** - use deterministic generation via pycti or connectors-sdk
4. **Test isolation** - Each connector's tests run in separate virtual environments
5. **Commit signing** - GPG signed commits required (pre-commit hook enforced)
6. **Docker networking** - Locally, connectors expect `docker_default` network
7. **Environment variables** - Use `.env.sample` as template, never commit secrets

## PR Submission

**Before submitting a PR:**

1. **Run all validation checks** (formatting, linting, custom pylint, tests)
2. **Sign commits with GPG** (required by pre-commit hook)
3. **Update metadata** (`__metadata__/connector_manifest.json`) if adding/modifying connectors
4. **Update documentation** (README.md, add examples)
5. **Test functionality** with different use cases
6. **No secrets** in code or config files

**PR Checklist:**
- [ ] Code formatted: `black .` and `isort --profile black .`
- [ ] Linting passes: `flake8 --ignore=E,W .`
- [ ] Custom pylint passes (for STIX objects)
- [ ] Tests pass: `bash run_test.sh <path>`
- [ ] Docker builds: `docker build -t test .`
- [ ] Commits signed with GPG
- [ ] Metadata and docs updated

**CircleCI pipeline:** formatting checks → linting → custom pylint → tests (parallel) → manifest build → Docker builds (only for changed connectors).

## Trust These Instructions

These instructions are comprehensive and tested. Only search for additional information if:
- Instructions are incomplete for your specific use case
- You encounter an error not documented here
- You need connector-specific implementation details

For connector development patterns, refer to existing connectors as examples. The codebase is consistent, so patterns from one connector generally apply to others of the same type.
