# Architectural Decision Records (ADRs)

## ADR: Just a Dockerfile Without ENTRYPOINT

**Context:** A single application command is sufficient to run the container.  
**Decision:** Use a plain Dockerfile without an ENTRYPOINT.  
**Rationale:** Simplifies the application root files. No ENTRYPOINT is needed to run a single CMD.

---

## ADR: Dockerfile with Multi-Stage Builds and Cleanup

**Context:** Optimizing Docker image size and build performance.  
**Decision:** Use multi-stage builds with a cleanup step.  
**Rationale:**  

- Results in a lighter final image.  
- Builds faster.  
- Aligns with [Docker best practices](https://docs.docker.com/build/building/multi-stage/) (consulted April 23, 2025).

---

## ADR: Use of Dockerfile 1.7-Labs Syntax

**Context:** Enhanced Docker build syntax features.  
**Decision:** Use Dockerfile 1.7-labs syntax.  
**Rationale:** Enables `COPY --parents`, allowing inclusion of multiple folders (not just their content) in one layer without multiple `COPY` commands.

---

## ADR: Use of pyproject.toml

**Context:** Project metadata and dependency management.  
**Decision:** Adopt `pyproject.toml`.  
**Rationale:**  

- Consolidates all project metadata (PEP 621).  
- Centralizes dependencies and extras (PEP 725).  
- Enables auto-discovery and packaging via setuptools.  
- Supports `pip install .` for clean installation.

---

## ADR: Use of Python Packages

**Context:** Maintainable and testable project structure.  
**Decision:** Organize code into installable packages.  
**Rationale:**  

- Separates API and business logic.  
- Installed packages can drop source code after deployment.  
- Simplifies imports.  
- Prevents modification post-installation.  
- Facilitates testing.  
- See: [Python Packaging Tutorial](https://packaging.python.org/en/latest/tutorials/packaging-projects/) (consulted April 23, 2025).

---

## ADR: Presence of requirements.txt

**Context:** Support for legacy workflows.  
**Decision:** Keep `requirements.txt`.  
**Rationale:**  

- Aligns with older projects structure.  
- Helps developers unfamiliar with `pyproject.toml` or modern tooling.

---

## ADR: Use of Interface in Business Logic

**Context:** Modular application structure.  
**Decision:** Implement clear interfaces between components.  
**Rationale:**  

- Enforces separation of concerns.  
- Structure:  
  - `app.py`: Orchestrates ingestion  
  - `domain/`: Defines business logic  
  - `adapters/`: Handles data retrieval

---

## ADR: Use of Custom Errors in Business Logic

**Context:** Error handling strategy.  
**Decision:** Define and use custom error classes.  
**Rationale:**  

- Enables differentiated error handling:  
  - `DataRetrievalError` → skip with warning  
  - `UseCaseError` → skip with warning  
  - Other exceptions → skip with error log

---

## ADR: Runtime Type and Content Validation with Pydantic

**Context:** Ensuring data quality and consistency.  
**Decision:** Use Pydantic for runtime validation.  
**Rationale:**  

- Provides detailed error logs if needed.  
- Detects divergence from expected data structures.

---

## ADR: Use of Octi DDD Models

**Context:** Domain-driven design and data transformation.  
**Decision:** Integrate Octi-style DDD models.  
**Rationale:**  

- Enhances business logic organization.
- Centralizes STIX format conversion through a unified factory method.  

## ADR: Use of Bucket Limiter for V1 API Client

**Context:** Rate limiting for API requests.
**Decision:** Implement a bucket limiter for the V1 API client, the value is hardcoded to default DragosAPIWorldview V1 rate limit (60 req/min).
**Rationale:**

- Ensures compliance with API rate limits.
- Bucket limiter allows first burst of request if relevant.

## Simplify config variables to strict minimum

**Context:** Configuration management and environment variable handling.
**Decision:** Use a minimal set of mandatory environment variables for configuration.
**Rationale:**

- Reduces complexity and potential for misconfiguration.
- Ensures that only essential variables are required for the application to run.
