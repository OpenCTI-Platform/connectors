# TDR: Enforcing Strict Code Quality Checks on connectors-sdk

## Overview

We are introducing strict code quality, style, and security controls for the `connectors-sdk` package. This will enforce rigorous linter, typing, and vulnerability checks rules as defined in the project's description. All these checks will run at the end of each `pytest` session, making it impossible to skip quality checks during continuous integration or local development.

---

## Motivation

The `connectors-sdk` serves as a foundational library for OpenCTI connectors. Ensuring its reliability directly impacts all connectors that depend on it. By adopting strict code quality and security gates, we aim to:

- Prevent low-quality code, inconsistent style, and common security bugs from being shipped or merged.
- Ensure type safety and early error detection via static typing.
- Detect security vulnerabilities in dependencies early.
- Maintain a high level of trust and stability in the SDK, benefiting downstream users and integrators.

---

## Proposed Solution

- **Centralized Quality Settings:** All linter, typing, and audit rules will be maintained under related sections in `pyproject.toml`. This excludes pylint, for instance.
- **Linting with Ruff:** Enforces a wide set of rules for style and static analysis; certain checks are explicitly ignored to avoid conflicts or non-applicable cases in our codebase.
- **Type Checking with Mypy:**  
  - Set to `strict` mode, increasing type safety for all code.
  - Ensures that all public APIs and internal logic are well-typed.
  - Can be easily replaced by `pyright` if needed.
- **Security Audits with pip-audit:**  
  - Ensures no dependency is vulnerable to known CVEs.
  - This could later be complemented with `bandit` for connectors-sdk code checks.
- **Pytest Session End Enforcement:** At the end of every `pytest` run (locally or in CI), linter, type checks, and CVE audits are executed after any tests run. The test session fails if any check fails.

---

## Advantages

- **Catch Errors Early:** Bugs, style issues, and security flaws are caught before running or merging code.
- **Stable SDK:** API changes and regressions are less likely to slip through because strict typing prevents many classes of changes.
- **Developer Efficiency:** Developers get instant feedback, reducing review/QA times and rework.
- **Uniform Codebase:** All contributors follow the same standards, improving readability and maintainability.
- **Security Posture:** Automated CVE checks prevent known vulnerable dependencies from ever being shipped.

---

## Disadvantages

- **Higher Entry Barrier:** New contributors must configure and adhere to all tools locally.

---

## Alternatives Considered

- No Strict Checks: Relying on best-effort code quality without enforced rules has been rejected, as it would lead to inconsistent code quality, style, and security issues. This approach is not suitable for an SDK library.
- Soft Enforcement: Relying only on CI checks, without local hooks or pre-test gating, has been rejected because local test/test-driven development workflows would be misaligned with CI, leading to frustrating "works locally" but fails in CI situations. Moreover, this would have led to special cases in the CI configuration, which are hard to implement and maintain.
- Strict Checks for the Whole Monorepo: Applying the same strict checks to all packages in the monorepo has been rejected. While this could be beneficial, it would require significant changes to other projects.

---

## References

- [`pyproject.toml` (connectors-sdk)](../pyproject.toml)
- [Pytest docs: Running hooks](https://docs.pytest.org/en/stable/reference/reference.html#std-hook-pytest_sessionstart) (consulted on 2025-06-10)
- [Ruff documentation](https://docs.astral.sh/ruff/) (consulted on 2025-06-10)
- [Mypy documentation](https://mypy.readthedocs.io/en/stable/index.html) (consulted on 2025-06-10)
- [Pip-audit documentation](https://github.com/pypa/pip-audit) (consulted on 2025-06-10)

---
