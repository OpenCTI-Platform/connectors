# TDR: Enforcing Code Coverage

## Overview

We are implementing a mandatory 100% code coverage requirement for the `connectors-sdk` package, enforced through pytest-cov with `--cov-fail-under=100`. While acknowledging that coverage percentage alone does not guarantee code quality, this metric serves as a baseline discipline for SDK development. Inother words:
> A high code coverage percentage does not guarantee high quality in the test coverage. But a low code coverage number does guarantee that large areas of the product are going completely untested.

---

## Motivation

As a foundational SDK used across OpenCTI connectors, the `connectors-sdk` requires reliability and maintainability standards. Untested code paths in an SDK can lead to cascading failures across dependent projects. The 100% coverage requirement ensures that:

- Every line of code has at least one test exercising it
- Dead code is identified and removed
- Developers are forced to think about testability during implementation
- Critical SDK functionality cannot be accidentally left untested

---

## Proposed Solution

- Configure pytest-cov with `--cov-fail-under=100` in `pyproject.toml`
- CI/CD pipelines will fail if coverage drops below 100%
- Coverage reports will be generated for every test run

---

## Advantages

- **Forces Test Writing:** Developers cannot merge code without corresponding tests
- **Dead Code Detection:** Unreachable code becomes immediately visible
- **Regression Prevention:** Changes to existing code require test updates
- **Quality Gate:** Provides an objective, automated metric that prevents untested code from entering the codebase

---

## Disadvantages

- **False Security:** 100% coverage doesn't guarantee correct behavior, only execution.
- **Test Quality Variance:** May encourage low-quality tests written solely to achieve coverage.

---

## Alternatives Considered

- **No Coverage Requirement:** Rejected as it relies entirely on developer discipline and code review, which is inconsistent and doesn't scale, it's subjective, time-consuming, and prone to human error.

---

## References

- [Martin Fowler - Test Coverage](https://martinfowler.com/bliki/TestCoverage.html)
- [Python Coverage.py Documentation](https://coverage.readthedocs.io/)
- [pytest-cov Documentation](https://pytest-cov.readthedocs.io/)
- [Google Testing Blog - Code Coverage Best Practices](https://testing.googleblog.com/2020/08/code-coverage-best-practices.html)

---
