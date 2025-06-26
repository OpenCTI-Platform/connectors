# TDR: Automated Documentation with Sphinx

## Overview

We are introducing automated, ReadTheDocs-style documentation for the `connectors-sdk` package using Sphinx. This will enable the generation and publication of up-to-date, user-friendly API documentation directly from code and docstrings, following a standard Python documentation workflow.

---

## Motivation

Comprehensive and accessible documentation is essential for SDK usability and adoption, both internally and for the OpenCTI community. Manual documentation is prone to becoming outdated and inconsistent. Automating this process ensures that documentation evolves together with the codebase and remains a reliable resource for all contributors and users.

---

## Proposed Solution

We will configure Sphinx within the `connectors-sdk` project. The build will scan modules and docstrings to automatically generate HTML (or other output) documentation compatible with ReadTheDocs. This documentation can be built locally or published automatically via CI.

---

## Advantages

- Guarantees documentation accuracy by tying it to code and docstrings.
- Offers standard navigation, cross-referencing, and searchability.
- Widely recognized format in the Python ecosystem (ReadTheDocs style).
- Eases onboarding and support for users integrating or contributing connectors.
- Reduces manual maintenance and risk of drift between code and docs.

---

## Disadvantages

- Introduces a dependency on Sphinx and associated setup in the repository.
- Requires developers to write and maintain high-quality docstrings for best results.
- Some initial configuration and ongoing updates are necessary when modules change.

---

## Alternatives Considered

- **Manual Markdown Files** : While we use Markdown files for some high-level documentation, this approach is insufficient for comprehensive API coverage. Manually writing and maintaining an exhaustive description of the package is error-prone and presents a significant maintenance burden.

- **Do not document** : This option was rejected as it would lead to poor usability and support for the SDK, making it difficult for users to understand how to use the package.

---

## References

- [Sphinx Documentation](https://www.sphinx-doc.org/)
- [ReadTheDocs](https://readthedocs.org/)

---
